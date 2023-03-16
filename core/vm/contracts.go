// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/naoina/toml"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ripemd160"
)

type PrecompileAccessibleState interface {
	Interpreter() *EVMInterpreter
}

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64 // RequiredGas calculates the contract gas use
	Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error)
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},

	// Zama-specific contracts
	common.BytesToAddress([]byte{65}): &fheAdd{},
	common.BytesToAddress([]byte{66}): &verifyCiphertext{},
	common.BytesToAddress([]byte{67}): &reencrypt{},
	common.BytesToAddress([]byte{68}): &delegateCiphertext{},
	common.BytesToAddress([]byte{69}): &require{},
	common.BytesToAddress([]byte{70}): &fheLte{},
	common.BytesToAddress([]byte{71}): &fheSub{},
	common.BytesToAddress([]byte{72}): &fheMul{},
	common.BytesToAddress([]byte{73}): &fheLt{},
	common.BytesToAddress([]byte{74}): &fheRand{},
	common.BytesToAddress([]byte{75}): &optimisticRequire{},
	common.BytesToAddress([]byte{99}): &faucet{},
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}): &bn256AddByzantium{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulByzantium{},
	common.BytesToAddress([]byte{8}): &bn256PairingByzantium{},

	// Zama-specific contracts
	common.BytesToAddress([]byte{65}): &fheAdd{},
	common.BytesToAddress([]byte{66}): &verifyCiphertext{},
	common.BytesToAddress([]byte{67}): &reencrypt{},
	common.BytesToAddress([]byte{68}): &delegateCiphertext{},
	common.BytesToAddress([]byte{69}): &require{},
	common.BytesToAddress([]byte{70}): &fheLte{},
	common.BytesToAddress([]byte{71}): &fheSub{},
	common.BytesToAddress([]byte{72}): &fheMul{},
	common.BytesToAddress([]byte{73}): &fheLt{},
	common.BytesToAddress([]byte{74}): &fheRand{},
	common.BytesToAddress([]byte{75}): &optimisticRequire{},
	common.BytesToAddress([]byte{99}): &faucet{},
}

// PrecompiledContractsIstanbul contains the default set of pre-compiled Ethereum
// contracts used in the Istanbul release.
var PrecompiledContractsIstanbul = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},

	// Zama-specific contracts
	common.BytesToAddress([]byte{65}): &fheAdd{},
	common.BytesToAddress([]byte{66}): &verifyCiphertext{},
	common.BytesToAddress([]byte{67}): &reencrypt{},
	common.BytesToAddress([]byte{68}): &delegateCiphertext{},
	common.BytesToAddress([]byte{69}): &require{},
	common.BytesToAddress([]byte{70}): &fheLte{},
	common.BytesToAddress([]byte{71}): &fheSub{},
	common.BytesToAddress([]byte{72}): &fheMul{},
	common.BytesToAddress([]byte{73}): &fheLt{},
	common.BytesToAddress([]byte{74}): &fheRand{},
	common.BytesToAddress([]byte{75}): &optimisticRequire{},
	common.BytesToAddress([]byte{99}): &faucet{},
}

// PrecompiledContractsBerlin contains the default set of pre-compiled Ethereum
// contracts used in the Berlin release.
var PrecompiledContractsBerlin = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},

	// Zama-specific contracts
	common.BytesToAddress([]byte{65}): &fheAdd{},
	common.BytesToAddress([]byte{66}): &verifyCiphertext{},
	common.BytesToAddress([]byte{67}): &reencrypt{},
	common.BytesToAddress([]byte{68}): &delegateCiphertext{},
	common.BytesToAddress([]byte{69}): &require{},
	common.BytesToAddress([]byte{70}): &fheLte{},
	common.BytesToAddress([]byte{71}): &fheSub{},
	common.BytesToAddress([]byte{72}): &fheMul{},
	common.BytesToAddress([]byte{73}): &fheLt{},
	common.BytesToAddress([]byte{74}): &fheRand{},
	common.BytesToAddress([]byte{75}): &optimisticRequire{},
	common.BytesToAddress([]byte{99}): &faucet{},
}

// PrecompiledContractsBLS contains the set of pre-compiled Ethereum
// contracts specified in EIP-2537. These are exported for testing purposes.
var PrecompiledContractsBLS = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{10}): &bls12381G1Add{},
	common.BytesToAddress([]byte{11}): &bls12381G1Mul{},
	common.BytesToAddress([]byte{12}): &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{13}): &bls12381G2Add{},
	common.BytesToAddress([]byte{14}): &bls12381G2Mul{},
	common.BytesToAddress([]byte{15}): &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{16}): &bls12381Pairing{},
	common.BytesToAddress([]byte{17}): &bls12381MapG1{},
	common.BytesToAddress([]byte{18}): &bls12381MapG2{},

	// Zama-specific contracts
	common.BytesToAddress([]byte{65}): &fheAdd{},
	common.BytesToAddress([]byte{66}): &verifyCiphertext{},
	common.BytesToAddress([]byte{67}): &reencrypt{},
	common.BytesToAddress([]byte{68}): &delegateCiphertext{},
	common.BytesToAddress([]byte{69}): &require{},
	common.BytesToAddress([]byte{70}): &fheLte{},
	common.BytesToAddress([]byte{71}): &fheSub{},
	common.BytesToAddress([]byte{72}): &fheMul{},
	common.BytesToAddress([]byte{73}): &fheLt{},
	common.BytesToAddress([]byte{74}): &fheRand{},
	common.BytesToAddress([]byte{75}): &optimisticRequire{},
	common.BytesToAddress([]byte{99}): &faucet{},
}

var (
	PrecompiledAddressesBerlin    []common.Address
	PrecompiledAddressesIstanbul  []common.Address
	PrecompiledAddressesByzantium []common.Address
	PrecompiledAddressesHomestead []common.Address
)

func init() {
	for k := range PrecompiledContractsHomestead {
		PrecompiledAddressesHomestead = append(PrecompiledAddressesHomestead, k)
	}
	for k := range PrecompiledContractsByzantium {
		PrecompiledAddressesByzantium = append(PrecompiledAddressesByzantium, k)
	}
	for k := range PrecompiledContractsIstanbul {
		PrecompiledAddressesIstanbul = append(PrecompiledAddressesIstanbul, k)
	}
	for k := range PrecompiledContractsBerlin {
		PrecompiledAddressesBerlin = append(PrecompiledAddressesBerlin, k)
	}
}

// ActivePrecompiles returns the precompiles enabled with the current configuration.
func ActivePrecompiles(rules params.Rules) []common.Address {
	switch {
	case rules.IsBerlin:
		return PrecompiledAddressesBerlin
	case rules.IsIstanbul:
		return PrecompiledAddressesIstanbul
	case rules.IsByzantium:
		return PrecompiledAddressesByzantium
	default:
		return PrecompiledAddressesHomestead
	}
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
// It returns
// - the returned bytes,
// - the _remaining_ gas,
// - any error that occurred
func RunPrecompiledContract(p PrecompiledContract, accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	accessibleState.Interpreter().evm.depth++
	defer func() { accessibleState.Interpreter().evm.depth-- }()
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	suppliedGas -= gasCost
	output, err := p.Run(accessibleState, caller, addr, input, readOnly)
	return output, suppliedGas, err
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// We must make sure not to modify the 'input', so placing the 'v' along with
	// the signature needs to be done on a new allocation
	sig := make([]byte, 65)
	copy(sig, input[64:128])
	sig[64] = v
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], sig)
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
func (c *sha256hash) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
}
func (c *ripemd160hash) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
}
func (c *dataCopy) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return input, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct {
	eip2565 bool
}

var (
	big0      = big.NewInt(0)
	big1      = big.NewInt(1)
	big3      = big.NewInt(3)
	big4      = big.NewInt(4)
	big7      = big.NewInt(7)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big20     = big.NewInt(20)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// modexpMultComplexity implements bigModexp multComplexity formula, as defined in EIP-198
//
// def mult_complexity(x):
//
//	if x <= 64: return x ** 2
//	elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//	else: return x ** 2 // 16 + 480 * x - 199680
//
// where is x is max(length_of_MODULUS, length_of_BASE)
func modexpMultComplexity(x *big.Int) *big.Int {
	switch {
	case x.Cmp(big64) <= 0:
		x.Mul(x, x) // x ** 2
	case x.Cmp(big1024) <= 0:
		// (x ** 2 // 4 ) + ( 96 * x - 3072)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, x), big3072),
		)
	default:
		// (x ** 2 // 16) + (480 * x - 199680)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, x), big199680),
		)
	}
	return x
}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))
	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	if c.eip2565 {
		// EIP-2565 has three changes
		// 1. Different multComplexity (inlined here)
		// in EIP-2565 (https://eips.ethereum.org/EIPS/eip-2565):
		//
		// def mult_complexity(x):
		//    ceiling(x/8)^2
		//
		//where is x is max(length_of_MODULUS, length_of_BASE)
		gas = gas.Add(gas, big7)
		gas = gas.Div(gas, big8)
		gas.Mul(gas, gas)

		gas.Mul(gas, math.BigMax(adjExpLen, big1))
		// 2. Different divisor (`GQUADDIVISOR`) (3)
		gas.Div(gas, big3)
		if gas.BitLen() > 64 {
			return math.MaxUint64
		}
		// 3. Minimum price of 200 gas
		if gas.Uint64() < 200 {
			return 200
		}
		return gas.Uint64()
	}
	gas = modexpMultComplexity(gas)
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, big20)

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

func (c *bigModExp) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// runBn256Add implements the Bn256Add precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Add(input []byte) ([]byte, error) {
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256Add implements a native elliptic curve point addition conforming to
// Istanbul consensus rules.
type bn256AddIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasIstanbul
}

func (c *bn256AddIstanbul) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return runBn256Add(input)
}

// bn256AddByzantium implements a native elliptic curve point addition
// conforming to Byzantium consensus rules.
type bn256AddByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasByzantium
}

func (c *bn256AddByzantium) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return runBn256Add(input)
}

// runBn256ScalarMul implements the Bn256ScalarMul precompile, referenced by
// both Byzantium and Istanbul operations.
func runBn256ScalarMul(input []byte) ([]byte, error) {
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

// bn256ScalarMulIstanbul implements a native elliptic curve scalar
// multiplication conforming to Istanbul consensus rules.
type bn256ScalarMulIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasIstanbul
}

func (c *bn256ScalarMulIstanbul) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return runBn256ScalarMul(input)
}

// bn256ScalarMulByzantium implements a native elliptic curve scalar
// multiplication conforming to Byzantium consensus rules.
type bn256ScalarMulByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasByzantium
}

func (c *bn256ScalarMulByzantium) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return runBn256ScalarMul(input)
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// runBn256Pairing implements the Bn256Pairing precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Pairing(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

// bn256PairingIstanbul implements a pairing pre-compile for the bn256 curve
// conforming to Istanbul consensus rules.
type bn256PairingIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasIstanbul + uint64(len(input)/192)*params.Bn256PairingPerPointGasIstanbul
}

func (c *bn256PairingIstanbul) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return runBn256Pairing(input)
}

// bn256PairingByzantium implements a pairing pre-compile for the bn256 curve
// conforming to Byzantium consensus rules.
type bn256PairingByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasByzantium + uint64(len(input)/192)*params.Bn256PairingPerPointGasByzantium
}

func (c *bn256PairingByzantium) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	return runBn256Pairing(input)
}

type blake2F struct{}

func (c *blake2F) RequiredGas(input []byte) uint64 {
	// If the input is malformed, we can't calculate the gas, return 0 and let the
	// actual call choke and fault.
	if len(input) != blake2FInputLength {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(input[0:4]))
}

const (
	blake2FInputLength        = 213
	blake2FFinalBlockBytes    = byte(1)
	blake2FNonFinalBlockBytes = byte(0)
)

var (
	errBlake2FInvalidInputLength = errors.New("invalid input length")
	errBlake2FInvalidFinalFlag   = errors.New("invalid final flag")
)

func (c *blake2F) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Make sure the input is valid (correct length and final flag)
	if len(input) != blake2FInputLength {
		return nil, errBlake2FInvalidInputLength
	}
	if input[212] != blake2FNonFinalBlockBytes && input[212] != blake2FFinalBlockBytes {
		return nil, errBlake2FInvalidFinalFlag
	}
	// Parse the input into the Blake2b call parameters
	var (
		rounds = binary.BigEndian.Uint32(input[0:4])
		final  = input[212] == blake2FFinalBlockBytes

		h [8]uint64
		m [16]uint64
		t [2]uint64
	)
	for i := 0; i < 8; i++ {
		offset := 4 + i*8
		h[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	for i := 0; i < 16; i++ {
		offset := 68 + i*8
		m[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	t[0] = binary.LittleEndian.Uint64(input[196:204])
	t[1] = binary.LittleEndian.Uint64(input[204:212])

	// Execute the compression function, extract and return the result
	blake2b.F(&h, m, t, final, rounds)

	output := make([]byte, 64)
	for i := 0; i < 8; i++ {
		offset := i * 8
		binary.LittleEndian.PutUint64(output[offset:offset+8], h[i])
	}
	return output, nil
}

var (
	errBLS12381InvalidInputLength          = errors.New("invalid input length")
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
	errBLS12381G1PointSubgroup             = errors.New("g1 point is not on correct subgroup")
	errBLS12381G2PointSubgroup             = errors.New("g2 point is not on correct subgroup")
)

// bls12381G1Add implements EIP-2537 G1Add precompile.
type bls12381G1Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1AddGas
}

func (c *bls12381G1Add) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 G1Add precompile.
	// > G1 addition call expects `256` bytes as an input that is interpreted as byte concatenation of two G1 points (`128` bytes each).
	// > Output is an encoding of addition operation result - single G1 point (`128` bytes).
	if len(input) != 256 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point p_0
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode G1 point p_1
	if p1, err = g.DecodePoint(input[128:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	r := g.New()
	g.Add(r, p0, p1)

	// Encode the G1 point result into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1Mul implements EIP-2537 G1Mul precompile.
type bls12381G1Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1MulGas
}

func (c *bls12381G1Mul) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 G1Mul precompile.
	// > G1 multiplication call expects `160` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G1 point (`128` bytes).
	if len(input) != 160 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[128:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G1 point into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1MultiExp implements EIP-2537 G1MultiExp precompile.
type bls12381G1MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G1 point, scalar value pair length
	k := len(input) / 160
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G1 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G1MulGas * discount) / 1000
}

func (c *bls12381G1MultiExp) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 G1MultiExp precompile.
	// G1 multiplication call expects `160*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// Output is an encoding of multiexponentiation operation result - single G1 point (`128` bytes).
	k := len(input) / 160
	if len(input) == 0 || len(input)%160 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG1, k)
	scalars := make([]*big.Int, k)

	// Initialize G1
	g := bls12381.NewG1()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 160 * i
		t0, t1, t2 := off, off+128, off+160
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Add implements EIP-2537 G2Add precompile.
type bls12381G2Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2AddGas
}

func (c *bls12381G2Add) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 G2Add precompile.
	// > G2 addition call expects `512` bytes as an input that is interpreted as byte concatenation of two G2 points (`256` bytes each).
	// > Output is an encoding of addition operation result - single G2 point (`256` bytes).
	if len(input) != 512 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()
	r := g.New()

	// Decode G2 point p_0
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode G2 point p_1
	if p1, err = g.DecodePoint(input[256:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	g.Add(r, p0, p1)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Mul implements EIP-2537 G2Mul precompile.
type bls12381G2Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2MulGas
}

func (c *bls12381G2Mul) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 G2MUL precompile logic.
	// > G2 multiplication call expects `288` bytes as an input that is interpreted as byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G2 point (`256` bytes).
	if len(input) != 288 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()

	// Decode G2 point
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[256:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2MultiExp implements EIP-2537 G2MultiExp precompile.
type bls12381G2MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G2 point, scalar value pair length
	k := len(input) / 288
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G2 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G2MulGas * discount) / 1000
}

func (c *bls12381G2MultiExp) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 G2MultiExp precompile logic
	// > G2 multiplication call expects `288*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiexponentiation operation result - single G2 point (`256` bytes).
	k := len(input) / 288
	if len(input) == 0 || len(input)%288 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG2, k)
	scalars := make([]*big.Int, k)

	// Initialize G2
	g := bls12381.NewG2()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 288 * i
		t0, t1, t2 := off, off+256, off+288
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G2 point to 256 bytes.
	return g.EncodePoint(r), nil
}

// bls12381Pairing implements EIP-2537 Pairing precompile.
type bls12381Pairing struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381Pairing) RequiredGas(input []byte) uint64 {
	return params.Bls12381PairingBaseGas + uint64(len(input)/384)*params.Bls12381PairingPerPairGas
}

func (c *bls12381Pairing) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 Pairing precompile logic.
	// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	// > - `128` bytes of G1 point encoding
	// > - `256` bytes of G2 point encoding
	// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, errBLS12381InvalidInputLength
	}

	// Initialize BLS12-381 pairing engine
	e := bls12381.NewPairingEngine()
	g1, g2 := e.G1, e.G2

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1, err := g1.DecodePoint(input[t0:t1])
		if err != nil {
			return nil, err
		}
		// Decode G2 point
		p2, err := g2.DecodePoint(input[t1:t2])
		if err != nil {
			return nil, err
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !g1.InCorrectSubgroup(p1) {
			return nil, errBLS12381G1PointSubgroup
		}
		if !g2.InCorrectSubgroup(p2) {
			return nil, errBLS12381G2PointSubgroup
		}

		// Update pairing engine with G1 and G2 ponits
		e.AddPair(p1, p2)
	}
	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	if e.Check() {
		out[31] = 1
	}
	return out, nil
}

// decodeBLS12381FieldElement decodes BLS12-381 elliptic curve field element.
// Removes top 16 bytes of 64 byte input.
func decodeBLS12381FieldElement(in []byte) ([]byte, error) {
	if len(in) != 64 {
		return nil, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return nil, errBLS12381InvalidFieldElementTopBytes
		}
	}
	out := make([]byte, 48)
	copy(out[:], in[16:])
	return out, nil
}

// bls12381MapG1 implements EIP-2537 MapG1 precompile.
type bls12381MapG1 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG1) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG1Gas
}

func (c *bls12381MapG1) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 Map_To_G1 precompile.
	// > Field-to-curve call expects `64` bytes an an input that is interpreted as a an element of the base field.
	// > Output of this call is `128` bytes and is G1 point following respective encoding rules.
	if len(input) != 64 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe, err := decodeBLS12381FieldElement(input)
	if err != nil {
		return nil, err
	}

	// Initialize G1
	g := bls12381.NewG1()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381MapG2 implements EIP-2537 MapG2 precompile.
type bls12381MapG2 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG2) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG2Gas
}

func (c *bls12381MapG2) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// Implements EIP-2537 Map_FP2_TO_G2 precompile logic.
	// > Field-to-curve call expects `128` bytes an an input that is interpreted as a an element of the quadratic extension field.
	// > Output of this call is `256` bytes and is G2 point following respective encoding rules.
	if len(input) != 128 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe := make([]byte, 96)
	c0, err := decodeBLS12381FieldElement(input[:64])
	if err != nil {
		return nil, err
	}
	copy(fe[48:], c0)
	c1, err := decodeBLS12381FieldElement(input[64:])
	if err != nil {
		return nil, err
	}
	copy(fe[:48], c1)

	// Initialize G2
	g := bls12381.NewG2()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G2 point to 256 bytes
	return g.EncodePoint(r), nil
}

type tomlConfigOptions struct {
	Oracle struct {
		Mode              string
		OracleDBAddress   string
		RequireRetryCount uint8
	}

	Zk struct {
		Verify           bool
		VerifyRPCAddress string
		VerifyRetryCount uint8
	}

	Tfhe struct {
		CiphertextsToGarbageCollect           uint64
		CiphertextsGarbageCollectIntervalSecs uint64
	}
}

var tomlConfig tomlConfigOptions

//lint:ignore U1000 Want to keep to show how Ed25519 keys were generated.
func generateEd25519Keys() error {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	home := homeDir()
	if err := os.WriteFile(home+"/.evmosd/zama/keys/signature-keys/public.ed25519", public, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(home+"/.evmosd/zama/keys/signature-keys/private.ed25519", private, 0600); err != nil {
		return err
	}
	return nil
}

var requireHttpClient http.Client = http.Client{}
var zkHttpClient http.Client = http.Client{}

var publicSignatureKey []byte
var privateSignatureKey []byte

func requireBytesToSign(ciphertext []byte, value bool) []byte {
	// TODO: avoid copy
	b := make([]byte, 0, len(ciphertext)+1)
	b = append(b, ciphertext...)
	if value {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b
}

func signRequire(ciphertext []byte, value bool) string {
	b := requireBytesToSign(ciphertext, value)
	signature := ed25519.Sign(privateSignatureKey, b)
	return hex.EncodeToString(signature)
}

func init() {
	home := homeDir()

	f, err := os.Open(home + "/.evmosd/zama/config/zama_config.toml")
	if err != nil {
		return
	}
	defer f.Close()
	if err := toml.NewDecoder(f).Decode(&tomlConfig); err != nil {
		return
	}

	switch mode := strings.ToLower(tomlConfig.Oracle.Mode); mode {
	case "oracle":
		priv, err := os.ReadFile(home + "/.evmosd/zama/keys/signature-keys/private.ed25519")
		if err != nil {
			return
		}
		privateSignatureKey = priv
	case "node":
		pub, err := os.ReadFile(home + "/.evmosd/zama/keys/signature-keys/public.ed25519")
		if err != nil {
			return
		}
		publicSignatureKey = pub
	default:
		panic(fmt.Sprintf("invalid oracle mode: %s", mode))
	}
}

func isVerifiedAtCurrentDepth(interpreter *EVMInterpreter, ct *verifiedCiphertext) bool {
	return ct.verifiedDepths.has(interpreter.evm.depth)
}

// Returns a pointer to the ciphertext if the given hash points to a verified ciphertext.
// Else, it returns nil.
func getVerifiedCiphertextFromEVM(interpreter *EVMInterpreter, ciphertextHash common.Hash) *verifiedCiphertext {
	ct, ok := interpreter.verifiedCiphertexts[ciphertextHash]
	if ok && isVerifiedAtCurrentDepth(interpreter, ct) {
		return ct
	}
	return nil
}

// See getVerifiedCiphertextFromEVM().
func getVerifiedCiphertext(accessibleState PrecompileAccessibleState, ciphertextHash common.Hash) *verifiedCiphertext {
	return getVerifiedCiphertextFromEVM(accessibleState.Interpreter(), ciphertextHash)
}

func importCiphertextToEVMAtDepth(interpreter *EVMInterpreter, ct *tfheCiphertext, depth int) *verifiedCiphertext {
	existing, ok := interpreter.verifiedCiphertexts[ct.getHash()]
	if ok {
		existing.verifiedDepths.add(depth)
		return existing
	} else {
		verifiedDepths := newDepthSet()
		verifiedDepths.add(depth)
		new := &verifiedCiphertext{
			verifiedDepths,
			ct,
		}
		interpreter.verifiedCiphertexts[ct.getHash()] = new
		return new
	}
}

func importCiphertextToEVM(interpreter *EVMInterpreter, ct *tfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVMAtDepth(interpreter, ct, interpreter.evm.depth)
}

func importCiphertext(accessibleState PrecompileAccessibleState, ct *tfheCiphertext) *verifiedCiphertext {
	return importCiphertextToEVM(accessibleState.Interpreter(), ct)
}

// Used when we want to skip FHE computation, e.g. gas estimation.
func importRandomCiphertext(accessibleState PrecompileAccessibleState) []byte {
	ct := new(tfheCiphertext)
	ct.makeRandom()
	importCiphertext(accessibleState, ct)
	ctHash := ct.getHash()
	return ctHash[:]
}

type fheAdd struct{}

func (e *fheAdd) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheAdd) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if len(input) != 64 {
		return nil, errors.New("input needs to contain two 256-bit sized values")
	}

	lhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}
	rhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}

	result := lhs.ciphertext.add(rhs.ciphertext)
	importCiphertext(accessibleState, result)

	// TODO: for testing
	err := os.WriteFile("/tmp/add_result", result.serialize(), 0644)
	if err != nil {
		return nil, err
	}

	ctHash := result.getHash()
	return ctHash[:], nil
}

func fheEncryptToUserKey(value uint64, userAddress common.Address) ([]byte, error) {
	userPublicKey := strings.ToLower(usersKeysDir + userAddress.Hex())
	pks, err := os.ReadFile(userPublicKey)
	if err != nil {
		return nil, err
	}
	ct := publicKeyEncrypt(pks, value)

	// TODO: for testing
	err = os.WriteFile("/tmp/public_encrypt_result", ct, 0644)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func exitProcess() {
	os.Exit(1)
}

type verifyCiphertext struct{}

func (e *verifyCiphertext) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

// Returns the verified ciphertext on success or nil on invalid ZK proof.
// Exits the process on errors.
func verifyZkProof(input []byte) []byte {
	for try := uint8(1); try <= tomlConfig.Zk.VerifyRetryCount+1; try++ {
		req, err := http.NewRequest(http.MethodPost, tomlConfig.Zk.VerifyRPCAddress, bytes.NewReader(input))
		if err != nil {
			continue
		}
		req.Header.Add("Content-Type", "application/msgpack")
		resp, err := zkHttpClient.Do(req)
		if err != nil {
			continue
		}
		// The ZKPoK service returns 406 if the proof is incorrect.
		if resp.StatusCode == 406 {
			return nil
		} else if resp.StatusCode != 200 {
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		return body
	}
	exitProcess()
	return nil
}

func (e *verifyCiphertext) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}
	var ctBytes []byte
	if !tomlConfig.Zk.Verify {
		// For testing: if input size <= `fheCiphertextSize`, treat the whole input as ciphertext.
		ctBytes = input[0:minInt(fheCiphertextSize, len(input))]
	} else {
		ctBytes = verifyZkProof(input)
		if ctBytes == nil {
			return nil, fmt.Errorf("invalid ZK Proof")
		}
	}
	ct := new(tfheCiphertext)
	err := ct.deserialize(ctBytes)
	if err != nil {
		return nil, err
	}
	ctHash := ct.getHash()
	importCiphertext(accessibleState, ct)
	return ctHash.Bytes(), nil
}

// Return a memory with a layout that matches the `bytes` EVM type, namely:
//   - 32 byte integer in big-endian order as length
//   - the actual bytes in the `bytes` value
func toEVMBytes(input []byte) []byte {
	len := uint64(len(input))
	lenBytes32 := uint256.NewInt(len).Bytes32()
	ret := make([]byte, 0, len+32)
	ret = append(ret, lenBytes32[:]...)
	ret = append(ret, input...)
	return ret
}

type reencrypt struct{}

func (e *reencrypt) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *reencrypt) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if !accessibleState.Interpreter().evm.EthCall {
		return nil, errors.New("reencrypt not supported in write commands")
	}
	if len(input) != 32 {
		return nil, errors.New("invalid ciphertext handle")
	}
	ct := getVerifiedCiphertext(accessibleState, common.BytesToHash(input))
	if ct != nil {
		decryptedValue := ct.ciphertext.decrypt()
		reencryptedValue, err := fheEncryptToUserKey(decryptedValue, accessibleState.Interpreter().evm.Origin)
		if err != nil {
			return nil, err
		}
		return toEVMBytes(reencryptedValue), nil
	}
	return nil, errors.New("unverified ciphertext handle")
}

type delegateCiphertext struct{}

func (e *delegateCiphertext) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *delegateCiphertext) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if len(input) != 32 {
		return nil, errors.New("invalid ciphertext handle")
	}
	ct := getVerifiedCiphertext(accessibleState, common.BytesToHash(input))
	if ct != nil {
		ct.verifiedDepths.add(accessibleState.Interpreter().evm.depth + 1)
		return nil, nil
	}
	return nil, errors.New("unverified ciphertext handle")
}

type require struct{}

func (e *require) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

type requireMessage struct {
	Value     bool   `json:"value"`
	Signature string `json:"signature"`
}

func requireKey(ciphertext []byte) string {
	// Take the Keccak256 and remove the leading 0x.
	return crypto.Keccak256Hash(ciphertext).Hex()[2:]
}

func requireURL(key *string) string {
	return tomlConfig.Oracle.OracleDBAddress + "/require/" + *key
}

// Puts the given ciphertext as a require to the oracle DB or exits the process on errors.
// Returns the require value.
func putRequire(ct *tfheCiphertext) bool {
	ciphertext := ct.serialize()
	value := (ct.decrypt() != 0)
	key := requireKey(ciphertext)
	j, err := json.Marshal(requireMessage{value, signRequire(ciphertext, value)})
	if err != nil {
		exitProcess()
	}
	for try := uint8(1); try <= tomlConfig.Oracle.RequireRetryCount+1; try++ {
		req, err := http.NewRequest(http.MethodPut, requireURL(&key), bytes.NewReader(j))
		if err != nil {
			continue
		}
		resp, err := requireHttpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		return value
	}
	exitProcess()
	return value
}

// Gets the given require from the oracle DB and returns its value.
// Exits the process on errors or signature verification failure.
func getRequire(ct *tfheCiphertext) bool {
	ciphertext := ct.serialize()
	key := requireKey(ciphertext)
	for try := uint8(1); try <= tomlConfig.Oracle.RequireRetryCount+1; try++ {
		req, err := http.NewRequest(http.MethodGet, requireURL(&key), http.NoBody)
		if err != nil {
			continue
		}
		resp, err := requireHttpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		msg := requireMessage{}
		if err := json.Unmarshal(body, &msg); err != nil {
			continue
		}
		b := requireBytesToSign(ciphertext, msg.Value)
		s, err := hex.DecodeString(msg.Signature)
		if err != nil {
			continue
		}
		if !ed25519.Verify(publicSignatureKey, b, s) {
			continue
		}
		return msg.Value
	}
	exitProcess()
	return false
}

func evaluateRequire(ct *tfheCiphertext) bool {
	switch mode := strings.ToLower(tomlConfig.Oracle.Mode); mode {
	case "oracle":
		return putRequire(ct)
	case "node":
		return getRequire(ct)
	}
	exitProcess()
	return false
}

func (e *require) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if accessibleState.Interpreter().evm.EthCall {
		return nil, errors.New("require not supported in read-only commands")
	}
	if len(input) != 32 {
		return nil, errors.New("invalid ciphertext handle")
	}
	// If we are not committing to state, assume the require is true, avoiding any side effects
	// (i.e. mutatiting the oracle DB).
	if !accessibleState.Interpreter().evm.Commit {
		return nil, nil
	}
	ct, ok := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input)]
	if !ok {
		return nil, errors.New("unverified ciphertext handle")
	}
	if !evaluateRequire(ct.ciphertext) {
		return nil, ErrExecutionReverted
	}
	return nil, nil
}

type optimisticRequire struct{}

func (e *optimisticRequire) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *optimisticRequire) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if accessibleState.Interpreter().evm.EthCall {
		return nil, errors.New("optimistic require not supported in read-only commands")
	}
	if len(input) != 32 {
		return nil, errors.New("invalid ciphertext handle")
	}
	// If we are not committing to state, assume the require is true, avoiding any side effects
	// (i.e. mutatiting the oracle DB).
	if !accessibleState.Interpreter().evm.Commit {
		return nil, nil
	}
	ct, ok := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input)]
	if !ok {
		return nil, errors.New("unverified ciphertext handle")
	}
	// If this is the first optimistic require, just assign it.
	// If there is already an optimistic one, just multiply it with the incoming one. Here, we assume
	// that ciphertexts have value of either 0 or 1. Thus, multiplying all optimistic requires leads to
	// one optimistic require at the end that we decrypt when we are about to finish execution.
	if accessibleState.Interpreter().optimisticRequire == nil {
		accessibleState.Interpreter().optimisticRequire = ct.ciphertext
	} else {
		accessibleState.Interpreter().optimisticRequire = accessibleState.Interpreter().optimisticRequire.mul(ct.ciphertext)
	}
	return nil, nil
}

type fheLte struct{}

func (e *fheLte) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheLte) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if len(input) != 64 {
		return nil, errors.New("input needs to contain two 256-bit sized values")
	}

	lhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}
	rhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}

	result := lhs.ciphertext.lte(rhs.ciphertext)
	importCiphertext(accessibleState, result)

	// TODO: for testing
	err := os.WriteFile("/tmp/lte_result", result.serialize(), 0644)
	if err != nil {
		return nil, err
	}

	ctHash := result.getHash()

	return ctHash[:], nil
}

type fheSub struct{}

func (e *fheSub) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheSub) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if len(input) != 64 {
		return nil, errors.New("input needs to contain two 256-bit sized values")
	}

	lhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}
	rhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}

	result := lhs.ciphertext.sub(rhs.ciphertext)
	importCiphertext(accessibleState, result)

	// TODO: for testing
	err := os.WriteFile("/tmp/sub_result", result.serialize(), 0644)
	if err != nil {
		return nil, err
	}

	ctHash := result.getHash()

	return ctHash[:], nil
}

type fheMul struct{}

func (e *fheMul) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheMul) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if len(input) != 64 {
		return nil, errors.New("input needs to contain two 256-bit sized values")
	}

	lhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}
	rhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}

	result := lhs.ciphertext.mul(rhs.ciphertext)
	importCiphertext(accessibleState, result)

	// TODO: for testing
	err := os.WriteFile("/tmp/mul_result", result.serialize(), 0644)
	if err != nil {
		return nil, err
	}

	ctHash := result.getHash()

	return ctHash[:], nil
}

type fheLt struct{}

func (e *fheLt) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheLt) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	if len(input) != 64 {
		return nil, errors.New("input needs to contain two 256-bit sized values")
	}

	lhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}
	rhs := getVerifiedCiphertext(accessibleState, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, errors.New("unverified ciphertext handle")
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}

	result := lhs.ciphertext.lt(rhs.ciphertext)
	importCiphertext(accessibleState, result)

	// TODO: for testing
	err := os.WriteFile("/tmp/lt_result", result.serialize(), 0644)
	if err != nil {
		return nil, err
	}

	ctHash := result.getHash()

	return ctHash[:], nil
}

type fheRand struct{}

var globalRngSeed []byte

var rngNonceKey [32]byte = uint256.NewInt(0).Bytes32()

func init() {
	if chacha20.NonceSizeX != 24 {
		panic("expected 24 bytes for NonceSizeX")
	}

	// TODO: Since the current implementation is not FHE-based and, hence, not private,
	// we just initialize the global seed with non-random public data. We will change
	// that once the FHE version is available.
	globalRngSeed = make([]byte, chacha20.KeySize)
	for i := range globalRngSeed {
		globalRngSeed[i] = byte(1 + i)
	}
}

func (e *fheRand) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheRand) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !accessibleState.Interpreter().evm.Commit && !accessibleState.Interpreter().evm.EthCall {
		return importRandomCiphertext(accessibleState), nil
	}

	// Get the RNG nonce.
	protectedStorage := crypto.CreateProtectedStorageContractAddress(caller)
	currentRngNonceBytes := accessibleState.Interpreter().evm.StateDB.GetState(protectedStorage, rngNonceKey).Bytes()

	// Increment the RNG nonce by 1.
	nextRngNonce := newInt(currentRngNonceBytes)
	nextRngNonce = nextRngNonce.AddUint64(nextRngNonce, 1)
	accessibleState.Interpreter().evm.StateDB.SetState(protectedStorage, rngNonceKey, nextRngNonce.Bytes32())

	// Compute the seed and use it to create a new cipher.
	hasher := crypto.NewKeccakState()
	hasher.Write(globalRngSeed)
	hasher.Write(caller.Bytes())
	hasher.Write(currentRngNonceBytes)
	seed := common.Hash{}
	_, err := hasher.Read(seed[:])
	if err != nil {
		return nil, err
	}
	// The RNG nonce bytes are of size chacha20.NonceSizeX, which is assumed to be 24 bytes (see init() above).
	// Since uint256.Int.z[0] is the least significant byte and since uint256.Int.Bytes32() serializes
	// in order of z[3], z[2], z[1], z[0], we want to essentially ignore the first byte, i.e. z[3], because
	// it will always be 0 as the nonce size is 24.
	cipher, err := chacha20.NewUnauthenticatedCipher(seed.Bytes(), currentRngNonceBytes[32-chacha20.NonceSizeX:32])
	if err != nil {
		return nil, err
	}

	// XOR a byte array of 0s with the stream from the cipher and receive the result in the same array.
	randBytes := make([]byte, 8)
	cipher.XORKeyStream(randBytes, randBytes)

	// Trivially encrypt the random integer.
	randInt := binary.BigEndian.Uint64(randBytes) % fheMessageModulus
	randCt := new(tfheCiphertext)
	randCt.trivialEncrypt(randInt)
	importCiphertext(accessibleState, randCt)

	// TODO: for testing
	err = os.WriteFile("/tmp/rand_result", randCt.serialize(), 0644)
	if err != nil {
		return nil, err
	}
	ctHash := randCt.getHash()
	return ctHash[:], nil
}

type faucet struct{}

func (e *faucet) RequiredGas(input []byte) uint64 {
	return 0
}

func (e *faucet) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	accessibleState.Interpreter().evm.StateDB.AddBalance(common.BytesToAddress(input[0:20]), big.NewInt(1000000000000000000))
	return input, nil
}
