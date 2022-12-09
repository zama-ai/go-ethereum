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

/*
#cgo LDFLAGS: -L/home/ldemir/Documents/dev/blockchain/go-ethereum/core/vm/lib -ltfhe
#include "tfhe.h"
#include <assert.h>
#include <stdlib.h>

void add_encrypted_integers(BufferView sks_view, BufferView ct1_view, BufferView ct2_view, Buffer* result)
{
	ShortintServerKey *sks = NULL;
	ShortintCiphertext *ct1 = NULL;
	ShortintCiphertext *ct2 = NULL;
	ShortintCiphertext *result_ct = NULL;

	int deser_sks_ok = shortint_deserialize_server_key(sks_view, &sks);
	assert(deser_sks_ok == 0);

	int deser_ct1_ok = shortint_deserialize_ciphertext(ct1_view, &ct1);
	assert(deser_ct1_ok == 0);

	int deser_ct2_ok = shortint_deserialize_ciphertext(ct2_view, &ct2);
	assert(deser_ct2_ok == 0);

	int add_ok = shortint_server_key_smart_add(sks, ct1, ct2, &result_ct);
	assert(add_ok == 0);

	int ser_ok = shortint_serialize_ciphertext(result_ct, result);
	assert(ser_ok == 0);

	destroy_shortint_server_key(sks);
	destroy_shortint_ciphertext(ct1);
	destroy_shortint_ciphertext(ct2);
	destroy_shortint_ciphertext(result_ct);
}
*/
import "C"

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/ripemd160"
)

type PrecompileAccessibleState interface {
	Interpreter() *EVMInterpreter
}

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64 // RequiredPrice calculates the contract gas use
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

type fheAdd struct{}

func (e *fheAdd) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheAdd) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	if len(input) != 64 {
		return nil, errors.New("Input needs to contain two 256-bit sized values")
	}

	verifiedCiphertext1, exists := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input[0:32])]
	if !exists {
		// do something here about u256-u256/u256-ciphertext/ciphertext-u256 addition,
		// not sure how it's defined.
	}
	verifiedCiphertext2, exists := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input[32:64])]
	if !exists {
		// same goes here
	}

	// serializedSks, err := os.ReadFile("/home/ldemir/Documents/dev/blockchain/go-ethereum/core/vm/keys/sks")
	// if err != nil {
	// 	return nil, err
	// }

	var decoded_sks_str = "24100200000000000000000000420000000000003eba269db2ca63b7eb371044575835a7b2bae9cef1e955f6d2307a8dc94a1dc5b751b080d1f5d7ca9cec21acff20304d6ea134360e84fc489609096ddea8c9040bf5b5b09b3066df6f5260f11301b3f5e7b386207320b03e7a09012143a11f27958ad13671fbdf5e478132b297e9aa656b221af7a81a5d3cf126400e1488469a8aa0f680590e3ee97f07ebddccfd2c80dd4bc10cc1fbb3e48a6ac5709985742505eb2e5a013d9349fe34c1c668ac4ccb2051fe24950d37ef42e10863bc35758a1f3cedb23643c0962bcded5146698221eb1cd9b203f06d0eaa3099195d29e32fe13ed0a16bff3e050d55cb45f5c80695c7b850c8249b48f8357c18d47b8ceeb37df5a7d5336ded4efe4841d3ff77e16b0ea2a1c7e39597fbd4d424d79ba1e45d6f75978b63d010ec777308e078ff9fa8df68ef1d7e7dbab18c851399baaa85a27fb974d792b7f5f48d58885c69ceb7081f683fae85a603a067bc229f05c7084d9492450078c642dc8fd8f91810921a7956cbd069332c12968a7d5e33b8b237b7644cc73c4f11877a974edbf4840271cc908b5273fcd995e30dbed7cb18a5629a9bcc8e74e22607730cd4fa7d785590ab4c241b101cb655daec91606b96e45dbe7cb305a6724d54a89b707eb645c9f3906f6e3a78cded49c2fb19a4759f58e33bf5a29c16f1b23df9103d72bcf42cac23960d9ef3662afd422a58b028ea39f5f4636fb95afe5bfa5b9ea6f9739d4729d4d2855f06604eab4c1d5f974a12d46b32cb751afca11ac28ac13731ff551120ae0a73100dca415a8cb481c0c659b87a247416bc6178e2dfd4591b5c349dc5266451b5e1b07306efa8801fe8dd801639113a858fd89bb26950c13cef7b2ef03bce89dffa787000ec6f360a16ca16eab8ff47389a9950f68703f7208ec893a8f75e59ff09fc41d2985167d4ab929c75efede426ce43c5223530be21a990a2b9f795faa48eb7d11ce3a7c52df9b8d1f707d9ce8b70d8bf249a333d73faaafeb873ada076eb62eaa3e04955e4294e315a902aaa6e2c896610352b2e1fd3691703e792f9a9b90d31a61336a7f31fd51b86d5c04321c07bb6d44eccd65f1109726eb99ebfce764130d8d9bf191f70c542e11af5733d6b6c12b08be0f91d29dd94623551daa7a8a74d94f9becb032b75cc235ad64d074654046dd47c11ef4802acb5d915e5e4ad347b4ebd9ccf6173bd5ccd04c88a334f542fdd17810700abbb5a84ac1da5109b68b3444f1effe0de73e025e0f9dff447637125c6cf7e9602bb2f1c8bbccc4ea694dc4736c4989661fbde0c2d7a3dc8003bc9e7f47d6ad6be591b80f15e1d2d11339e86bc4b090c37bc13aef3077022762476977900e7325174e7e8054ecb262e71b7cdde469749a5c7fec98907ba08eed13839c78494d42d525c8f5e9fd933f2edb7acedd70f0d334df20c0121046fa4188f72fc88310d21a0cd5400edabcd9117a5016777d35634adb087b66a69683019ba4160226a23ab55bbf1f0e387d55c0adab6d45a591cd00e853593d1fd3eda85c10b6fcf7eee8d7b65d7d33624ec5927c871079e15d0f9619d113e083b71dd86c5e75f233155e8cadd4f40c4366895387866cec9c2638326d70ffe9c07bd141a83e45af36aecdc8253b4f38e599d3b80d4806e5e416c1fff820f4df6280906681ab6bf59780e294253671e68b07f2f5dac84dd4d520abd083b27af0201a77f499f76c2824bbf27337dc5fb22ed7f7b9a78c711bddd465f722f720c35100c47bd89851e29d477e9c00be6f7e1014968e71a56e4d3c58a4e64e39b91cad180684ebc9a928b877c6188602a048e259ec5f10a552d77bd14e0f9b94a45a28f216665b67149af1cfbe724b6cd5646099142d757cc0f7e2a30481f8d054ddc11d2bea35419cf951d1c586f08775b4f8a4360781df5d57c3925f27de21ecdc9ec676054cbcadcfafa32f7e7a515d31fbc5a48b91fb79c30ce6d0882fa4245fcac7beeb1eeae87c1fdfa1abdb9e38ba2d10a7d6ac4d24afd3b9e5dba84aeef5882555edc365030998865a72b26e80615e5abb1531d263b727c274fb6180e2de6dd0c02eed795516f3e670cc9c7d0096285bcb827a052834f5ac8b0536d55f02380db0dbbf3328a5950282a9021fe62aa105bfff2e89bf461bc3b7ccd6c699472911c068a1a2eaeef33432759912dd764dc7871efbd0c09a6e97f2aeb75de1e5c190c3f9900c209ddbd3a57c10ad6981239daef8c4ca36f6f9155fb934c3b86ecbe2c5258ea1e9c8ec26c185f0a5936319b4d9367e50c1ee296eb8efc645dc8113552e51b45e77df58a518e48540d49c6001444a4152921dbadc2f7da085e4e438dbed01bcac69d17ae8c1eb87aa6ad5682946afef55f86398070ee035042fa9bf1facc80d4a1310f5de4730b5fe63b5c5b09f692653a2ab0b0e291cbb32221c8f8cb5885fced93cfb45b7e5d4156afecdb658358a090c9d4b042d33c2f553c7474197516635cbfe8c40ecf5afa91d5430ab1be004ee39a2a585d49ec422826f6a163cc654508005b5a464aba7696bab3e4f077b2fbe0a7606829b1df6f37f06afc068d0d4ff70192aa2d99ac8371de9b929b986604d78a9cff0c359824a20540158eb45ef09beb6896f0e27c9e23807abc83dd383ad1a77a34a4d681464958a0a9c8dd729fdd0c91893240593d6f8fc825a9274b46623e20be33bf1b25b1599e46a73d76ed6ec212acb2ba203ccf9d722da0b8c8f4900226ff08f117aba8ecbf294390277844a7d569b96df3f126f386565c66996d0c8c71e24007924a89bb44117692b9ed1ac8a50dddddf82dc1517c8adee05f091488e5bb43f64f663d7e03e64ee89e33dffe56a71fb8e25055925b87b6b5fa6d125a730a2e62d109b050a33bd9cda0a0eaccadfdede90e4aff07ee7cc7a2d5369765585648832fc90f5de16fcc78e4c85d55541ce2eb00d191374dd9452e12ff2172c829cbdfa67123c7345f4bb5de75d3a1ae43f4c984e0a960c4c069f0e22eb40eb5af02ab2a4cf8cca875a2d1f1f93edeb7651501c0e3b7d2bac20d2952e9cddf2ad5b9e4758b4b60fd4d6a29a74df40a3ac1a72630170486942390fee366728accff963c8fda7a0ca1aae964d35e7cca04cee9d549ff106499283c72a2940f10c93c45f6b2fc91b32fdb1bcbb5fbe3efcc092e5f881b672d86acb70f7b1a8effb4726cdd491782be5401c89e81a15783fb7ef2792ac3dcfb70d67658cb4215d463422fbbb6447c354861cda786a42adecdfce3f13cc30426827cb4d721dc57cf08f7033b4e3f110894db486ec47af3a5c4927b96f87245edaede333daa9c5ef1a480a38fa604cfc91aac64d8f919a8c57f7dc06ff8d75f9098191df1ddfcf425ef73e5b94d00612d7f810eea05ee02939a99d82d36adfa7a0793c77425252b7a864b491b2faf34977703ba0e8fc2dd7036683b688404ff05da18013279fe1638fbc75ae2dec661aa76f8f23d67286d1673850f697dc91398513821f10bd23861af6770d6a4b7aa69fc5162dd6f378881dd8f62001ba8fb4918c1336120a3fd93b71077d35241899673fe3911461378b7854d3598309c9258ebb5404926161c0f527369295472e38e76fe41574e76bfe846a888dc9777d9a90135af05a48396ecad6ac9de2244f7c98829aceeb28a875927ead42585822de6e49ec28d2572bca4a5ca8e8c6a6cb2d726fa87d2ed0e95a00012bfa646fd3d04e119c5a7135e6bb96b5115b04bef0b0bdf7168301af130d284a4c240902eaffd64d6b51362c666b40dd0689a3eb2325831d2edfd6c651d1d7f273cb9cafdd192f1f58145f2ede2d77d93292bdbe5a63d553b9b1e2e34e24a97fd4d91b0150d173c51102b03aae7cfb6d01bce4709f85ad0be3741f52f55c04dc5b6aee8c676d314a8de7ffc57f973d146c77fc1d123dc7e2878bfdf199ce1e3c2ea73ab057cc6daffce7ec1c6fb6d8d6ec8b45e5feee6786db2dd9821b66fa339568f55a6fda1a5f2bbeb55f283a6857915b1ccfc0167996d31ef3a4f5f1ab0205ab3c1e8be023983996a0b990a6c774c8d463528d7d36efb4128a56aaff22fddb27a4faf62eaa7174bf73ee9bac87905b737596c7b2743b9c4e858e039d6e22c6e8f917d01f3545e0964583a02d34f692c3606babdf6c3e5d83b1ec99193adbc60a5fe3755520b39143515ca0301bda5d0f297df1fa669300f5b387f12ca78a413380d1b095f725a428fd1785fd8960e6352187b38ccfb15e952fab7405028fc638cf63cb22fdf136a967df34066c8370d567d792d2a029e6b7b9b87ba2a3df04a74d799d0b4c8298cad7ff130be68b9a9048d7a4b19b2fa680b8f2fcb4287809651c9f6f1ba3336e4f455e5d0da8bfc196f0e84e5ce25d396fec8bd6e9a1f8f69283d5f23e113db9da248fe384d40cb5037b1e131b675d8cafa06778fa7edb02997c9350c86e6648e4bdd83ccb06c29af6f8cd3e523bc8f189cc683d0cb11c35d82ab1b17d7804117f73b26fa3da27bcff3003196c90ad0b6538770604da06d45cfeec043898f2cec4e6b3a371dad991a2547fb847c024b614714889ec8cf2f23700e866a42385f62596fb4af381bd24e8e17f1a4063c601ee0a7b2b44740ddd6fb656851af922f2beadcb8f9a5d057246fba59b976a3de0918d292d7d51d84728332b83f75d0a3db82466a30161324140a935151de113d2d674da87a8666b5bb8f745562dfd00fa206c222e000690d1440f6dba8b8a6ab35f1e4ccc7a775466f2d50e5a9cbb346c245aa19120d499f9c2e793c54edba697b6c8aedf6ce3c6d6e9f859fb1c70ede46b81433b5b126dfaba6b6f72043ae2cce806842ea39d2702b80f7353acc33c15db7fe84faaa7b31f7b71f6cd4ee15bd6122eea246b3fa18e5d9335cf3ed8fe0db07118069ada213c0d2dba3246f8efd50dc516624e86baa3e892608378ec26b81f2671b22b1a45a3c8601cf0b5eee6f7d782237cbda01568a72f744697f48f2a2eb1972d9295643caead2ecfaad0bda451311d2454ddeff8901098f6ea1215bddae3946269c47c028f196bf652c33c51851078e906f1252e1d1986e58b77f624aec1c50205b87e671416e038cdb5598500d6203ce1e4d9a8ea1c2c583b967f61a46bcf592bb4f6b58bc57f84979b98e93ffb42f85cf92ed1820a2a77e55fa938b2b12d094af12d29d11ea1ad8c4f9d8405aabb51b6723436577fde76ea5d6e3cdefaa8798fd913c3165829184c41eaae42faa9356e38f88f39d4fa97515df2eb0029aecceafea4b4d962a4c14ebc4d13a2a430c3c075d1192bcf88c24a25c2e1ef9a516bead8ad4d6de8199dbd540d29957631884b58b65cd8ac2a5c53d65df13528888c6ec8665a7f8a988297b3414d9d8a9281793844d76dccac2d370b0d715bebf196d52dcb6e4320e0d19a5b4cb8d1af2a8437ca8108c2358aeacbec7710697f107c9df9eb15fedcffd4949ddc0e23465fd63340565fa6277078176d331e444ff4951d4b05b6ecd9797f33586acea7a5f194106c3c264d384866dcc5091e9653502f2682ef59690d41228ec6d39cb9fe92361e9ef3120a3688f4bbd06e787a63b44b454f5f6e4c08f5153ba4c96179f8d2dcbc0bbbf93fcabc4b7a09e1f49a4b9ff6206029854a8f4f036eae713f7e5301075a7fd9d389dcea2c21e596ee8fa853f3e8ce7d618e0399049745dbab91c53a7814949a59107f342e440b61079939bb4a720012d66ba58b465e9e89e1ad375151542de083b91670e60ca187bc523cd7809941172edcc0cefd95d1403c8c32905effa48da16baeff622a598e7f14f9049f554940d368cc20af8b67964e2712e4c1e780a4dc489becc65a9398be4ce720f10af8ed06b4a96409763af8c9679913047af1e8b20dc0dd2a09eea88ee917bf7b3a3ce971522a8c3627fa3d1c9983477a95aa9a96faf596265ead1e1a251ab0f1f1d51540add0e4ec3bc6274757b0f95e137867cb4ae8b88bee487abffc69a9de6b5d76847f54be03a7470037a09c03671518a097d87640761fc972eba17609e3b5afbeea607f36fedbc473ada5e6c16a16f77f5ebb5b624c14704d958f37c9c783a7f8aba9516d6a435b9b61a8770c3542b48c95e7159be2d951d67963d13b104f719f6f9cebc238c4ed801b0cddfb576643f9c20facc6e523df9a69bb2cac9fc41bc7b386338dfed35c9d7d57790be585f727f9f68f8b4bbde1bd6aab441e24ddbc865b9287a2f55f3965e59d9670380dc1cb097bc70159ad2a81c9da3799b2ca1f448f20e126bb300bb5c659d73376122e5f6f5f3b5e64b25dad9ab4c1c1e261c1cc9a48299aeb1e3062d9bb512d614126567c596c28c155a9c74f5ceb9cb8f42198becb530af1593c0a21b3a6fbca8465a28f2b340c88699c2006552235b54e55bd541cf114ce69d15a30d59c49423f15d3bb8d0d1f8a0c33047b3e222ecc22089b27a2c765c848dfc96e7837253d7cbf4b98a468594777ca22f01fe313e8121c72da40e8f9113b6a9dfb98bf2ae326761080c4532fd5c6aa84d8b0fa968fcd8f5d383a6b8b7bff384646ffc11be159c32bc6600bde2a039c9e6aa5f7cb582957ae162ae8fde18ae9cad0d1ebe3e9edc95ac6527d2f9bd6281be690d2ef840ecd82643e0afa2d892e1ff2338d8e86c65a813a8a0e2cfcdbe5716de791ef5707d3cb1b1db637ce05c3ec3886690e67962c381e7c14c2d5c6d17751d94db8ab70838e5cdbdc394cb32aa646e6abdcd872930e9061e7c94a047b23563ebff00b5d44af5335f9e631cdda3d7f5103d8026cb7f618ae3c8133fe4a9372cc41106bce0fb737dfaab144afaf8ec5c52697e9fd0d596a67e63afecce72db5ebe2f7cf1419334ab9019a150c41d2cd41fbb849097f757969cd11f52b42df88555c7edb7ab436be14cb99358a1410389bb8870b47b251682006668c0ccc9e3be8917db87eaaca5bdc2a16e61c1468ce0e349e537b8808412005ee115169e8f34d1fffc3f6fd638c365312591a4b73dbd573227b09b924bd7a36492d6f25555c7d1ad8bec7f50e460e5038fd2031d42175d1147febc9a27039d3bec96f7f21a7938558a92d4f8bc6e5613add852d4bfa864413580e35a30c860a4df8400fea5ef399ef232b16e5ce84208647511a07b4ae81c9bfa86274751442960647aa4af166f1eb9b75c4886f7c652995a6b25be32fa3a2e8e576ded822d3787ec1d64192182d11f9cf5eaa388021df4d81a59c972c4ba94501a977c2145a91ce4674ec48d9f8c5a655d620592f18daab3c2eebbf4cec6cd13cc49d35262f2713b081ed7582b5ebca740e43072539e48964bc31301315c5153476b69e8ff346d158a48fb23e95380d17f47619bbef44551931cee10a0aeca835e7957b95e6e01f9724d8765663b9c568dc4fdd37a5e66cdbcc3ab7da0b7559068e8a1e75847398c150e72fa984fd96bd5261332da8f0674be0f04b2e40af1f7cbcd951a28257beb997ac8828633c3b237b2c63ebc8b54b7a1067a55a43028f3c9cde3b5c3a5233044b98813d5086b7f18267efdc0bbd129f9010821e89deb01a4ccf5c37cb744e543ed39293dd8ce68a2b2dfcaa03e60be0f77f21a79cea68428e97374859a302dda353839261b1f8b9a84602571553a4008b8a34a8005fbbe53c06e5d3241af4da6295d9754ab14033995049fad395f6b3443eca8d8156246543a4d80869b2803c9b18919ba8b6973f3c10cb75287ed1de13c858652ca39550276df917d2d31b74282b2c9494dc036df8f7ce788134ebe09394848be5eb390ef0836e5eaa8476ddcbd2034b9670dfd9a9eb2830f09db7834dbc3f57d074003d762392a1cd60417297212671beb306e9f9c471319aa35ab4f24a28452fa35d57f3605e3f1b8769ee93c46785d97bac1f3e4bb65ad7a8c1d2de8a9afebc5011e1ff418abd7af08aa062eb2f7c918edc7203fbb0d35bc855ea7314e22de637612cf0ced18e7ff115f321590413020bf454da1947519ee663770f79aa0d8cf566d5ee1cc55612c61de36e835d7da8b524025a58dacc012d391900948a5fbe94e71e4e5c8c61ff335f7aa45dd47519069c7b06a9bacc92cf68145adc58c3df421b413f70ff30b184a66d5f57be68d5ab6ed88871358cb1f48205d99cab93b3aa5ccaea1657821402ae566ffed0003dd19fd6e43bf48820bfad90db8a0f35803550fb3df69616de07f79ace014672d907feaf132ab4bfbfc41aad32f43df766e86842f1af02709dfe45835bc42d71417383f670a77f2da71cfdc484b03c66b554b85dbec345148b63b7c19b8b11c25fed05e5c0aacb355ca9e1110ce1bfd74a4d019b6fec29ee9e001a36797807981fbd67c2d1988105c396cca7a5b07b031b4e5f3857aa53d4dd41ec5d61b3e953431532485ff4117ce119cd3c00aba6053db0b1eb7e63be78a70ddf372844a10b1d1a8fb1fa1c143bf67b2df3e0904748a7712680e228b48494fa40caea8f6b6e16e0a28bf9900204e354a25041d7ee161b89acdfa9807dcf9a4004f5a8d4c63d11ee29e44333ec324dff185ef01e348c63603a3957fb2a07b446842d28236a8df2f30b6385d85ec9da5cf4ae13edd6a57360b109b7ae7e6ab82f84b1513ae2c53471aecdee19716e61f54a016f5a02f888f4dac8eee8587f3ace40fe2be82ea0b0f1829d470a92a840fa4ef87844b7ff8e3d95cb5547c0e5393f097d71386ec790f5a1f2e1f10fe23bfd356592507ff2567201d899149a275c1306dd8b023527effa18d8bf263bfcdf340c8c3fe02eb9aed4d9e4b02bb8c02ef7c9fbf3c21770d218697f9a113f9f6a19313c3b1cfc3ebc3456be153f59e4be2c1ac9fab1c86004284cc9f3df1b32361b8873e2e91d165c5d50c11b9aa249e90a23c5a6a19b0e56019c4c0989078f1b2e89f95fde12ca25f7bdc94c25ab90dc2d7036c1500e2023c30d5307f94b34a9baf74d3643a26bb4d73803fafa824c26f7dfbfb4a941702034716b20d6fe8c00880e1172d9d727d154f16486f2d59ddf6db9b2bd38f4b28de10f16d1ef258fa835b2fc11dcb8c27f2ebfdae6f75ec067eaa3e00d9f619eecf586c608ed5cf5f18e3738d049ddd5ad7edec6f5d18dd944ee6ff078ddf4197172d3c887e2b8eac814d0e59fd85845f41b896691d04d7823e697b53090fc3ced1f8e9bf183bfe6a31f103c3d06f0ef08ee5f68355a39be4c83f520876699352db885853a943d7b507e4e2ed78aad9245519b43883b6ee993d3656780eaf0ff5a9100cc481836ca7acd3979a18c4ac3eb2c13443adf9125a7d76a91c7cd22c7b1463a5853c6b8a6c21aa588006cf34fbb02ec8db10549a659ccfc3d7d8437fe59dbd42412929d1971cd7b3e0e82239f04466ea8833249de2029441ccb216325fae2cb5f2f30808b00b268189081d1c5d199b0088c49c2d1de6827f7a17cbf36456f9b74313dca01ce53ba07f4b8b9121df2dddb610169dce631b7b1e97220c8db80bc003ac4abb6fb3dedc262e8aba2952978b98a633a7e4da7a842d8848fb970f27a067a8df830a35a45118b45f5bbaae952b5c463c90c7d2122a676e24b9a64c162d28a5112110e4fb010f502c99fd0347296f49bdc9a9596f43e6cc876940c8e613bf104dc1766817c27724a63dfe302bbe588294c1ae6829b4588e1091d89250afd7049350de0ae8c48973d6233121aca4185454b9cb6c238bfa94d4eef408383fc387e310b0e96a61adb4866634e308af23d91e88685984aa1f157e0f11437b86f2d399a802822a9c2f17b05257f76459a1cddf349f4dd39469d936c1a877de4f5afc03f1bac1ffd9d4839d446b4af2ef4afa812c3fa6662401667c2994f428476f32ed7bfd36b880f2bff59e6c2444a9ca5fb51eb55ca4bd11a74616e5ea7071e14232444bdb4eccc9a56c7c96a2dc6927fea44e1c482edd6d6fcddf36d2e8f98c111148b93232c4f3b7e8be9fda55592437143e22ab0638e1560e909628730c1ff26ff1fcf15a4560c06049bb2749fa13359d3465fea476020483588b0132ed4157bebd841a5f0819410e8082d7bfc3e29715b7528f2bc53ea79dfe6fc9f1ac87b304129501c6709fbeeea8b0e1e885e97545621f50f7050733b55979d8b4b1c09581d21f8bd5b1efcdafc0fa90ab8e249741f76fb0ce90604611c8e2ce588f95ab28b4a25a31173061fcd18bd2689711b3cdc5867460e875d88c36186220af64712fd29a9772161f86d8bd99cc958174f2045e20bb88ff77d1a3c3df4fb8d5e57fdb0a84247f14b919b0d31660c6f3c014838fa1497aeeaa8e66f32810ada8837577f2dff23b55655af52fe44f7bb0857587725e0c704b3b83be518771ab306fce8a64fd44e5dce08ed5f122aa228e59fd37d64c0f568a688c55b72a8e7ea73892e66c848e7f5b203b93d6d9e3720863917419f9563bffafd408aacddcb6198b9f842fcb1d5cd0629f899f3e25a7e4139c7c16ef411c7e457ce7b68c11ae0d6d17a963b33113f0efef0daa024a22c7299ec4daec9306a5c4f0bd09be0be010b4c315ebc2567d7795ec1331c1406394d211211ed7fdbce82a143d791f125d3a3bba3c9f517843fba2ab234829bc4ee326a0cbd67921acba71a2230d7b975e0ba404d5285e7a1badc46b6d982089813b91aabf451f848ae43d675a29adb3c2920d79262fafdca02f742a54005f186f3e4467751a6a810b5bf740a6648e96cf2d29bb423ea6ae737a8e4e5ab8a0db43257c0348a9e31c7dda123bc01d74c2cf029a74616c138049fddd51aa660bcd4f4fab35bf8fa6fd5448dc500178346c0b3ee7a35de910251c36839254f436d621a58366cc10ab55b23c3018e937389922b6414c59b57a86ed3c84f39c3ea2d52701a66cd79841ee8a7e3a824f343c42bbd902308ef47320d8142499612ddf9dbc4b8af374f84dd93733378d92d7037de85cd1c6ed5fa011f32204c35f8e775c452f06b98ce67c73eca33d44ee8dd35372033cdff0c9413fcfa8b9ad7c0778a348dd9a73af7ca7b7a741b1899d4b68e93788f316dd346a68d3c68a7bb37f1fa588a3802d5239f41a3e7ed383ef1171853716df7bfa17a8945c4810dec85be7b9520dc31ae8ca3373e198c26022e8b5008078979b32a97d70fab8db92c9ea722d5dc0fa311a50b56d5ab2d15b229dff575f447e3c2acd7e05d251c0ae05db9bb1bf37c03c2ff05ca1093d24d8fe66de4fb7548b15a7791dcd1115124f0f1f47e947fc01583e0fef14e401737cc485458fe47ebb92fa5c12251117b8b4138806e48b3474f8abbe00a7bc67e4c139f26c3f3347fd36928306d1b46d56ff84e6745db4949c601e3cbc2ff371345a8f6de9354a07fed4864128758b34c729d530a7f3d122516edeb965e08b6a3160221bc7b3df9591e4ff9fb43230d1c181c882685f984950b14734ec7b4bf523d00c30be2e9e20615d3d200f562d7fc8a431cd18df1e1342ded7a38b427ee86ab7f20b9a1202616816fe4767567aafcdd44a700692a5947c8cf524b5b8ccccec254f2f1e300417e10123be62c1c0d186bdf5cab4e41711e82ee79126e63ec80cc23767ef2363a4832b5bade2af65f3eb66a40c12eec1952313dd1a58d6814bf4675d57de27f9de4be81c85587ce0fe0bb28f1218ba8ecaae2feaccbb9eaa9dca41759bf10a8666fbb2563a96602f1d50e2f489e25256a266ba2c7148e16164153cf5d7b143f86d44d42d97b88d64025aa33178aab713e0cad0d2449aaf144beb4d5c52b4ee92774266b61e41a3136c9da8c7b45fa5eddc12fa7e348b2af81d3b0dd20d9b19762f63e73d233c82c0eda7472126d6118cc3fed74d7e02ebecf82981046a028308f21c0b39f7313eaadecf83b683c8ef4d08c33a01d282a0c2068b7c1b6eb380bd04a617a6428dd64342edcb3d8b098a84a6dbaecd8fcf8cdc71d3eebdbea3fd6b854f3944c4d8d32bc1290da78aada09386063ca50a2d7d5cf86ce2380e567937c7d0b2cfc4ed90b8af59db7bf2bfb2100c86be3f3facc36a52249311d59a8d2ff06c84d881238989e803a905a090ce7929fef25efd1f2aafd206522479c5b0cc1be9e543b2532fe96a68ac8651e19038e0433094dbd824a075999c7ee840ce8c7911dc808a6f770da2bcd1ec13ca4fa807f2b31ed37ffecd3f01e73898fa579bbc2e13601911d13f6317cb1c6bfba2445e0c00e8e89bed42241c42ef96963edc02de4cc7bc0c4704e991ac2d53e2ed254cdc64c2c654c5decf3ba1f373b92b7dc7432f9a21fa5b3742481e51c3387f44f602bc9d06c6858b15cfb06edb854a3245c3d955e40e064af7f0871b870deb8c4d4a553eebfc47cbcdb18afd498a8688743b8ec0afbce92e35cef1924bb4274de95731c102c856e0e331e31b517f27eb2beaf94acf13f78c7bcaba17517e18618e21d8eb72aaef6f71b52df1832df4d60ee3d8e2def1353502c213e2535d7a85e4e49d1af75141dc5c072eadd14089c23ef90f5360b427a59bdc22c3aa1739784f0c4eb1ef92681944e68cc9c031d4be9030f6da1d1db35278c1b4531e5bffa0594c6343533159288afdc9202fd4631eca3f09c1cc12a0e56328ca350c5c4f8d39e3358006b7b0f8258c7971dcb0f0debb099af1c3d5097c5614d38c5ec0a6a1a2b28a9249e5a88055bd137bcd47c7a5f49455e09f3ef152e94b03e3dad0ce4528faab6f249531549dc53b51e155c33cb30ea9b2f9d756df1e66ab51ebd4f630b11701a892deffdc4007edb84c50508aec5e7c5a52fca57205b13176c6a702302d2e9eb7697a2d6ddb1519768bd8cb232707da9710968f0e2b6857ee365b74a39aed9adce7549bf07404f1f06cec56bdef37aff247836886f1acb8a3c7a57129247a81ad28a9bb016214e9deaffac756899ad8e57ccb9275f00c24608a00502d7c688d0bb633f01a9850f92e156be36b6343f271aa9fbc103682778401a71213151d0c50a541d568c12d23696671e9ae2d932f7353396240dfbedc434d29b5951c3c7a6ffa5099f1f68c14acf00ec9d86866723afdc8b3945300d164b8fe854f011f82e0ef12eb4bdfb8b5f2f6974a5a80d1e517718473715d60f27c145b349f39ade4188540fe42d92869dc79ee6c3c338dbb63805c69285fdb5a252ec03b1b1cbdfa53fc0b9cd334f5b246175533795554c0e43c013d143ebf4ba9fe053802f732fb38e1bb813fc2feb8f2610e376e8a62e357beb62cc2c50bfc93f07b86522ff258e6578d6293980ec4fb2c49cc856a0026c985d7a92ed90a4c179be260c02d990508fc735c260057a8bf99dfc5c56496ad6018903e4ea3e87985122733480459c3d8aab1c2619699754d141b9629754c936576bde0f6ccf756f6ee17097000387ed186101a169e8f5b27b4994201bd991b628c8a909a978a726cf2df3178462fdd2087b5ed1b048f34ccbe525a4afb53959fb6f1c92799eb40c153404afd6e80bf3610c813155d7519b691cb7311cd6af2e39236e84740bb3ee7a0db4e251992de921b38140921fe5ae87340b621284aeefae5e3fa0ff8c6465cbce15116726a2d4fc7abf408638716b9de900489fb6db9497eef0f7a014e2b50220f8aba8adf3daff67d90cb31ad33a49cfa70ebaad607c68083a529ed106c0b8064bc9a0eb9df08669b5d3b20905117b4263581cc8ea29e165a1ac2563e7074450cd623eb5a2f559954a583306ea94eb2f855507eec6cb5f962711fb915ff76a8e0583ab189bd72837d4e969809cd187638bfafd1dd39b4fc90577cf4a147e88b274d33eae3bb5fbdcef5c6281ef66deb21f3a47751db4928c0c0f2afc6297bf757e6ea2ee1ab310660f5530488c872670abbaea45d027355a867937cee8ce6c5423640b69effa060e08ed1df07f383c6a9623ee4314a4889c771ae51a22750f6f8605b8cb115b6f33d311663601071377cd9c70a9c146709f23b434fd3851f1e2351287c54a0d726f1dd6ae7332ab5b18f7458ca1165f4257bd641f0b978d3873173f478654726c037ebbd96de9192fc69dddff0d28eb886fa85ba88146d849b86a487b9de3f771968898b7d3d62307ea34367315ad92580e1a107cbdac89cc01b7d71818726987064f8006294bf54fecb93cc645c949696c5cea79231864eff157ca27fb2982c100c2cc56d15d34cf57a2a5d3c23b35661cc66744f7c55988ce52ec6f302ca246fbaa2a8e1a0550547d2cc05bc50d1e068b8ebc290d731b88a37632213629f7d6e171b57f51ce0b6009c27717b916bb41ceb22c63e13f04365fc840ccde1689347efc23e7ca2f99756240a376a3fec9796fa7ef38d2f520b4723cd606b5129972aee88af295fcfa67e40b8e4919305f2bf167f029385238b53221524f887bfeed21e87dc8c5033725d8bdbaf221837b51a3bb225265af2299ee654b2bcf7107e6302363b300d778fbba61c2c399e45302febd834711760d43bf687076175ae80ea7c3499dd030a133d94866f8249b787f99aa4c89b73b1896829948fd241b1beba4d1e0b692c3c00736fdc5f4bc4d6596d79f7c9bd9763498c5af90cf763dce8a271ed2d37ed5b8eb3b2984087c8a0f54756451c6d81ee1389d77ffdc1a66c884de0103e1a558744c60c15d705bee6f22ad33aff5381052eba221cadc20fe8c85cb262ff98b05ba1b8ece68fc51978ad7aa319a3a42b56c3bd2795f2b83cd8e75785ad2606aa844e275db78d3265ce486ac3fcb3494d67b159a66bf1f873a167345bda4341b204fb5cb8cd24d695dc575895ad755028bac151e0b5b4a837cbecd2de3a98bdd49f6d6969cf8971213a6c2a431c55bcd607ec473a0df8ab43c444c9e3c5d99001e4f3de9c7532a8ca668b8daffa5c661d248770c74ec9fcea1f3c238c479235eee73a80c30530c5bd54b62de99863692d98f76eea640f55905cbe7271a921557f5dec3513fc42258c813591e5967ec0556ac3950de23a66b4850958a24ef4f37e3f25b0232ce1a0d5fc36507b2fa76a187456e7cb9ee6a8b44296600d16194e54ccb2c8fae343b0a164c4dd24774423fb57717285f7835167395a08489dbc896dd9efeb082188ba75e2b8459fcb1d6784855f31facb1336bca06de53770b93cdfdeae97115b3a8dbaa7c15f5aada86311215ef1db2bd64352142213ae7df850be4b9755a48e363baf7c59c492f147a63dfcd40dcd51523c595d87602ef650c818044ae621f0e22378410939e168d2596bebf9c4f94a99e8171b4867b1d3280d75b874fb103a202673cdbc5bdeef13843e060fdd433564a1367db71a357649ba6566a2afec54f6901576af85ab032ceca73eb54fc04d970300b2524e0d0c3451c2d8c57f2bdd845cb3e73326cd82ed3c2c584499ee1470885b51a88a3f4b7300ce5b1cbe9b3b294641a240f9b5bff5bd1d000343f2c07c8378688c68a9448cbc2edfeedc15df13c7bc652cb9e9541b49e9d2b1fb85418c2e15a3885f4690c3de71e294d588910ce54c61505a14aed47af9e889ea802ad0db49d9a337ae209fca632925357f838a47bc8886971885121c2ea82a3a250fabd8539e1a5a8368a9019a4f42016761a9656d397d148790839ad40922695fb6141fa07fee904a85388a79ed41c0783d9302700980d3f286395e5ed4eb27dce5b711f840f65182af29964ca8f573c3626518fa3f0da90e935b86b872c6f5000fd0870c182fe3e565d0306d65170d9a72f35f2040db1254a94e95b592b171b3b4c85c3aecea83932cd3348d13c71e49ff414b73295878317601b201eada64c4034a88a74c72cb7d878ba1430df4451f1952163ef575184250e4dd520210a7a8bf7085743f3ef304c9e23770d1094ded71a0d7964730e6d7a0761e0629779d2fe8cfb0d9bb2739d12c6d96cc3281b6305c66ad6461f8d615bde0348580ee87ac8108e1823bbd3d05ebd62d01be0d441824ca4b89a4ad687becedc0c45b773b028328bdde954933129f019e7b390216087adb0780a1364739fc1c57486f122fab3dfbed1196bc592ff75655edb53c7a5cd41d9d04bce3413abcb1bafaf1799517f8be062800069cf7884d001f07a7b0dcbf505062e1c8130396392bf27f37b6488f275181889cc436d9fce4908ffa9e869b7924856696109b1c9b08ce1ecb4d58d6c048c0835641f7eedfe40f485ea751e61324f1efa4a7fd443ee42627309e54e1cbc1d57fbfd5d3a558367c5d50469dde5020cfcc80e209314e045ea37d24aeba8a3b5d65ed244b91d907272d3ad5558a7f7304d92e5b97d37e6d700dfecdfb1401cd811f24017c517f6fe43a5b6cbd7d97acff2f4a7dfb3067bb24d874ba9bf7f0ee288a59e7fb1a4eac05f04e37c7c464946b9e45ff717d90d3622645c68ea7737cfa44d09a280700837d992d6fd9ef4d75387dead104686f7e63c57c0d59bcec80716fe75b9416b5699fd9348c700e4e1af80b43630116e6193661f45a760c4e4c5ffcaf8b4ee29f7435b0ec4ba07cfb663aca8dfd62c00a52e4cd6d4f154ba6ba312d164ccab51beb6330ea79569e3a17151c1846927dae37bac393bcbf97595e8789425ffc230e6db6db208043acbab2e4a3a6cb376bea7f9c53ad4bede7ae4ea93dd5c08b7f07f0ce96245fd8adbf2679a728e2c94b32e37d55a7fef61f09008bcf91fbad67b13f479136c2b5cfa590dbb2c82a51ff59f22036445f19ac9026b6a92484ce34d4586c3ed1cd2bd3d215a6cba1d394384a4b327a4fbd5c3596131ff96de87fefaef45d045a67d3218ff1e7cfdb33ee545d376e72cd8701ae49e4322861db87ff12732366c18499b1c4ed5d18137b79c0f93418bdd62809a41afe5cb75f8717dbc1ca834a37e831bd86d165d6ac965da8b5c143bbadbe8425a3f480d2130805fb19007d4ffe57d5566f3d0509d242b244624ba6ada180befb685db02382532d1092899ad496669ebd09c72b8bffac39d10607c761828a3f8d4a17218a0d8e0604cc5822b8b9b1d82489b6f552460f0fd93e23068aba4db829d46948091cba5ef11fbe132628f88f9c8a0611f9029b6fc361f0c1dbc1584878534f42ab21c4a08f5f680fe44b1a46df3c377d544518a5dfee60bc0f1d3595994c2467ed223a3063007076305b7248aef60c2787f1dbfa8e0bab8feb02845e9313fc26ea37bef5a2708b3e382297afaa41bca5c728e01d6c6efbe024e282b049efec8e68bc94ba50"
	serializedSks, err := hex.DecodeString(decoded_sks_str)
	if err != nil {
		return nil, err
	}

	cCiphertext1 := C.CBytes(verifiedCiphertext1.ciphertext)
	viewCiphertext1 := C.BufferView{
		pointer: (*C.uchar)(cCiphertext1),
		length:  (C.ulong)(len(verifiedCiphertext1.ciphertext)),
	}

	cCiphertext2 := C.CBytes(verifiedCiphertext2.ciphertext)
	viewCiphertext2 := C.BufferView{
		pointer: (*C.uchar)(cCiphertext2),
		length:  (C.ulong)(len(verifiedCiphertext2.ciphertext)),
	}

	cServerKey := C.CBytes(serializedSks)
	viewServerKey := C.BufferView{
		pointer: (*C.uchar)(cServerKey),
		length:  (C.ulong)(len(serializedSks)),
	}

	result := &C.Buffer{}
	C.add_encrypted_integers(viewServerKey, viewCiphertext1, viewCiphertext2, result)

	ctBytes := C.GoBytes(unsafe.Pointer(result.pointer), C.int(result.length))
	verifiedCiphertext := &verifiedCiphertext{
		depth:      accessibleState.Interpreter().evm.depth,
		ciphertext: ctBytes,
	}

	ctHash := crypto.Keccak256Hash(verifiedCiphertext.ciphertext)
	accessibleState.Interpreter().verifiedCiphertexts[ctHash] = verifiedCiphertext

	C.free(cServerKey)
	C.free(cCiphertext1)
	C.free(cCiphertext2)

	return ctHash[:], nil
}

type verifyCiphertext struct{}

func (e *verifyCiphertext) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *verifyCiphertext) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	// TODO: Accept a proof from `input` too
	ctHash := crypto.Keccak256Hash(input)
	accessibleState.Interpreter().verifiedCiphertexts[ctHash] = &verifiedCiphertext{accessibleState.Interpreter().evm.depth, input}
	return ctHash.Bytes(), nil
}

type reencrypt struct{}

func (e *reencrypt) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *reencrypt) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	if len(input) != 32 {
		return nil, errors.New("invalid ciphertext handle")
	}
	_, ok := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input)]
	if ok {
		// TODO: Currently, we just sends 1s if the reencryption would have taken place.
		r := make([]byte, 32)
		for i := range r {
			r[i] = 1
		}
		return r, nil
	}
	return nil, errors.New("unverified ciphertext handle")
}

type delegateCiphertext struct{}

func (e *delegateCiphertext) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *delegateCiphertext) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	if len(input) != 32 {
		return nil, errors.New("invalid ciphertext handle")
	}
	ct, ok := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input)]
	if ok {
		ct.depth = minInt(ct.depth, accessibleState.Interpreter().evm.depth-1)
		return nil, nil
	}
	return nil, errors.New("unverified ciphertext handle")
}
