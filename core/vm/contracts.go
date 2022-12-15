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


void encrypt_integer(BufferView cks_buff_view, uint64_t val, Buffer* ct_buf)
{
	ShortintCiphertext *ct = NULL;
	ShortintClientKey *cks = NULL;

	int deser_ok = shortint_deserialize_client_key(cks_buff_view, &cks);
	assert(deser_ok == 0);

	int encrypt_ok = shortint_client_key_encrypt(cks, val, &ct);
	assert(encrypt_ok == 0);

	int ser_ok = shortint_serialize_ciphertext(ct, ct_buf);
	assert(ser_ok == 0);
}

uint64_t decrypt_integer(BufferView cks_buf_view, BufferView ct_buf_view)
{
	ShortintCiphertext *ct = NULL;
	ShortintClientKey *cks = NULL;
	uint64_t res = -1;

	int cks_deser_ok = shortint_deserialize_client_key(cks_buf_view, &cks);
	assert(cks_deser_ok == 0);

	int ct_deser_ok = shortint_deserialize_ciphertext(ct_buf_view, &ct);
	assert(ct_deser_ok == 0);

	int ct_decrypt = shortint_client_key_decrypt(cks, ct, &res);
	assert(ct_decrypt == 0);

	return res;
}

*/
import "C"

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strconv"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
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
	common.BytesToAddress([]byte{69}): &fheDecrypt{},
	common.BytesToAddress([]byte{70}): &fheEncrypt{},
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
	common.BytesToAddress([]byte{69}): &fheDecrypt{},
	common.BytesToAddress([]byte{70}): &fheEncrypt{},
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
	common.BytesToAddress([]byte{69}): &fheDecrypt{},
	common.BytesToAddress([]byte{70}): &fheEncrypt{},
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
	common.BytesToAddress([]byte{69}): &fheDecrypt{},
	common.BytesToAddress([]byte{70}): &fheEncrypt{},
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
	common.BytesToAddress([]byte{69}): &fheDecrypt{},
	common.BytesToAddress([]byte{70}): &fheEncrypt{},
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

	var decoded_sks_str = "24210000000000000000000020040000000000003e666d48f50cfd89e1f9a911142f85bb16ff3bd3a2484132f82cf430feda749a67be257d50bd19e38f9c7dd9bc841a24a9ffb5760c4eea6a0dbbc0a6abd665da7b6b66fb97ad8f22cb5be4a5826bf33dbb502abbfa74a35f4508a97b188509c0e8080796a70ad2f526add7b444241904eed2a2c20ec751677ffe086cb3ab4ba5b2461428ea3d656b615ba859607ed8ef3ea0fae85a62f389042ca7ce376f5165f44a46e1015dd9d559065a93a1ecd067619e25711bcb98a8e9210ad415a73118d2c0aaa8490dfdea80bbe1c6fc58ff6c178ca8e8b0717d3be4329971fa34b14e817932aa09fb5159ce408dcb4d5d648e4c5f851fcdbb317fbee73305d07dac16ccc819a3906de03f0e25e32737754002a069ef9fa713fec370e09279a64d51f1bc1eba4baa77ce975b8ecbc4cd02fb3655362f0d949b9063acba0525b39f1c76dd32a0de3574c25d4c30ea0ceda10344057775340cdc792503475fbd0c30cbd633b5a5db90a00517ca4f9f8eb9dace813776471d1f64887407c65a11f25144f90d3873836d968fbf13db322404f53c0b936e2ddbdc111f8e27b7b3a21e0534518f41884ec788c446e4bc4324e309c27c6d8ff571e04b6781fdb53af3edaa45562514d276dd67b260fa89fa8befca9b87ef1514610d7abd41f5e3fbf3175ea4184f9baf67b2cc84a658131568662ea90ad3bc243461a2708ddada98d02cf7201b4d3b3845b95a4dcce3e87a9c2f3735d67172225276bc89310898052650eb8876c8cd16ff495112ac3365d84a09978a6534b9598e11a9d7dbf2f1db3712d8ed59b06d4aa6684325d5ed567c1052e1cf82851a71be1062025f571c6eaf64bca21af4d0a8bd7b8ded1627905bd14834cae148e72246fad44b9865fe73ef0cb6e21a3fd6c8462b9620d2899c4ec84d3c8d1059bee4ddedc89c7551614c0c186fb65616183fa4c93dfcf13c9c2f57f72b91261beeacd71553acaa4cf669ac6ad38aa1507cfb01532ace5c5859da7cdffc30df280b5641101616185ad55081d61b1970eb540d2a7052fdca990c53802dca38e246a9da4f02244ae77e3076da404da1dac775af5c622431a748fd9e882402c3b564f9e784888f78c1e8a0e76d0c063e08d85d13fc2da6f9a96b3e1837dca749f934eee2f753e5f374bc39ecd0e416628d1015a661e7c1484c1a3e16e955df2d4b0497b6d8f2aa58cb2e5356f0de1b8410c8e6d3ca0df55ac0f6d838b545bed3c0f5fc2efdd819ab2e9ecaf9fb7fae0d7acf62caa758f70844430ed8e590ae7cce464975909325ed369115ff5255fdd5cc781f3d146245eb207f2e0a4d8806785954f25135bff742d0ad7b22886da466687b1499a7637aca4f98b57fa56471febc33b61db122c3c681fd2b49ecbd665bd4c997f1562157d04a69e49ffc4b9c55bc1b20209e6ccc216e8fd67521f4b678f2ae2369422ed24733e7084fcf7119c3bdac82c7fc517291344c3bfed30110b0468ff14d7fc83261213859f7b9ba5c17dc280c7cfb84d48a05202666e02b27baf91013d0a04a26b4dcbe5ff7af789af9ef85367bd70fa5dd218d54cacf4752709d0292e1e448144e6c7c77fb383d1753086a240f207abed31ed63e84d6c4eabca5b476016e606f8d6c244c8b57639b52b82af05635f64a1c9199cf7991fde574ad4b520ac404ac65a1fd8b357e6beb1e58894809c1fc32112326206f4bc5dc636a39d1fc4817b474869d564180197d821519674e5391b971dd6f7015375b5bcab897ff6c16a91bc5b1d84b5b5adceccea20ea5ee9d572dff268920f533ae2f6753037c1fe6aab356031c7c6ae6a27f3c3d9f3dcd3b059d0c2bdf27c6a6d64e9ae8f49e2c6b9412a5ad89588d71c9c94a341e968b55d6d70b126619ff1bb58237b6c469cdafca928a225433687c92921c7d5d2cfeacfdc9291bfa0f6d410f69746c84a19d177d115b2a1bb7fbe6bc385e02b089d55a1e2002f351eabc68f03511b8dc37c423a9755450d90e55adde33f415fa9d7d2200bfae23e35ca572c99a47285d8917a17b5a7a925c5f975c76c30b00569cdfc553c4c17f3d12b348c7cc4810f79e74914e26e79acf42650d8375743a10948652724fad6b99f3af868de17d8eba8e5f09aeb47655a4c42f28c257488c27be2cecbcebc422ff8ced67150ea76181feab7c118e8723253f09713834d566365a4cc72dd0dfbcf12662db2283c5641a50427c37d4c378d100dc38a371a83e41267ce4514cffe758e4390322018d3bae68262a158ebe6b07272a69199dba32afc43268a73e9085ff7eb067c1f79b4aa9d2acc1f44ffdbc8d8286d138bb94619295d2fc9d412e33529837b76408b963a06569d1801e062be0538a401536721ac4191c1fcc401a8dfcc5011ff30008e832efd7509ed51b7ab7539e08b1c21b867ff8418c4f3c369d37ac53be2d8e7dcc764d1c803e1b9df2d02624561e03bd406453d19d95f394dd7d83b6ce39dc1ece748ae80a362297be84329879ae63d8ad0b1d2ab1a83b48a02afb433724239773b0562507e71ef9587cfc6b8e8844fa11bd7de5642e346ee8d5d130e631864e6ffcbacdb21403ff780f630cecaf5c07bc5a3fcf6acee867f3d1274002220e28c890b4b6845357919cd82185373d07f8ac0b1fc10f519e881ff59ce2e79826ad3e8711d2b30f2c6b54eff785c54a7736c8712c172477da6e061dc50f4f92453d1dea3af758017aa0cdad356acbcf610418c47a2b0883886ee8b95ca0c879b7e6d5b5d6b678f5ab543ee65659eec46fbb3d6176577cc0ac7c60cd649b14b646adedfa0af8534c4b7d739d48df15c8c3096771ba4f5770b9f46b00d850631193e6b671e4a08a6f8d13e001206dcbab5b522288f26ffd82a828fbbf6e0f23d99cdfdb6086feeab76b5c2774cc06c8f35b0f1401671b3f1baa556bce675c8996a7e8405172f717b530d4688deebf7a798cd22a701a12990a989440e933352ba8fc66611cb0d80faed40a8209125c550e984ae88fb30f11fd7e4a0a024d535bf754220314079c914d3a70b3df33d96354cea0e7d866c2081d4de17a65f7a11f6fbfadad573f4cdb291f258f244fd3492539a1e576a5971d7d460232d9d2e98c5524f7e2e68d550444add5832657d32f84d1c35323af18adeb0280fb6920f624da223ef4725ca4384bc1a0d138a5af4a2a42a5bdc162e02cac2b30923047409f9632f8f95bf98b258a25143ea2a4a475a0059c6d62eccfe29e683842f42c21596f9f6c91d4f0ff76be4556412d4dfdf5b5b472b1d54bb126ac9ed81797efd310fe62f6e101d1c22589fe82225db04ea91f50fbb6b89a28b4ce872de9b1e79b63329cbf49ae60f829a0bae54338dbe53486e1830678bc9b76b0b7a87f4296fc30bd34ce9ffa7b73170a0d12812ebed1202ddec42d4c4abc0ac7e0ee1f8fcda739cee67198eccc7374beef431696e2f086ca06d79f5ab15e6dfeb91be636d9d135b2a956d2bc61e97a14b2e84e36719da4f9ed20d987710b7534e3df200b525d24b1144c5c378a79320005167414d8d7d5f3e6b506d45d9fbd4fd5c19dd9df415a24ece296b1bf9d6aa0764924e625986cb816b074290d12664b7edccdf29e44e39c1e87780c2d25fe869dde6f25280045a08966a425ec87cf786e628a9b846f1accdcc879ee0fd33f37d64f7ca14ba5d12b6b7a7c1a4a5f132d9335a121c34025c64c2403dcff82a147106beeed605d0d92752e770a07d6ef88370a0cb02b43c426d3332c8ab3197f5653818e390e4c08f625e99469e5a34eec0f8a241e483e753b1ddcbfb49453b90a42627051acba889a3c0b3fdfcd4c131f99422fb4cf39fe6493f54931ed7f2e28a2e914d1f3efbab38176fcfa8805a9fa6e640cdc5a89cf4b574c66d7936503d8bbf96977eece3e43cb8e1703ab83a2c101ff912d86f4853b6930c0b7bcefe175d271270569d12375e82bd6b3b4c2e7c6cb39314d740b0f8bde18646a1e04cd665fa5cf9020bad1dd9d519e122d7e171f8308a9cc858053d344bf292f25fa2281f436ad057b27d046212514f65d07ea83a78378759b5ca8d54c1fdd521ff82be9ffd2e2a541bec89d377ee2ddea2c741bd71a58c1fe9159ed69fde7e65dbed8e98308c4f8ddecf33b21c50ee84760aa95e0ceedc5a2e5001994b3f4ebb6f0954a1c224e344fe3f44f68eba05de66ac5091317e39f0854ca84fa1a9c0faa5a734dd968e33251584e1df3a5427d4099dd7378622612424281621d3d99512b2ec81ded7726b93c9317c91596b9da1294d3f86e73ae759cb8fdc332c31e3dc94c7961e2e8b0699eaf36daa44b39d87587fade3a2f90e22ce9eec11577187d07f16603dd7591c8ac9d9700aa69c1c6fb6a6f58d9e1b95293e55568ead48ef621ea3799f6c77bdab43b76b359ca276560533d3fdcbc6a61bb058666ea40626c368b125f4318fd37fdafc75eb0a2668573469d80ec13dacdcf40e503da16c4bac57bebe2684059651c55bd900f96deaafd53c30e35df3ed8ae7ae8f7554c73dee7424d437e991b74c805d7fd0b47ed56143c0319b5151f4deef7e70597b0ac03cfe8349ff6e887139d8ad317cb82fa1e82fb276bda64f9cf0d8268f6703531027fecbe67a61ef330386bbcaf6f3012d0dcc35a8f150d63a016b12b3aaaba48ad7ed9c23bac56f7277835849af69f8c36f9b3d239bff9943c229f725e965ff0ea7900ac69f12f2aae9400b88ffc558fc000bb0434a2c228760331b016a12b20a90a6516402f13f5aea2c850543a234d23e4ced0556eac57b0d8445c435d4ef49299b3f228444878f5ecfc73f682e016b5269ba0200fd8426bf2bf48e90edc0ffcb06372e198d30792c6c1a630f465334c910d911a3b0076e99bb5ef81ae3e72313fc34e65d8f4ddcc51bf898b40bebb09f9fc5eb906d5c18c630177f600f928e37a7d415ea8e4c5cdc5ed1162823b7338d411664d8a315916e87d7b6dd6ee8605e01e112483837a76fd435d2427dddef4848544bc04643af36b56d227294680e01064ed8c9302b7fd8d46187f64ff201ba716f7b98aa43c9b63858202f8d895b2b1557e409080efceb4e4f195af7331fb2b549b1974b60554a556a4cf5d5cb46b5baad7addc81542fa91466b9b240f165f74543751d1a1bfe96d558396b469bf7cf892462a1b6fefd15c7c9b641759e4f73c26c05198946564877513363f5e2846ae51e740d8a5e24323dc58f08d8ed4bf334997f79f364ebc5947da3ff5cb8c6c22a977fac3db7e45930aa8fcbc7f09212ede328f679b76320d599c94f0fc247adbadc3f6f8d4971c5a0e21b7c3da4c1a0fbcea4b4527819687ab04dc309c922d3adda0076f1dcfc0ecd120c72635c7905841b24361b20c71fa2027fd9c232809aa2cd03910ec1ca76e74f9a0138d435faaa5768ea57416a4cdf46cd7c39672f16101b70e179ab253e794443a6ceb34b358d9fdff1e61ee854877d056f40697fd54a006094560a111ce7fe90fbe8626f8a4e0404613fc16fb41e3b27923c2fe5f870eddd65cdb1258df36168e56e912aea9986c7722a3a9a0b007ca5fbf2aeb0d79e39e156c937277331da11a55ede15a11561778abc7b32acf2b89c3305d9917cea08d8567c5c01d5854774193e1c16e7dbf7f20a717a784efe98f26dfaf39eb5c8d2877f0ded43674e7938c915c9a41edf069e5660473c6ff9e0115653e9d1c9d03f5d1eb1315b21be7acf253bb44ec5bff1192c06d22d015a1fcbcd55d8bebaf1eb37c19e63920f656323678771f2a975ae761eacacf5352d9fc5803d9f3553f6058640aa96469faeb5c287ad9df0a67623a42d535d617544734fd6beeca161ab540981dc5397a4a87a4515369df11d7363bdca3200e61b55509993cefdd7b1ba2b095862e7c1a034f289d1130176110248beaf7f4472a4e8f8a0b9c629715ad8a52f5e5406cf49b2d0e78495e9622098a449145ad158ba145238793ed218ea39e3ca5ba8da5edd126c28a5f0e5210b3f93b9953eaeeefec3b47dac044a3cc27920b2fa3f733cdeb5492a6cd625ae39ca098ddf60202062a742f9e28cc3a4237b48cb90b0ddc1f55585321103f52cc2cb8923dde5803a072354a8a190c3ec804283c7fc0d700f443ca9f7debe5a7e16255d89260c47be4dc5b6d164cf80f2ac550071ba6bd6f09d98af0fca134cb015f6b36e42e63507ecec21788bacbe5b31e32cbd6e558f2fd119b99a1396f60cc7411865e5d11bb7de5aa864e223d94892e9e1117d49552d3a8c174d14a050c61ef6a0e6852d8213000c135cadf43fb630f39ef7622de4058a7cf4644d1bae97d6f811c79679abc6045943d2297556410ed6725f136b5762b5a0e9fbf3b4020a98e342139873e198805cb8a4f173eff1951773992dacb990ad1cd5880423133d5471b21c1cd893f098651b7aeaa6f59eef71f7b974463e47cb44e4b934655bdbd7504f084b8586d2a65c6feffea709c4fd3b01363110322ed97fc9ae4b210a093ff1a074fe7a7f9f3cda54578c2f0db431f72a5b0c9ae00d37e0db1e29c787d1d891c8bd14612bdb40942885567d515f9c9e7a052fa702be023d223f00f74be0e3efc3661392fa5bcc221326f180ae3fadf0feb572470d2cf98d61551b59f90c67d13903a88b6434056aa6eb604bc95c2c0c3a71c7d533a5d9817b809cd8ecaa84697526f283618222dd8afaf7b4372a0ed61c761290b7013c096a9f73d3728771d34bd1320f93335d17b825194a17531425bf6c396a4d407de78af24cf2a78b60032de427d9647b0014155cd291d100c22892cf6bec00eb5bd2247eb62bbbfd9b57e2e5b8ce029e7ffe044205830efbd65952e246e426ae552ed771d40bc5e5fc4eb8a806f1e4eaa73ee674f6122f7c2e89713ffe9a13d8f3f8d9115536743f4cf1c62d41cd85e602e62b03b9abe4393f44e2bd84e4efa2605d892ba2115cf20395c72ad58163db7f2e8d25fcd3c8844f39e080575174a4c3dfe2c75830e3b2bc5f2a7a639d42caa522c6cabbc1090d92be8d27b058d4d54ba47e5e9e3a93badd6225c472e0f18b0af76cce5f54540ad209523fd395cfb37221d3dd73ed0f85cdca88f997e090250eb33889c8da37a201aa2747b6e61804397798b8a9dd39fc65bedca0b6bbfdbab7e60492f5a02526ce0d1a61bf18104203247e0fd964b16cf1dfdc1bf39720140f2cc7527de501e4be87b25ee116f46c2e7bd0ccdf283eb59f17f97befe77b941164d9e5d1ce8afa2dbabc1386cc0b82261e4c858b575dd6c676839a0627505ddc19d9098109c70583dbf418f78d30b7f805729f6c71ce857bacc2eb64350db77318038788e8b3717aa56bf1c88245bd7a997f7fa92674850e6ab4373863ddcdc11fdb8c30d5f87221c6cfa15711532709ba5edb091c6eb36222515c30cbd74060d496be5f667166f8c09aa2e698b11fe99d5ea4f72dab9969ffc8e91bd4e43d2288415991be490d2c72fd2093b056f57556fd2d619453172bf4bb10149b48225f32ccf5180e1931ad6c479853cf881da41de7e0c4d62a0a7860cd318d5b94695543fde0d5f11f39b9c691bd71c06bd2d1a4b18e6df873813bbca2793f326560d6fd2123586273e319ddb2531fac4d51a1a87c7d0f548c3f1da30c0cfff8432fe4caa731596495ff150612f5d0c0cc9c4413b3494582aa902d14aec7e8daff167f085a15e9b4fe5a54629211396eaf679a53c1a660ce258fcb1a53578e5cc3b7c66f28a267f77a6d9ed05a4eb1200072f3a86187fceadb207fc97558764005ada5bb890ee14dec345b6d133fb4348b1b4725c408fe8ec49580cab5437ba6dbe130d2449a7d0d13deb9acb5c595c937d14f1d3040f45801eb8f101e4db9a896f39820c6e8c2ad90cdb9a892e7578b085136a403cb1be6c45a1157a5697b667f3ebb606dcb9f237aeb662364ad0dca01cbcecd19b34ab93adcb6f2f50869b6edd44e2bceb277d3a232b6d7ab40c69846e644bb12d540a6cd0b2ad4ba819e9238276c1cd24604b62cbc31757bc9feb34e211d9efee4c1d2a7956e9b54a9e0eda3cb5821345d17e8bf2bb929a20767b80c6c1b52e28ae8a287f49b7602edaad8558f89c19147a54a452d765a7c063bf1798578f648a6f7839d9fa39bfd8ab604ba6816e9c52a1470fb0f402fdd1131252130941b3fea009ae8c21ee578faec8771ed1e232232d5ac4c5de9dd34b40140f8214f0262ee1a137c7766deefbc629724883c9ba1d3bf067eb233d52da7845b6140a3e7c51e517141f92eb32908ad19328e8e07e3057f02dcca35cd544d39275246a583f1c9254ee10c7b029f58c00b0cad933bd17f915565cd893830537e9d016f1b572406a41fa43979551427fdea90b481f188e180c715f21454941aa082a995ca8aa960383107a0a63f72aa835aeb3be23a9fb14214e5965943e01aca4f0f4abc9d80ccbc44cbb80ac0ba208714760a15d2d26e92f30cdaf2f76b9dec352b8c88d81f550f243c7a4a11325feaf0fe515ee1b2f60ae2a14d3d08ee401764231b562717a97399d1e8267900bece23be60044dfde280338524c5201e396ad3e1a4fa80c7b595f7f74ee9e2dec5db3de37042873bb720fd6124ce61f98ccda886730f29053fc807ae0e0e4631575669c35bf3267ba9aea3aae07231ab183d21e0f75bb874a64bc9006ea43896f7a37ef205c15201d783caa2c403dafd59c4eefa929021a76456809b5026baa53cccd2cbbf5c8220e3e87f7d5943fa1488001fbb1fb5c5cf67330d7d422969456928de5941a10679666490cccf3268f8d45f379ea423d4d142e752481a8a4f83edb804e577a2ce948307edb43ac500b9a1fd7f3911ccb701c12c2b87de80ebb69240e4236903818ee79dc8827eed89b9fdf3724cbf07dcd6f8f38dd769d02e46b16e5fe2d50a1e408053f47fe393d8c7888398ef583fdab1c5710e68917698316c3d454a73b52bf94edaf3af391b54d7ab2301c98401ca071aaab2d1f0bb336c83aed41ed5c43f33403fad6682fcac300838ff0dc004cc066ebf1b800b092757dfb92a8b0617780a01d176a7547f95e9ab4681680b7332737e4cc2862f424c550e68e0b20240030016e90d3a3d42b6ab7093ece23465b76397598e34573ab775b1f3b5993cc6b0e62c48df9667012041d2ab9bc7d4b85c1bb0bbfc390676c83323f2dfc483d529a50c6bd8d35dfdbd5e26b6167b531848ad5b3a6ae7dd6f22dcee73ec526445563321705b1d03ecc91bb009987e9c713fe240b6e1e9f914215bfe37deaa9f7166836db111d1848ee6f7076bc76368a61479456183daffeedcdecfd1d2fca01cb6fb1f5b56fff8ba934f3070eeaec8aeae43407ce816405fed33289402e0ca9c1530455aa6a30aa98ba65da64130a3e1ccd0af15c137b4394361c655f6579f300d4e1123cf19dec1f755b175d728fcc53da4044abfaf6163237dc7ed51eae9af834f3a9ac4f78517d62269a75dc73cbba2ec9cc47d0dc490e3a2cbe6ab54731b33f865c2971943d1956f63dbb2b63fe2e1f8825f0e3936aa88bde536199ac2a7e821b10efe234b9c669ea6784200e51add896efffd483d44d2f20cdb0ade8f06aaac2d000921726daa19bff40049a558d1096d56efd8c152a009d2c29dd0405848c20cae5ce35516d0d5dbd84c54821a767be96bd11a44479bed2311231715086f241a8d701b54e7f175f1ab37de8820020ab8f26b18a9bf383ddc9797a3c983dc4236e6ef2be72c4a7d6f687b99dd1634031d99d1e5a4dc515eb02d444bf9ca5a68a2c2dc4f4e373cc1628d0c55bcec21cd1c5210294335333bff0a704ac3cd01bb99fa9f5b8dac95df02b875a7e45d41fd6b1e884af049a9802daaec835e932adad91420c552823988b49f03bc13def380ea757100829d491c2d52e9dd98a8e64229c16ef6ce582b2fb763ae59e31ced96913fc4940c5a8f500ed170dc38c7c3205eff25d5135f921943f1dd6da34d4cb62209d39a20110905b77e0b0ba184feb63bdad9854dc3aa382d1c886ded7316173336d6fe4da0e5e6fdb275ff882a5dde665e2162e6007d46b7c0f8bab37c0111e6cc2819779672ec42c02d491eee05cc12835dc55720bd48a0491a254256c5bb4a738665ecc2438087a68f1a8ec057a01e167ff7dded6b456b1247b820d102678db54007d573f5f286dbe3364914fbc85f80a205f2caea30457d04d21ab85332a686cb3c1c043e56a1c61070b1f8e6825918158cb0738205003326a6b50725322c327de73cd4bfa3eb3556a416700dc113df03c3aced077c2f6c537af71a8f2b56a724013a4b8a9147749e75d3ef35487a7f8e90dc1f56eab8f4868d6a54395978417252c1a9039d0688025d3217dd5451dad05c745307311d33f5b93a33ecdf69bad25ff91df3790138e3ed92031dfaa5b919e352a8387ac3228ff63034d56676d17efa16be232e1dd1c2b49f64cc1404474971a86bbae688550b9733322d43d1033f564bac0ddc083c31649c393793e3428d173f8966089ed6d0c017c913e4336552c48ae26ef6fbcc2426f01a326ce41edf7e96925a0630f431c3d86bd60a2dc8279ea48725e58211cff1c930b383fa91aba6872a92f44ca768880e1d73bb44ac2f40c9b46a8e0c860df3e6a40af5bb31f9b5b9f47476e9af4855dd005cd6288196f655a59b7069a34ac04c13777e2183bd4071d4eb0f6026c06782977ef636e22c72e39f12229916aced63bb35ce7bfea4ecbdf68f4a352e56d59dd749824d988f4b1f8cb43d90f4dc6ca2c0a266ff1ce0c2c0f73bb6d4089e00d6fd77d336ae9fa8a2c37fac782a8341861a54431ba05ee9c1e2b33ad2b594e69747843b78707eb9893445f239a7043f4d8102e9621e2e04cb66530bbdd9cf402357bec35f6534c5c65a0610eedc75f5e91075674f04e73b671c8cabe5eb122cedd1abd2cfde43a42da0cff1d8533abf64c4029426c54cede07869b14e07a6e33c13ca26f03970ae03a7b040d0f0eae5cfec3a0395f6ea04f7c5c616e37e3c63e8d106d7f45f1bff4c6f4f3308b5bcaff31df0991e79e8c2d9ad3fb2f736240a140c1a70053eeabcdb730bf35fe6cb2059f576c19c5dae6bf0a51d79cb6badfe75f43c984ed3813aeb2ae1f7149c28dbfb38db255666608ff7ab88bace458d0d30842c876d91240e3dae85f90ddd11fbd85c02202d6451550451cb2696617773ae66dcb6631288beb54d54df8f9b752bd1567e89becf45977ac4c57e6f524d71cfee17aa28fdddd5771d8c83578d5169ec2f5b71880bd33323d5f32aed158da070c065fa1e7c72251f6788a907c6c434f59b7e7438baf61936caaa6046203a0bfe8cf7e00f1daddadcde49042a218646520e0d14f984380dd2419ecabea2524e3b2538fb01235dfec48d9029b9a57e5c7e259c6d3eea67ab8fc79721649dce012859b9039b726a5b92ed6cc7c13e62a3119fd9cd8559a0ee7e417241dcdefeaf4967e63c0788c7614125f2c822082a49efb117d8f6c72fdf8ed8412747eb570287857b0487f19949b811946c8da603a4f9d556b5c1fa9acab5d2019122ce3ffee8547a5683b058117bc441cd67098f4177410f76081bee6a4073fab81ffa562837c3fe9c7d58f344b7a3d01a1c152edde50f1d863124afdc82d9382ed49a33f69824fee159834d0994ffa99897b4ed405fd823f061717ac175fe3b8df2b117493bff0b4acfa4aea3ad5b4b2a58d207536b855e68209e56ccecbcf705669a4577da80c1a14bbad738c38ecc2b376934a524cc34d8502bd5db762ec775253403f095989cc3f69017d75b10a15f28068c5691948f126331d79463a58d95cbc7ee00b3abcd92d81f5d09b62a5b7ff49f71e4f242ebc9b2c056c66f211270d8305731453bdd3582f4de550ba46a66f5c026d93ac974d5c24ebae585483e8dd1faaae1fd93307ea5bbf0b75a34c83ac2b4143b671b7ba3f4809823060000000000000003000000000000000b000000000000007c29000000000000000000002a0000000000000020000000000000002800000000000000100000000000000088e8b28c325df8bf5ee8a8cf07f4f6bfbb801051f23ae1bfacbe27ef2b0cd7bf5838fd88751ac9bfbeaf60c7466f0540874960230b61f03f9e9df008ed5d04c0eea1939d7749ddbf9801e9b9d3d7dabfb6dbbefa2981e73f040f00314ab6e3bf2fe954f9c5b7ebbf127ae5bf4931fbbf1a39c6bb2b0ae43fd436c8004470debfe08c7cd36f39933fa5154ebd71db06c0dd110f0b4225e2bfe81467e6443c0040773eb334eac2fbbf98a7a9198417cbbf2552fe27d8c8d2bf19a9cf9f5f24ea3f610e6fc6fc2eecbfad3f855ae5ed0a40c7feb1e1a6b4ffbfa6d43b476216f43f068b086e9729f2bf6055c07538f1d8bf25032db8b34bf93f6acf3015a02f01c0100000000000000009ff9056bdc9024058d39f2cdc36e83f1f5d6beb037dd4bffc71aaf86bb3af3fca6484b6ecd4e5bff0ba4e52b36dfd3fcaf22abe3292f73f7b226f5dbb19f5bf0f6bfc62e35cf73fb2bf5a189ab20140a7454d4faa26e5bf0c04fc20e2d3e1bf83070342b861fdbfe4f86346c7a6eb3f946163838d29ffbf2109ff7b2240f3bf201ceadde648f43f10d9366a01fde23f8e1d53d891f1c43f87a098c0f676cdbf04948b1f5462d43f702a8ce8daafa2bf722ae712aaf2f43fdf4e108d86f5fa3fecce3a42cf5ad83f4c3663d27bb9fdbf4b7b44677cc6e1bf422e3a08da6ef7bfd84bffc51228c63fe60b77129ea0f23ffcc7e715318ec0bfbdcb7556cebbf63f1000000000000000350946df5b36e7bfb09c29bd349fe8bfd01b2e7fc4d5f7bf35b850e4c056e93f23ef3cb981b9d53f523bb57c36dedf3f445cae2228ecdc3f5a46f265d61cabbf06918071ce36e4bf229b2a9c86a9f23fa0022eea2e03bdbfc421a0db7832c23ff60b5bf4c05ae7bf80bf3e7f28400240a2f3241f98e4f1bfc629bc4f6f8cdb3f50ee3bea44cf04c0840d0fef51eed6bf32545d3aff4cf0bf80c0a54fd40f7cbfb796a9c732a8d5bf00ecc67d08cdd63f909087305f52d83fcda6cbfef9f4bc3f658bdbcff99ff63f7e37be1722e9f93f50cb00dad7bf00c0a058867629da81bfb592b9eaf64df63f7ae65915e979e5bfb106dbc248da0240433b1915a6bfee3f10000000000000004a49c432648be13f3468bf11f83ee23fb5125f9cb766f0bff5ba011b38a504c01cbf0b436746f83f1dd584f11e9bf43f2006350e76a8b03fc8bd3ae485bbc0bf3ad28b5ef47402400fcab52edee6e8bfc82da01c71b3c9bf58136811e5f1f3bf319b9bd86dcef3bf14fc7431e3a9c7bf9a73d06f430ed83fde5ffff0077300c08a686a354458ea3fa879120ecc28e8bf00b62913b23e883f00e9d7eb2ef2b33f0c2560fd951ae73fd709430f6426d3bf202a7ab6c81bf13fc91210c446dff7bfaaaa34e091a6f73f0a245b42d9e2f6bff43fa23be5d9f63f105789b9d010fd3f35e8ed3e6705f0bf5e74b5a87483fa3f244a4067646adbbf181faec94bc7fc3f10000000000000000065b653a712fc3f0e3c1ef9a5cce3bfc79d0f4c15a0f43f97290959f017e7bfd64c707d6752ecbfee662869e1b2eabf185acb40b21bc73f3652d10d8c7cf3bfb4e0797ffab4d63f7f43a4a528ace63ff8a0fa46f717c1bf79e7b09c5691e43ff8136fecd455ef3fbf0b0b2be184d6bf29bc21bcccf9fd3f9066d422a783f73f80c2a5b2b54bf5bf91f15400b463f13f18730b1624e8d9bf7e72337d689ad0bf94d6d006c046bb3f2865099fc2e7b93fd6f65a2e01bbf0bf001c22599cf970bfc2e8de42018dea3fefad1814b18e014072744dfd1c0ac0bff16d0d0e6eb601c0babfd640ea74f0bf325b83b5f81fef3f5e7e206d3b78eb3feda5427384d60040100000000000000079e89cc31cc0d2bf582759e787c9e03f3cde316d6f7bda3ff0597e90b214d43ff3e2c98892c8e63fe877b2687dccc7bf5cef561195f2f6bf6f36660fdd56f4bf2c0f8bd6209fd53f8c23c539eee6e43ff17711c51328f23fd3906dc0bd05d63f0b8f65d0c92f04c058f0ae68c890f03f8dece8c1926de13f342eaab7318af2bfda6178468c6ce43fa084fe17a14bed3f8a32143749f4ee3fe986c53bc601f3bffbf655988b5befbfeaaa8dc7b7c808c0fa79422293b4f33f744711d90e94debf45186543a90cfb3f88929f6ecba8f5bf860f3aacb6c4c83f1c223e6d184ab6bf9367608eeda007c08a3fd905fc75f0bf2db2434d8bb20140f87700633ebbe63f10000000000000007512be15c461fb3f54794b0fabfed73f76c7036ccdb1e43fe74ceeaa56aef1bf1e6ecf66014df53fd2ae9ff8f3bdf63f4f73ca2d3543d3bfb8363d06ebc6c0bf421f48fbb402f03fb63bf36d7af2fcbfa8c544908007e6bf36e2fff02f5fe0bf58bd3d0ab046ea3f3ef1eeb1c0daf4bf6cbe97867622b3bfa33a37d54f55ee3f6c83225b8a3dda3f07cee430d504f63fd0684307bc53f2bf16d880843a8ee63f10054964eb82ec3f6071d2539c46b4bf8d4f398d0331d7bfea33a4a0cb13024004c6e412509cc1bfe8b4d3089043e73f9dbbb1ead646f43f8d6e35b1b93cf3bfe0686398520de4bf606048be2aeabdbf94b55285102be53f68c8fd96d667b23f100000000000000088c94a669b0bbd3f1c1bfdb503b1f1bf36456a67213adc3f1571572e5974e33fcc4cb4b2f649f13f90c0246ab678a6bf7f0c4fdcaf6ce6bfea09020f773901c098871d62677ee83f5405fc154e4ff6bf061b7fd1964b01c0b8a943daf4f2e3bfe4640a5bf7e3f63f58fc71c1e66ec03fae8f2dbe3e1aea3f6a403778ed9c04c0e417abf9266cf93f046c7c1bb93fe2bfc7f4e0ec432de33f88b5e1d43c38f43f8933b2c7264ceebf5678303d5fa5febf4cac9f1452e7fcbfa2ca4d2244b3d03f5e39142f25f4c5bfbb165fdc6b0ee33f20c2d2e333b3f2bfea2508732ef4e93fcc141f0e3409f23fef532a8072acf93f1a004d1da4e2c13f54a11348ba34ddbf1000000000000000a288b23930a404c09d77ac6e6c44fbbfd469feeb4a77f93fc74e040f16bae03fe8e0f684564df93f1ef8a1a7affefe3fc4e7c1620986f9bf06601f5bb250f9bf2c3217de54ece23fc66960aaf28ee1bfcc83dc0efb4ee63ff7f0533294adedbff07c4e79527ec23fdb162627a003f3bfb0d1facab3ab903f42623ffc8e43c5bfa46b3760f74ef93f04f83940a623d9bf54b5f5dd721d0440dc5f6b641718f3bfdc698464e7d6e73f3ede0b590542f4bf14345040525bfd3f689af79c34bff7bf09c26d0083e7db3f2e82bd402ab6eebf1e0c302e93eae23f3a917526ffc60340000fde451a0fd7bff16beb3428e1eebfdaa73498a641d7bfa9b99b5e30f4d93f1000000000000000f46899f792e2e63f62e6b4d41136e63f65faadcddff2e63f614e112c6c46dfbf28088a93ce46b4bfee955c94e99ef03fd4f49500bb23d6bf634eef333329f2bfd2a17808622bf4bf17fd449981ebfcbf68ef3452eeccf3bf87d19e617b52ea3fee006d007d5bde3f26a7861dee0ffd3f026c688c5c5ed13f36c78ddae630ec3f480cfeb5adf2d43f487e90472274a0bf8e9b2633e936d73f76cf73fb69a7e1bf1051e2b6e458ac3f8304277e84bc02408799efebd3bbf2bfd775ab4cd7d8f0bfe1612c9d08d2d2bff5ce2d941d9ff0bf42649a0832f7d6bfaed17c9ac50605c0dce221842a54c6bf119b49b3c12fe1bfce6968b68519d43fcca8ac4697d701c010000000000000005f4e48afca4aeb3fd0742ec60813bb3ff462236fddb2f43f16a18f377fc5c8bf0c5d40143490b63f788a90db59b1c53f1186fe8f8840e9bf2b63a24b6d41e33f905d0d0b56c2d9bfaa9952add541f1bf7889d78cf343e1bf7d5643a2f745e93fedd7dc65cd16e43f385b3b6b4ce3c23f4864ee7de850d03f97a86adbbb04f43f7aff1abdb81b054006a22868392a07403648fb9a8477f6bf40a2d48b63f7c5bfb695c6c3a00ae93f58a72fffedfbd8bfec6d701b99eccabf4fb501beb4f4ebbf880d4d06919cc33fd945bacaca62e73fd0dc179e75b3e9bf5830956241ceb23fa632827aa130f43fb43e588e6608fbbf40f960541899df3f2a1fbe3c14a6e53f10000000000000008672a7eab7a9fb3f3e91c5f2ed73eb3f3bc34160a4abca3fc4a6c6d225a4e6bff84edfa7d01ebabf829289ac03ebf5bfdd07de8528e9fa3f2853a8a1ed1bf1bf9c21bd0c7331e5bfa3afe755873408c02c51f5550256fa3f3830efe1d0e5cd3f33ace5df16c4f4bf3a9d375d4f3d08403069b1834b9bd3bf6e3ad4db55d7eb3fb2d513a246c5d53f064eda027241c03fc55618fd1da8c13fc08b98f017fc913ff61706e04d2ef1bfe0eda24ad3679abf152b439e0aeaf0bf704803fddc35c8bf9c35e203330df53f62dfeaaa4da6f9bf9e1b0d9289b5f63f1283c752cc1df73fdbb3be31f2b9f33f376bd99e768cf7bfe4b1f7765ce1ec3ffcb5f46ac652e2bf10000000000000008db060c513e801c0e0caae63a58f95bff59e66664127f9bf2425c0e5f385d6bf04f67e527191dd3fa6bb964a7539e33f716e29e93bfff43f606eb86e42ed8e3f1032ff1df653f5bf2c388ffc9719b33f8bbf271476b7044004d64434469bf33f2813ed74d5bae7bfb792a4e19aa604c0f90a562b43d9df3fbfdd07781e14e13f54015d54102de5bfc6cdbbb4d8c3f53f1f6fd035fc8df03f78dba303a22fdfbf5b1f0a6d495cfc3fad072ad5d79fd13fda99870d1ca8e1bf7af5e780d8e5cc3ff95cbc41de9de53f2c4a24a91fa3bdbf30293445aa1acebf303aff299fc4ac3f5403cf3aab75df3f02f21caf9683ff3f9a9493545bf6cf3f4885de1dc42bfa3f10000000000000005cc04d7e6d0ff3bfcbedda00c0b7d1bf20b7e7f6c6ebf23faca5a7ac4922e93fef30aa9ac9f3db3ff642050eed3201c076553453acf3e0bf786bad22ce04de3fcb68ee56c201e5bfd86c7c6a34edf73f91e3d18c67080640a0a6a1f9c02ceb3fc1286ac3114ddd3f719c7180a62af53ff6f4c5d770be00400358c9103b51fbbfbf9cb06706b2ee3fe1b2fad8d910d73f6e11c11a0412f7bf4e78801be30de63fda535a410013e3bf52ba0cc898e4ec3fd8c7404894efdd3f082dd5d98e7ac9bff2f7388c6e73fdbf80600f04967bca3fd09fd5949018ce3f42e67c009ab007c0647c13d361baf43f27d933eb391bf3bf0361fb0e78c7f53fa4574fde7013d5bf10000000000000002ab25fbd436103408ed60deb6467ed3ff65de4843c74da3f9c791095474cf4bf90d5c5557f79d2bf3edddda1d649e23fd4820bf682df06404974d1b8a91ef83fde9438259da6e5bf36cc2682e878f13f3bd0addb8176f53f98142b0e8333d63f223c1d071e2999bf2332998d5af6dd3f3c0aa70ae71bbe3fa6caa99e3b87f03f7d4e24307c1df13f31c9fed97d0ff03fccc4e76756a0fb3f74bb5780e1a5df3fd1f586731038c6bf9466680d7a1ce3bfea1a6a943463e33f18883938bb7b04c038d1aabe830bc3bfaedda004b460f23ff47b1111728801c02676c9477bc6eabf6fcfd5b4b21ca7bfeae6c64c7953ebbfa8452c149f3ee43ff573dbeedb4cee3f1000000000000000aad650b21e55fc3f05b01b0980d9e3bf4a62463b9986f43f59729ee3f9bfe9bfe4b7b24468f1024013890f75e4f9e13f952edcdca691f0bf8a031a50b4f7f33f80bee1ac59a9dd3fd048b362084704c0c8d800c983f4bcbf9cc0ac935603dabf80337576ea8cf4bf2969df3c7a02e33f4dc2c4c6c64aefbf28870339c80feebf40991f239cdeb13f643ed38ea2c4d5bf2edcf80e7188f63f3a162a816fbad4bfd9a22a6fa57df93f7ef5401972c4d4bf2d45b40433b7ee3f1288a7772ef1d5bfd870095887fdddbf10574022b0a3c13fac63cea5b6ffc5bfbe7e036f943ae53f7086bf114e9da4bf21b1b0d5a9aaedbf7b711a29f874f03f20445025be92e8bf100000000000000060d6bb2cab1ef93f51cd09a12cbeeebf16b7430225e3d3bfe6be30f085aad63f21513491dad2fe3f9acacf639207b5bfb202ada3f4cde1bf889fd887e74ef13fa00571527a70f03fc9d26ca5557de0bfe86a0a03442cebbf12420fe65efdee3f9e252484fe5fed3f272275130319d1bf9e072c649319e93f9056ed869880efbf38eb383ac507e0bfeba671d2104ee63fbc335782f38ff53f4423241f6291c03f1f85de8d121ef43f44b8c6dceb32d6bfa2ceaa76b944f4bfa6557fd76395c9bfc685a2793a1ff1bff1b269d14ec6e1bf743240b27ce1bdbf15096d285d35f43f6007c6e94e35ecbf899c2c8798c8d83fb4c9efb4d42c07c05eb123d7c8def4bf1000000000000000543f70f5417cf23f48ff6eb041a1d6bf04b6672ece47d4bfd073a715088df4bf589c4c77f05ef5bf86443fc4dfcde6bf14528370addebcbf65f335a18c1ffe3f5aac30ab78d7e0bf3c0261b3b04cd53f48b2a5a6e0d4c03ffd1cebb3368bf7bfacdd0309d05eebbf06765d1db2e8e43f88939ca488fce23f22fe707a036ebe3f4dbd30bffc8ce53fcdf55f70f97b06c0d0a041defaa808402ea051cba37bf33fa81092b1404fbd3f381b141ae3e6e6bf2299c299b8b8ef3fc91c8796d7a5ffbfcf42f1589690d9bffade67450bfff0bf004f14253503ee3fb36a3d3e8865f8bf400f8d6eb6bfbd3f30008a2dc854d3bff4e48525edf0f13f642a6605b0bddd3f10000000000000004af0d9f615e2d5bfcca16b6c5b95fbbf164f599a06dbe6bfdb3ddb27bd91ed3fbd40b9c81704d33f06ae71a11beefa3f3886a9420f1c03c09cb35a38f300bbbf522d8a716a4de3bfb897795ab255e1bf6e69557e89a0ee3f30dc13a79b1aa2bfa461442eb3d0e1bf94df9d2e8a24ee3f779c1240037fd83fbc6268ae9ee600405769695315dfe83fc0d47ea04e2cecbfc4522224df08e13f2eec9bda6a7cdb3f92b4b29cd7d6cd3ff8dbd742e10ac2bfee0b76443a01f13fd8f75f6ded90ecbf27bcb230d3aad03f9609cba59b67d3bfb696cca01ff6e23f8ff7b9310d5dedbf2081990d8d33f73f2865ce90bf48a13fb491b0409960ee3f86053640e3f1efbf10000000000000001f691beea760fcbf8e5cee5a639dcebfdc73b051de72fd3f34656f1cec28e83f253eca16b60000407502e20e6168f93fd8fd0d93920aee3fee7b2f77fdf6eb3f4efe393c27cdfbbf9052f94ecbe5e4bf921494542dd6e7bf8ebdf53836cef43f78c37c31659703c0a8e766942df9cf3f600435b1024da3bf715498b6bb5df0bf6bdf7f712587f2bf7a4185b9db41ef3f3881b85e108dd3bfa0895ba75f82cb3f42932bc29d11f1bfc2471ac45319edbf2c2f4ac6bc41f5bfe5be52d6e02ef83fdafa0e88360af53f78cb70e455cbb43fa10eb788f36cf5bf746d1c935880c83f9cf94650b28fd6bfc72a42bb897df43fcd2e848542b2f53f4a233492cb0ee2bf10000000000000008b163b638572d13ff8ad7dc21ac001c09352369e8a03e03f6b65f75456ccc63f6e210d5d6d00d33fb01c4a27d150f53fb82a529674b0dabfde7791281c8cf3bf0032ba1629bfbb3f3c799a8cdf13f73f545c3987a38fe5bf6888df26b6cda1bfd4f7f73d00c9de3fa9ae67db6114f83f286e50155c3ed3bf41984345af6efcbf28dd1f6b09b8eb3f075239c77f2cf73fcccbb7b84d82c03f7efb9f78e032bf3fe6ffe1fc0fcef3bf18a593745f17f0bfb0b4a5ad1f8e8dbfde2275d42444fd3ff7fded1518b4f03fa62db7f22fecf1bf0c7f92d9898fe33f1fd5c22b15fb9dbf0aab9ac80d2e084023e8f4e8778cf03f563b5b67a497e83f3b643c83a2b7f0bf1000000000000000ae44978ed79cfa3fb2df8bb69b18e2bfd53c0b68c98900c04b9265b2e52ef2bff992a1125017fb3fc7fd47d28553edbfbefdb92b1923ebbf27e2719786870140a143b4269876d83fc0a464f73566a63f236267e59b2ae1bf4a23f35313c5f6bf717d8c9336e8f63f65f4ee32eb0effbfecac10428dbbe93fe27a6285a4b6e4bf94b4ac9a1d49e9bfc13e8aca9e63cd3f7943d5a9ba5603c01d09c9ce1459f1bfa097ca767d59a03fd9534cd106350140418728853b08f2bf3a7d47c1e3efd73f58df8d10eb5da4bf55fe4a06e63ff03fdd1b8173a2dde1bf68ed28e7c359c53fc62ead6f2ac80bc08bd22173995ef2bf9ae5d806ffc6f5bf3adaa2c7791ce03f10000000000000007f15eb0fba5201404524bde3534b0040b62faf505d92e4bf5e28886edc76f73fcc8719dc964ce83fb0f75d3e7421b2bf1efc2bc06023c43f882acca009b3c5bf9040bc16525fd9bfb0420e8dd87ff4bf000a16a258db80bf42141650c49cf2bfe650e2ad699a0140ec7e2bb636cce33f8240137dac6dfcbfee49ac2883baedbfb1e94a73e48a04c080d7653e6a00ec3f64596ed63356f0bf44495e9f294af9bfe0db98ea1fcdc13fd14aec1c8593e3bff606d1e2e69ea7bfa9afcb1bbd62eabf54125002627ff2bf3ab81f1193c9d73f29e3d7f0c156f63f1607284c7cc8f5bf2a40fd916400d73f84f64d75ef57ee3f3ff8532ddc25e13f4e6226967d7ec6bf10000000000000005048bc586acdc33f247eff0e4aaeedbf17d3e0b92947fc3ffe93781c93d8f83f4b6ba43d4129f13f2a0d73d0dd5ad7bf6a6f1a84b2a9f43ffaab334d1614f0bfa03e11f17d0fb03fc0c82e94be4cb3bfb81b9ace1005c43f54eb5d3a7c5be9bfb100e1e1ef4cf63f1f60e41dc992c9bf744fd1c3ba77c43fa88d7123e087f1bf7cc50788add4ebbf0397515ce79ad73f6867075669040940f80a0eaefdabde3f68703cf0b6e5d3bfe110a7978614ef3f9bc1d28398f401c00a21f3ea0fe7f0bf35ae50f5678000c05e79378a6df8f5bf10d7c873838af13f082bc742a532a1bf93fd289d75d7ffbfee727789ed7fd83fa3759084e8ba00408c3a0182d1f4f23f1000000000000000ca823e47a94ee03f4c96c6ae63ea0140ec51f748db07c5bf4570281f623cde3f00c543c3f69ef13faa25cd66bc83f0bfda6d77f4d5a7e2bf50766533a8a4943f06334ef63adee7bf43312bca449eeebf8305b585068ce3bf37b9f0bf2726f9bff2dce4078df0ffbf86295b3c5c29f13f14189353105501402ec526e2cdcde1bf132d1a75728ff53f50b54a8b0969b7bf02675383f6a7d73fb7030f464969d7bfb9e0a0154e5adf3f4cb43a2eb5acf23ff20fbfb9e290e4bf46b67deef6eee4bf2f996b225112fc3f4277d89da8b9de3fb24e8c1d8718f7bf95873a042a86fa3fb0f6c2980189df3ff8eb0f8cb87db2bf6a1731ef6a60f13f0faa8dd4e81cd03f1000000000000000f6b52cf7f88acf3fa2528312b86dfbbf3808b0e62519d6bf1c198a2265a2e8bfcefd22b6b0e0ed3f1c6ca25abaf9ecbf3dbc6087d3c3e4bf8b57bbcd3930ecbfee9aa94a6937fb3f3629b0ed61e3f23f50580e9d09f1cfbf269c765a094bc73f20d4b09ceb86da3ff4177e5ac615f5bfad3fe8fa044af33fcc007d9b289dcfbf15eec6fa001bf3bf409971a130edf13f1c8f19ad939ad53fda34dab059130740c440c7dfd578e9bf74f545cd8227e0bf999c212c981de8bf8ffcf31f4323e83f800491e877b7c03ff6d372b9cf62d23f756749c4a004e23f1ee814804e0df23f10de83da0051014020a6e4fdde81c0bfc2e24b138cdaeb3f568100c908a5f1bf1000000000000000c0e45119f5d9ae3f00e70cbbf795dd3f5ec270d2e167b7bf4acad58e1d6700c01469ea689fc5febf95b207777aebf0bf94b2e11a6924f0bfe8e097b02e28d9bf441b7cfbe070f6bf8de69fcbf3e2f9bf8e6b644ed526c23f9c7b63478591d83f286f6069fe6ef03fc0861255b5b806c0f0193f9667ff943f6c1499cf0f55d8bf94de570936a0f6bfe4f8297966b9fabf61232d4f8aebcabf7a85d8963802e3bf9cef7758930bf1bf8394de978cc0f0bfd94d37c2a5c6e8bf36d66999fe38fd3fb0d123dd678e03400e37d0196a2fefbf0c0c92f7ca3be3bf1ffae8a92b7ff63fa8c01bf950a0c9bff89beb0a33dfc93f74997b880809b73f6e36aa2a9191de3f1000000000000000c2b9cb7c2535074043c74d08a40eeb3ff001575c7d70f63f6335583a451ee1bfddac31fa5481f33fb3e42597f3e3f23f167bee5abbe0d73ff4f067aebec2e1bfd49c12f88a0dc9bfd07a4d4aae8ee33f97f85f0d3faff03f3b8acd9c66e9f0bfacd9fd02b4b6f53f3d0f0b707f30e5bf22d134cb99cee73f4f7146107666db3fa2ab7d439101e73fc10e6057f244e5bfa6244e931f72fcbf0d2b355d6852c3bf6f8fe22cacb1dbbf7cadecc7d596dc3f528f68635411d1bf45756db121e402409026c9121df2f13f69e05412689cf0bf82036f44413de4bfa51c7aef127ef0bfa830570432b9c7bf2c79fb648c76c7bfe8c816410eafe13ff16a80e406bcd9bf1000000000000000e6a0198923f7e63f6f02a3388ad0f8bf60cf32b3a48fe3bf04ff960e3f02fbbf8c0d6e7a72e7d33f6686abbabc170440b0d252250d14983f808b84269e32fe3ffba2deb25aa1fb3f0d82b73f4bfdc33f849204c0055df93f765a94ea9718d13f3415d3d0b7bed73f424961f1d27ada3f717a87461db9e43f7b3689d9f876e4bf97468a06fca4f63f70eca29f31d4bf3f2550e7195c6ff03f4cbf42d4b3bdf9bffc9ccfd7cc6ae2bf4c7021652b75d8bfc148d6a2b5dedb3fe976b00719e7e63f8f0236fcbae7f6bf54d2ae926adea1bfe867147e233c03c0b55e8d4888a2e13fd4cd88095a5ef63f2079d4694b7fd13f9145829ccc9301c03e95d104a5ddf2bf100000000000000079f165446e00ee3ffcf32a123b45e43f7dca82ea3a52b43f106a9df9fed2d7bf02bb473e9b2ee63f0feef8569b5fdc3f5249ece84e2ce1bf5a8d781f4abbb5bf90e5ad83753e02c0f43219b6d808e3bfeaa29fae501ce9bfba1d4a3e2ec6e1bf988aa8852f450540d89a11083e5bd53fda2a3555a232f63f5e90cb7337cab6bf2fae9f4665a8efbf4ed6bb3e4647c8bf04ee479acb1c943f735d64bd2eb303c0feccdd4e9411f1bf7e84765c119ec0bfc6379806b1dfef3f66619aafd039c0bf7065827871d8dbbf99670fff6b5b08c05400829bbff5dd3f0e8761df0ccaed3fd513f8b44d89f63f9208f074a2e5ff3f519b037cf525ee3f772dd3c5d79ea1bf1000000000000000c5f4bdc09a3ae73f26b53de7ed87fdbf807a221c9713b0bffe30e112fd97c63f0bdc04a13c89da3faeaee0276abcf9bfa770233b1efcfbbf764603fcdad6b6bf9209ee322e52d7bf512f52cfee89e23f07616073342ffd3f378a1d9300c4f6bf6821a3694715ca3f8ea29e71f488fb3f6eda06f47049e9bfef11123d4c73ffbf8517011d84080540f6f1f8fed28af33fc5aecbf47463084092b31f8ec4b0ebbf345599fcd88bb33ff8dca4a7a2f1b2bf5666fb1bc065efbfdd9a195daef1c9bf7220bd31c011d63f6e2f145104dcd43fd85e9c2ea6d0c83fc2e09148015be4bf7e3b0dc2ce13ecbf32d7673ecaedfa3f287186aba9baadbf7d628bc440cef3bf10000000000000001834ac6263b002402a45b7cefa89f13f2024a952ee69eb3f32ff29db0deffabf2b8f31215fdbde3fa62ba7ad8c1dffbf6c19f576ef51e93fb3614d40a2a8ec3ffd4790619a00db3f92f7032e7912f03f3c65e86b62d3cd3f68d78bfba390b83f7aa40f39bd57ba3f054ca5302630f0bf8a308624f0f3d4bf32e7499ceb1adebf787615c80586fc3f84cd835a0de5ee3ff378755b978501402c7b22098593c1bf05060008a625d03fb000d079ce21ef3f97f5f1c702f9f2bf725651633cded73f238cbe606caef53fc8cb82fbd359cabf22f5d50aa1f6f3bf3eca02c3f262fe3f16d24ca1d9e3933f2791491f0d2ffc3f5cb26c518fbdf1bf007a0e56ba49bfbf1000000000000000f6971f18781de73f14ee260b8419dbbf78c109d23f1bae3f8a1e0a91b101f83f30cb06d72e98d1bf34f827517d80e53fdf22e0af1933f23f9a5c3dfa291a04c018e47d186ad704c03b519b20267bf4bfae55bcdc1850e3bf367ac2a127d8f9bfe6b5c926d395d43f28851de0916ce33f604526056956ca3f20b42817d599014038ce86f0f58a0040e6abe1cf7ddceabf64ce53cd5590e43fd8cdb8590694bcbf04f1a073a1e9e0bf00b772e678d3d1bfe241bf3533cde43f754ae2895843e1bfff60b3b0eff9fc3f0b9ae9db0b76f2bfb31313929e66f2bfe6f49f389cd3d73f7aa22ff09ce9d13f201a2167603aca3f986e59e6958cf3bf8865c0100abbd53f100000000000000096d826392671dcbfdea01754b77cdbbf430358ad18cc0840f093c3835d51f53f61a94854c683dc3f8a5cd821082cf3bf8627c82a2c20d23ff6fb62f23e62f93f2c024902e705febf66f04cd8997af33f335c3a84e04af4bfec7ee560b01cca3fd52c1b3f8a41b4bfd2b2dbc5b5dbe43fb05699e0485bf13fa00a34e7c990b4bfe92bc3c11586e13f77df754a9d7ee43fa04878784a72d4bf1cee789e2d4bc4bf39aaed03121ce13f6e152f0f793ad0bfbb2971a00809e53f06dc32a5fe2ef43fff7f81a9682de7bfaab7b7928713f03f9204ce5b5faee93f5a5a173d2eebfc3f652cd2e80be9d1bf804ebe161c5507402e24c74de27604404d1a9b4f4db00ac01000000000000000eaaea3070524f8bffe53a5f4852aebbfb87be253dafaf13f869037fd84b2e3bf2f5967ad02e3e0bf7b8414b7fba705c0bc319c909315e93f30dc2c0a9fcefd3f99e4b62935ffeabfdb79d442cb05dfbf13dc2b32b8fff03faebc4a8e8959c1bfa0bef4b40a4ec3bfb4490ee9de0cfd3f249afd24091dcd3f2112f5262e3be1bfe20d6d81505cd2bf9cead6eda082d0bfe3fbd7ae6e9febbfc273288641dcf43f4d99bd205e8de1bfd20729f16c15f93f90b45ba02c3b973f7cfa9d04a0d4ff3fe05982eb52dff13f901baed74b8f9a3f98cd6f5bc999e23fabf57ff03938d63f32cb688d9440fdbf4831e64171c90240709d83c4d5d9f9bf0fbcc97690d0d9bf1000000000000000032833d0e804e93f4070cbfaf3e3fb3f603fc97b0ed2f13f6b5fec540c69f9bf6cdb5cc3b810c5bfac4af25aac29cdbfa0a00c0067e693bf8cab055d023cd33fe6117751af8cec3ff3e7021824b5f6bf8c714ea69311f43f2a6b9842f1d6e3bf9349266e2da6f4bf1c49ee2454e4acbf6f69750e6856eabf286a8ae466e8d83fb254aca20dd3ddbf1cd7bacb5ec7e9bf349ad70f2672f93f7a463c8064c7e0bfd25e5a64ce83fe3f80fd41c5066af5bffef88217374af23f5693637e505202c0a2443727835b08400759c75361b2f83fdbede1f62141ecbf424a4807abcdc6bf3c28efd35124e43fd8af5be82393dcbff02be2932675f8bf804e49115480e8bf1000000000000000d26b3890b7b4f63f9cce902737c7c3bf4e9c1bbf22dde4bf9607282fd8c3fbbfff918ff92963d93f5c325734c072e2bfe016ef77514ead3fce5f5f0ded6edd3f1de04aafeee1c83fb7f5f33eb385f43fd25c14a723a500c0f03ea063fd8dc23ffbe635e54211e5bfb3474b6d2fd6f3bfcaaca863c65efd3f90570c2b152be1bfec297a80d3b3c63f4328eac90678e93f2af47b023b9c0140249e90ee3e0cf8bfbc729f01f715e1bf6e262e8f193fbd3f008cb91c9af8e9bff75fdc0288fde7bff3efb627a518c33fb3d928520823fe3f6044380730d2a43f9c1cd2a34729f1bff5ca358117cde8bfc868d51df585d63f20bd9e81145b99bf4ccfb9bd5ab7e9bf100000000000000024dce98dc1c3cebfb30349981654eb3faadf23d6658be2bf8e66e99b8aae0640bdff1b28e30ded3f5f039da78047ef3fb808b2598f01b7bf1d1242db75b1edbfd099b8554084bf3fab8946b4c8680340ee3b46ef1523e6bfe2ab6164b73df43ffea9296a6c68f1bfd4481cee0248e83f00971b1490eba8bf4788c7b92162e7bf188d982341d8f73f6e89db1c08edf93f46c1c77f23aaebbf7073b23994e9d4bff2928c6fcb25d5bf8b151f1eb00f01c05182739b7be1edbfade6ff959cfff53f8ab5b952dfa5f5bff84f263c31b8dabf927d910712daea3f5c71d8ea3a57c13f2018177bef74eebfc447192aeb8bdbbfe0b7df828491f6bf05517ed55288e43f10000000000000009209a2fdc327e13f88f684c1b23dc23f7c2c6c80500990bf915990700666d4bf176ac1484bc9f0bf78af8e582dbdcebf8a89b0d450e3e6bfdba806e5b8dff43f042a84b6aac8df3f5b5de6cee62edebf60dbf260b093b0bfd33e3737bb56f33fefe17a677b400940ca909569b43bc33fb7e111b337a2fabfe565a45fc74ced3fa41101139ab1c1bfe058fff71782ea3faefb2343cd1cc03f8f26cecf8f57da3f91f944d1932cefbf5b40d41ea7f7fd3f1db65f8f3060d0bf7718f44f3646fa3fa55d0365f10ac73f629222f97d32c8bf8636e22ec59ef13fed14f9ca357c01c01e4de68dc80af63feb648061b39bd2bfaaadf93f99e8e5bfc8e3d27f5d62bfbf100000000000000000b567fc9bef074062201b05f729d2bfd99629b308e0e63f0c116c0c9fd6febff46d5d673ab0d5bf4c3cd39e269aff3f69691a464fd7c73fe4d15942627fb5bf1b5daa52f043d33fd6a549d8d6e2edbfdd839be3d7d1e1bfa675c53259e2f6bf38ed6674cbf9a23ff65799abc29ce43fec0b0a1b6f31d13f60656d4722caa53f243ee925cfa7d93f70aecced3fabf73f4606d2357b0edebf6611bade64aad93fe650e2a5e682f93f4ec2cd10dca5febf951687681c64c03fe20096ba0e95eb3ff3212d21c334d7bf76347fa6c76703c03a0938a7631dd5bf47a50393bbc907c026f05f76507be43f1c8b60853c92e83f347802040e7fd63f64e0f4e873aff8bf0a0000000000000002000000000000000f000000000000000100000000000000080000000000000001000000000000000700000000000000"
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

	err = os.WriteFile("/tmp/add_result", ctBytes, 0644)
	if err != nil {
		return nil, err
	}

	ctHash := crypto.Keccak256Hash(verifiedCiphertext.ciphertext)
	accessibleState.Interpreter().verifiedCiphertexts[ctHash] = verifiedCiphertext

	C.free(cServerKey)
	C.free(cCiphertext1)
	C.free(cCiphertext2)

	return ctHash[:], nil
}

type fheDecrypt struct{}

func (e *fheDecrypt) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheDecrypt) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	if len(input) != 32 {
		return nil, errors.New("Input needs to contain one 256-bit sized value")
	}

	verifiedCiphertext1, exists := accessibleState.Interpreter().verifiedCiphertexts[common.BytesToHash(input[0:32])]
	if !exists {
		// do something here about u256-u256/u256-ciphertext/ciphertext-u256 addition,
		// not sure how it's defined.
	}

	var decoded_cks_str = "0c010000000000000000000020000000000000000100000000000000000000000000000000000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000014010000000000000000000020000000000000000100000000000000000000000000000000000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000020000000000000005c00000000000000000000000a0000000000000000000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000a00000000000000010000000000000020000000000000005d58a7a27f665d399b2ba1869b8426390f0000000000000001000000000000000600000000000000030000000000000001000000000000000f00000000000000bd89d897b2d2bc380000000000000000000000000000000008000000000000000100000000000000"
	serializedcks, err := hex.DecodeString(decoded_cks_str)
	if err != nil {
		return nil, err
	}

	cCiphertext1 := C.CBytes(verifiedCiphertext1.ciphertext)
	viewCiphertext1 := C.BufferView{
		pointer: (*C.uchar)(cCiphertext1),
		length:  (C.ulong)(len(verifiedCiphertext1.ciphertext)),
	}

	cServerKey := C.CBytes(serializedcks)
	viewServerKey := C.BufferView{
		pointer: (*C.uchar)(cServerKey),
		length:  (C.ulong)(len(serializedcks)),
	}

	// we need all those conversions because the precompiled contract
	// must return a byte array
	decryted_value := C.decrypt_integer(viewServerKey, viewCiphertext1)
	decryted_value_bytes := uint256.NewInt(uint64(decryted_value)).Bytes()

	err = os.WriteFile("/tmp/decryption_result", decryted_value_bytes, 0644)
	if err != nil {
		return nil, err
	}

	C.free(cServerKey)
	C.free(cCiphertext1)

	return decryted_value_bytes, nil
}

type fheEncrypt struct{}

func (e *fheEncrypt) RequiredGas(input []byte) uint64 {
	// TODO
	return 8
}

func (e *fheEncrypt) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {

	value, err := strconv.ParseInt(common.Bytes2Hex(input), 16, 64)
	if err != nil {
		return nil, errors.New("error during conversion from smart contract input to uint")
	}

	if (value) < 0 {
		return nil, errors.New("input must be greater than 0")
	}

	// TODO: load this key from file
	var decoded_cks_str = "0c010000000000000000000020000000000000000100000000000000000000000000000000000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000014010000000000000000000020000000000000000100000000000000000000000000000000000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000100000000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000020000000000000005c00000000000000000000000a0000000000000000000000000000000100000000000000000000000000000001000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000a00000000000000010000000000000020000000000000005d58a7a27f665d399b2ba1869b8426390f0000000000000001000000000000000600000000000000030000000000000001000000000000000f00000000000000bd89d897b2d2bc380000000000000000000000000000000008000000000000000100000000000000"
	serializedcks, err := hex.DecodeString(decoded_cks_str)
	if err != nil {
		return nil, err
	}

	cServerKey := C.CBytes(serializedcks)
	viewServerKey := C.BufferView{
		pointer: (*C.uchar)(cServerKey),
		length:  (C.ulong)(len(serializedcks)),
	}

	result := &C.Buffer{}
	C.encrypt_integer(viewServerKey, C.ulong(value), result)

	ctBytes := C.GoBytes(unsafe.Pointer(result.pointer), C.int(result.length))
	verifiedCiphertext := &verifiedCiphertext{
		depth:      accessibleState.Interpreter().evm.depth,
		ciphertext: ctBytes,
	}

	err = os.WriteFile("/tmp/encrypt_result", ctBytes, 0644)
	if err != nil {
		return nil, err
	}

	ctHash := crypto.Keccak256Hash(verifiedCiphertext.ciphertext)
	accessibleState.Interpreter().verifiedCiphertexts[ctHash] = verifiedCiphertext

	C.free(cServerKey)

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
