// Copyright 2015 The go-ethereum Authors
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
	"encoding/hex"
	"errors"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Add(&x, y)
	return nil, nil
}

func opSub(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Sub(&x, y)
	return nil, nil
}

func opMul(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mul(&x, y)
	return nil, nil
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Div(&x, y)
	return nil, nil
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SDiv(&x, y)
	return nil, nil
}

func opMod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mod(&x, y)
	return nil, nil
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SMod(&x, y)
	return nil, nil
}

func opExp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	base, exponent := scope.Stack.pop(), scope.Stack.peek()
	exponent.Exp(&base, exponent)
	return nil, nil
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	back, num := scope.Stack.pop(), scope.Stack.peek()
	num.ExtendSign(num, &back)
	return nil, nil
}

func opNot(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	x.Not(x)
	return nil, nil
}

func opLt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Lt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

func opGt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Gt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

func opSlt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Slt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

func opSgt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Sgt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

func opEq(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if x.IsZero() {
		x.SetOne()
	} else {
		x.Clear()
	}
	return nil, nil
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.And(&x, y)
	return nil, nil
}

func opOr(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Or(&x, y)
	return nil, nil
}

func opXor(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Xor(&x, y)
	return nil, nil
}

func opByte(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	th, val := scope.Stack.pop(), scope.Stack.peek()
	val.Byte(&th)
	return nil, nil
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	if z.IsZero() {
		z.Clear()
	} else {
		z.AddMod(&x, &y, z)
	}
	return nil, nil
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	z.MulMod(&x, &y, z)
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Lsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Rsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.GtUint64(256) {
		if value.Sign() >= 0 {
			value.Clear()
		} else {
			// Max negative shift: all bits set
			value.SetAllOne()
		}
		return nil, nil
	}
	n := uint(shift.Uint64())
	value.SRsh(value, n)
	return nil, nil
}

func opKeccak256(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.peek()
	data := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	evm := interpreter.evm
	if evm.Config.EnablePreimageRecording {
		evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}

	size.SetBytes(interpreter.hasherBuf[:])
	return nil, nil
}
func opAddress(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Address().Bytes()))
	return nil, nil
}

func opBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	slot.SetFromBig(interpreter.evm.StateDB.GetBalance(address))
	return nil, nil
}

func opOrigin(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Origin.Bytes()))
	return nil, nil
}
func opCaller(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Caller().Bytes()))
	return nil, nil
}

func opCallValue(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(scope.Contract.value)
	scope.Stack.push(v)
	return nil, nil
}

func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if offset, overflow := x.Uint64WithOverflow(); !overflow {
		data := getData(scope.Contract.Input, offset, 32)
		x.SetBytes(data)
	} else {
		x.Clear()
	}
	return nil, nil
}

func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Input))))
	return nil, nil
}

func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = 0xffffffffffffffff
	}
	// These values are checked for overflow during gas cost calculation
	memOffset64 := memOffset.Uint64()
	length64 := length.Uint64()
	scope.Memory.Set(memOffset64, length64, getData(scope.Contract.Input, dataOffset64, length64))

	return nil, nil
}

func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(interpreter.returnData))))
	return nil, nil
}

func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)

	offset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		return nil, ErrReturnDataOutOfBounds
	}
	// we can reuse dataOffset now (aliasing it for clarity)
	var end = dataOffset
	end.Add(&dataOffset, &length)
	end64, overflow := end.Uint64WithOverflow()
	if overflow || uint64(len(interpreter.returnData)) < end64 {
		return nil, ErrReturnDataOutOfBounds
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[offset64:end64])
	return nil, nil
}

func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(slot.Bytes20())))
	return nil, nil
}

func opCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	l := new(uint256.Int)
	l.SetUint64(uint64(len(scope.Contract.Code)))
	scope.Stack.push(l)
	return nil, nil
}

func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		codeOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	codeCopy := getData(scope.Contract.Code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		stack      = scope.Stack
		a          = stack.pop()
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	addr := common.Address(a.Bytes20())
	codeCopy := getData(interpreter.evm.StateDB.GetCode(addr), uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//
//	(1) Caller tries to get the code hash of a normal contract account, state
//
// should return the relative code hash and set it as the result.
//
//	(2) Caller tries to get the code hash of a non-existent account, state should
//
// return common.Hash{} and zero will be set as the result.
//
//	(3) Caller tries to get the code hash for an account without contract code,
//
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//	(4) Caller tries to get the code hash of a precompiled account, the result
//
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//	(5) Caller tries to get the code hash for an account which is marked as suicided
//
// in the current transaction, the code hash of this account should be returned.
//
//	(6) Caller tries to get the code hash for an account which is marked as deleted,
//
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	if interpreter.evm.StateDB.Empty(address) {
		slot.Clear()
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	return nil, nil
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.GasPrice)
	scope.Stack.push(v)
	return nil, nil
}

func opBlockhash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	num := scope.Stack.peek()
	num64, overflow := num.Uint64WithOverflow()
	if overflow {
		num.Clear()
		return nil, nil
	}
	var upper, lower uint64
	upper = interpreter.evm.Context.BlockNumber.Uint64()
	if upper < 257 {
		lower = 0
	} else {
		lower = upper - 256
	}
	if num64 >= lower && num64 < upper {
		num.SetBytes(interpreter.evm.Context.GetHash(num64).Bytes())
	} else {
		num.Clear()
	}
	return nil, nil
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Context.Coinbase.Bytes()))
	return nil, nil
}

func opTimestamp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Time)
	scope.Stack.push(v)
	return nil, nil
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.BlockNumber)
	scope.Stack.push(v)
	return nil, nil
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Difficulty)
	scope.Stack.push(v)
	return nil, nil
}

func opRandom(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v := new(uint256.Int).SetBytes(interpreter.evm.Context.Random.Bytes())
	scope.Stack.push(v)
	return nil, nil
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.GasLimit))
	return nil, nil
}

func opPop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.pop()
	return nil, nil
}

func opMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v := scope.Stack.peek()
	offset := int64(v.Uint64())
	v.SetBytes(scope.Memory.GetPtr(offset, 32))
	return nil, nil
}

func opMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.Set32(mStart.Uint64(), &val)
	return nil, nil
}

func opMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.store[off.Uint64()] = byte(val.Uint64())
	return nil, nil
}

// Ciphertext metadata is stored in protected storage, in a 32-byte slot.
// Currently, we only utilize 17 bytes from the slot.
type ciphertextMetadata struct {
	refCount    uint64
	length      uint64
	fheUintType fheUintType
}

func (m ciphertextMetadata) serialize() [32]byte {
	u := uint256.NewInt(0)
	u[0] = m.refCount
	u[1] = m.length
	u[2] = uint64(m.fheUintType)
	return u.Bytes32()
}

func (m *ciphertextMetadata) deserialize(buf [32]byte) *ciphertextMetadata {
	u := uint256.NewInt(0)
	u.SetBytes(buf[:])
	m.refCount = u[0]
	m.length = u[1]
	m.fheUintType = fheUintType(u[2])
	return m
}

func newCiphertextMetadata(buf [32]byte) *ciphertextMetadata {
	m := ciphertextMetadata{}
	return m.deserialize(buf)
}

func newInt(buf []byte) *uint256.Int {
	i := uint256.NewInt(0)
	return i.SetBytes(buf)
}

var zero = common.BytesToHash(uint256.NewInt(0).Bytes())

func verifyIfCiphertextHandle(handle common.Hash, interpreter *EVMInterpreter, contractAddress common.Address) error {
	ct, ok := interpreter.verifiedCiphertexts[handle]
	if ok {
		// If already existing in memory, skip storage and import the same ciphertext at the current depth.
		//
		// Also works for gas estimation - we don't persist anything to protected storage during gas estimation.
		// However, ciphertexts remain in memory for the duration of the call, allowing for this lookup to find it.
		// Note that even if a ciphertext has an empty verification depth set, it still remains in memory.
		importCiphertextToEVM(interpreter, ct.ciphertext)
		return nil
	}

	metadataKey := crypto.Keccak256Hash(handle.Bytes())
	protectedStorage := crypto.CreateProtectedStorageContractAddress(contractAddress)
	metadataInt := newInt(interpreter.evm.StateDB.GetState(protectedStorage, metadataKey).Bytes())
	if !metadataInt.IsZero() {
		metadata := newCiphertextMetadata(metadataInt.Bytes32())
		ctBytes := make([]byte, 0)
		left := metadata.length
		protectedSlotIdx := newInt(metadataKey.Bytes())
		protectedSlotIdx.AddUint64(protectedSlotIdx, 1)
		for {
			if left == 0 {
				break
			}
			bytes := interpreter.evm.StateDB.GetState(protectedStorage, protectedSlotIdx.Bytes32())
			toAppend := minUint64(uint64(len(bytes)), left)
			left -= toAppend
			ctBytes = append(ctBytes, bytes[0:toAppend]...)
			protectedSlotIdx.AddUint64(protectedSlotIdx, 1)
		}

		ct := new(tfheCiphertext)
		err := ct.deserialize(ctBytes, metadata.fheUintType)
		if err != nil {
			msg := "opSload failed to deserialize a ciphertext"
			interpreter.evm.Logger.Error(msg, "err", err)
			return errors.New(msg)
		}
		importCiphertextToEVM(interpreter, ct)
	}
	return nil
}

func opSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.peek()
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
	if err := verifyIfCiphertextHandle(val, interpreter, scope.Contract.Address()); err != nil {
		return nil, err
	}
	loc.SetBytes(val.Bytes())
	return nil, nil
}

// An arbitrary constant value to flag locations in protected storage.
var flag = common.HexToHash("0xa145ffde0100a145ffde0100a145ffde0100a145ffde0100a145ffde0100fab3")

// If a verified ciphertext:
// * if the ciphertext does not exist in protected storage, persist it with a refCount = 1
// * if the ciphertexts exists in protected, bump its refCount by 1
func persistIfVerifiedCiphertext(flagHandleLocation common.Hash, handle common.Hash, protectedStorage common.Address, interpreter *EVMInterpreter) {
	verifiedCiphertext := getVerifiedCiphertextFromEVM(interpreter, handle)
	if verifiedCiphertext == nil {
		return
	}
	logger := interpreter.evm.Logger

	// Try to read ciphertext metadata from protected storage.
	metadataKey := crypto.Keccak256Hash(handle.Bytes())
	metadataInt := newInt(interpreter.evm.StateDB.GetState(protectedStorage, metadataKey).Bytes())
	metadata := ciphertextMetadata{}

	// Set flag in protected storage to mark the location as containing a handle.
	interpreter.evm.StateDB.SetState(protectedStorage, flagHandleLocation, flag)

	if metadataInt.IsZero() {
		// If no metadata, it means this ciphertext itself hasn't been persisted to protected storage yet. We do that as part of SSTORE.
		metadata.refCount = 1
		metadata.length = uint64(expandedFheCiphertextSize[verifiedCiphertext.ciphertext.fheUintType])
		metadata.fheUintType = verifiedCiphertext.ciphertext.fheUintType
		ciphertextSlot := newInt(metadataKey.Bytes())
		ciphertextSlot.AddUint64(ciphertextSlot, 1)
		if interpreter.evm.Commit {
			logger.Info("opSstore persisting new ciphertext",
				"protectedStorage", hex.EncodeToString(protectedStorage[:]),
				"handle", hex.EncodeToString(handle.Bytes()),
				"type", metadata.fheUintType,
				"len", metadata.length,
				"ciphertextSlot", hex.EncodeToString(ciphertextSlot.Bytes()))
		}
		ctPart32 := make([]byte, 32)
		partIdx := 0
		ctBytes := verifiedCiphertext.ciphertext.serialize()
		for i, b := range ctBytes {
			if i%32 == 0 && i != 0 {
				interpreter.evm.StateDB.SetState(protectedStorage, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
				ciphertextSlot.AddUint64(ciphertextSlot, 1)
				ctPart32 = make([]byte, 32)
				partIdx = 0
			}
			ctPart32[partIdx] = b
			partIdx++
		}
		if len(ctPart32) != 0 {
			interpreter.evm.StateDB.SetState(protectedStorage, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
		}
	} else {
		// If metadata exists, bump the refcount by 1.
		metadata = *newCiphertextMetadata(interpreter.evm.StateDB.GetState(protectedStorage, metadataKey))
		metadata.refCount++
		if interpreter.evm.Commit {
			logger.Info("opSstore bumping refcount of existing ciphertext",
				"protectedStorage", hex.EncodeToString(protectedStorage[:]),
				"handle", hex.EncodeToString(handle.Bytes()),
				"type", metadata.fheUintType,
				"len", metadata.length,
				"refCount", metadata.refCount)
		}
	}
	// Save the metadata in protected storage.
	interpreter.evm.StateDB.SetState(protectedStorage, metadataKey, metadata.serialize())
}

// If references are still left, reduce refCount by 1. Otherwise, zero out the metadata and the ciphertext slots.
func garbageCollectProtectedStorage(flagHandleLocation common.Hash, handle common.Hash, protectedStorage common.Address, interpreter *EVMInterpreter) {
	// The location of ciphertext metadata is at Keccak256(handle). Doing so avoids attacks from users trying to garbage
	// collect arbitrary locations in protected storage. Hashing the handle makes it hard to find a preimage such that
	// it ends up in arbitrary non-zero places in protected stroage.
	metadataKey := crypto.Keccak256Hash(handle.Bytes())

	existingMetadataHash := interpreter.evm.StateDB.GetState(protectedStorage, metadataKey)
	existingMetadataInt := newInt(existingMetadataHash.Bytes())
	if !existingMetadataInt.IsZero() {
		logger := interpreter.evm.Logger

		// If no flag in protected storage for the location, ignore garbage collection.
		// Else, set the value at the location to zero.
		foundFlag := interpreter.evm.StateDB.GetState(protectedStorage, flagHandleLocation)
		if !bytes.Equal(foundFlag.Bytes(), flag.Bytes()) {
			logger.Error("opSstore location flag not found for a ciphertext handle, ignoring garbage collection",
				"expectedFlag", hex.EncodeToString(flag[:]),
				"foundFlag", hex.EncodeToString(foundFlag[:]),
				"flagHandleLocation", hex.EncodeToString(flagHandleLocation[:]))
			return
		} else {
			interpreter.evm.StateDB.SetState(protectedStorage, flagHandleLocation, zero)
		}

		metadata := newCiphertextMetadata(existingMetadataInt.Bytes32())
		if metadata.refCount == 1 {
			if interpreter.evm.Commit {
				logger.Info("opSstore garbage collecting ciphertext",
					"protectedStorage", hex.EncodeToString(protectedStorage[:]),
					"metadataKey", hex.EncodeToString(metadataKey[:]),
					"type", metadata.fheUintType,
					"len", metadata.length)
			}

			// Zero the metadata key-value.
			interpreter.evm.StateDB.SetState(protectedStorage, metadataKey, zero)

			// Set the slot to the one after the metadata one.
			slot := newInt(metadataKey.Bytes())
			slot.AddUint64(slot, 1)

			// Zero the ciphertext slots.
			slotsToZero := metadata.length / 32
			if metadata.length > 0 && metadata.length < 32 {
				slotsToZero++
			}
			for i := uint64(0); i < slotsToZero; i++ {
				interpreter.evm.StateDB.SetState(protectedStorage, slot.Bytes32(), zero)
				slot.AddUint64(slot, 1)
			}
		} else if metadata.refCount > 1 {
			if interpreter.evm.Commit {
				logger.Info("opSstore decrementing ciphertext refCount",
					"protectedStorage", hex.EncodeToString(protectedStorage[:]),
					"metadataKey", hex.EncodeToString(metadataKey[:]),
					"type", metadata.fheUintType,
					"len", metadata.length)
			}
			metadata.refCount--
			interpreter.evm.StateDB.SetState(protectedStorage, existingMetadataHash, metadata.serialize())
		}
	}
}

func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	loc := scope.Stack.pop()
	locHash := common.BytesToHash(loc.Bytes())
	newVal := scope.Stack.pop()
	newValHash := common.BytesToHash(newVal.Bytes())
	oldValHash := interpreter.evm.StateDB.GetState(scope.Contract.Address(), common.Hash(loc.Bytes32()))
	// If the value is the same or if we are not going to commit, don't do anything to protected storage.
	if newValHash != oldValHash && interpreter.evm.Commit {
		protectedStorage := crypto.CreateProtectedStorageContractAddress(scope.Contract.Address())

		// Define flag location as keccak256(keccak256(loc)) in protected storage. Used to mark the location as containing a handle.
		// Note: We apply the hash function twice to make sure a flag location in protected storage cannot clash with a ciphertext
		// metadata location that is keccak256(keccak256(ciphertext)). Since a location is 32 bytes, it cannot clash with a well-formed
		// ciphertext. Therefore, there needs to be a hash collistion for a clash to happen. If hash is applied only once, there could
		// be a collision, since malicous users could store at loc = keccak256(ciphertext), making the flag clash with metadata.
		flagHandleLocation := crypto.Keccak256Hash(crypto.Keccak256Hash(locHash[:]).Bytes())

		// Since the old value is no longer stored in actual contract storage, run garbage collection on protected storage.
		garbageCollectProtectedStorage(flagHandleLocation, oldValHash, protectedStorage, interpreter)

		// If a verified ciphertext, persist to protected storage.
		persistIfVerifiedCiphertext(flagHandleLocation, newValHash, protectedStorage, interpreter)
	}
	// Set the SSTORE's value in the actual contract.
	interpreter.evm.StateDB.SetState(scope.Contract.Address(),
		loc.Bytes32(), newValHash)
	return nil, nil
}

func opJump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if atomic.LoadInt32(&interpreter.evm.abort) != 0 {
		return nil, errStopToken
	}
	pos := scope.Stack.pop()
	if !scope.Contract.validJumpdest(&pos) {
		return nil, ErrInvalidJump
	}
	*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	return nil, nil
}

func opJumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if atomic.LoadInt32(&interpreter.evm.abort) != 0 {
		return nil, errStopToken
	}
	pos, cond := scope.Stack.pop(), scope.Stack.pop()
	if !cond.IsZero() {
		if !scope.Contract.validJumpdest(&pos) {
			return nil, ErrInvalidJump
		}
		*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	}
	return nil, nil
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, nil
}

func opPc(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(*pc))
	return nil, nil
}

func opMsize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(scope.Memory.Len())))
	return nil, nil
}

func opGas(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(scope.Contract.Gas))
	return nil, nil
}

func opCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		value        = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}
	// reuse size int for stackvalue
	stackvalue := size

	scope.Contract.UseGas(gas)
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		bigVal = value.ToBig()
	}

	res, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, bigVal)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
}

func opCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)

	// Apply EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas)
	// reuse size int for stackvalue
	stackvalue := size
	//TODO: use uint256.Int instead of converting with toBig()
	bigEndowment := big0
	if !endowment.IsZero() {
		bigEndowment = endowment.ToBig()
	}
	res, addr, returnGas, suberr := interpreter.evm.Create2(scope.Contract, input, gas,
		bigEndowment, &salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
}

// If there are ciphertext handles in the arguments to a call, delegate them to the callee.
// Return a map from ciphertext hash -> depthSet before delegation.
func delegateCiphertextHandlesInArgs(interpreter *EVMInterpreter, args []byte) (verified map[common.Hash]*depthSet) {
	verified = make(map[common.Hash]*depthSet)
	for key, verifiedCiphertext := range interpreter.verifiedCiphertexts {
		if contains(args, key.Bytes()) && isVerifiedAtCurrentDepth(interpreter, verifiedCiphertext) {
			if interpreter.evm.Commit {
				interpreter.evm.Logger.Info("delegateCiphertextHandlesInArgs",
					"handle", verifiedCiphertext.ciphertext.getHash().Hex(),
					"fromDepth", interpreter.evm.depth,
					"toDepth", interpreter.evm.depth+1)
			}
			verified[key] = verifiedCiphertext.verifiedDepths.clone()
			verifiedCiphertext.verifiedDepths.add(interpreter.evm.depth + 1)
		}
	}
	return
}

func restoreVerifiedDepths(interpreter *EVMInterpreter, verified map[common.Hash]*depthSet) {
	for k, v := range verified {
		interpreter.verifiedCiphertexts[k].verifiedDepths = v
	}
}

func opCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	// We can use this as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get the arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	if interpreter.readOnly && !value.IsZero() {
		return nil, ErrWriteProtection
	}
	var bigVal = big0
	//TODO: use uint256.Int instead of converting with toBig()
	// By using big0 here, we save an alloc for the most common case (non-ether-transferring contract calls),
	// but it would make more sense to extend the usage of uint256.Int
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	verifiedBefore := delegateCiphertextHandlesInArgs(interpreter, args)
	ret, returnGas, err := interpreter.evm.Call(scope.Contract, toAddr, args, gas, bigVal)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	restoreVerifiedDepths(interpreter, verifiedBefore)
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil
}

func opCallCode(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	verifiedBefore := delegateCiphertextHandlesInArgs(interpreter, args)
	ret, returnGas, err := interpreter.evm.CallCode(scope.Contract, toAddr, args, gas, bigVal)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	restoreVerifiedDepths(interpreter, verifiedBefore)
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil
}

func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	verifiedBefore := delegateCiphertextHandlesInArgs(interpreter, args)
	ret, returnGas, err := interpreter.evm.DelegateCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	restoreVerifiedDepths(interpreter, verifiedBefore)
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil
}

func opStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	verifiedBefore := delegateCiphertextHandlesInArgs(interpreter, args)
	ret, returnGas, err := interpreter.evm.StaticCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	restoreVerifiedDepths(interpreter, verifiedBefore)
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	interpreter.returnData = ret
	return ret, nil
}

func opReturn(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	for key, verifiedCiphertext := range interpreter.verifiedCiphertexts {
		if contains(ret, key.Bytes()) && isVerifiedAtCurrentDepth(interpreter, verifiedCiphertext) {
			if interpreter.evm.Commit {
				interpreter.evm.Logger.Info("opReturn making ciphertext available to caller",
					"handle", verifiedCiphertext.ciphertext.getHash().Hex(),
					"fromDepth", interpreter.evm.depth,
					"toDepth", interpreter.evm.depth-1)
			}
			// If a handle is returned, automatically make it available to the caller.
			verifiedCiphertext.verifiedDepths.add(interpreter.evm.depth - 1)
		}
	}

	return ret, errStopToken
}

func opRevert(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	interpreter.returnData = ret
	return ret, ErrExecutionReverted
}

func opUndefined(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, &ErrInvalidOpCode{opcode: OpCode(scope.Contract.Code[*pc])}
}

func opStop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, errStopToken
}

func opSelfdestruct(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	protectedStorage := crypto.CreateProtectedStorageContractAddress(scope.Contract.Address())
	beneficiary := scope.Stack.pop()
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	balance.Add(balance, interpreter.evm.StateDB.GetBalance(protectedStorage))
	interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance)
	interpreter.evm.StateDB.Suicide(scope.Contract.Address())
	interpreter.evm.StateDB.Suicide(protectedStorage)
	if interpreter.cfg.Debug {
		interpreter.cfg.Tracer.CaptureEnter(SELFDESTRUCT, scope.Contract.Address(), beneficiary.Bytes20(), []byte{}, 0, balance)
		interpreter.cfg.Tracer.CaptureExit([]byte{}, 0, nil)
	}
	return nil, errStopToken
}

// following functions are used by the instruction jump  table

// make log instruction function
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		if interpreter.readOnly {
			return nil, ErrWriteProtection
		}
		topics := make([]common.Hash, size)
		stack := scope.Stack
		mStart, mSize := stack.pop(), stack.pop()
		for i := 0; i < size; i++ {
			addr := stack.pop()
			topics[i] = addr.Bytes32()
		}

		d := scope.Memory.GetCopy(int64(mStart.Uint64()), int64(mSize.Uint64()))
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: scope.Contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			BlockNumber: interpreter.evm.Context.BlockNumber.Uint64(),
		})

		return nil, nil
	}
}

// opPush1 is a specialized version of pushN
func opPush1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))
	} else {
		scope.Stack.push(integer.Clear())
	}
	return nil, nil
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		codeLen := len(scope.Contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := new(uint256.Int)
		scope.Stack.push(integer.SetBytes(common.RightPadBytes(
			scope.Contract.Code[startMin:endMin], pushByteSize)))

		*pc += size
		return nil, nil
	}
}

// make dup instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.dup(int(size))
		return nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.swap(int(size))
		return nil, nil
	}
}
