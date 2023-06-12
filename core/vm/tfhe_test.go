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
	"math/big"
	"testing"
)

// TODO: Don't rely on global keys that are loaded from disk in init(). Instead,
// generate keys on demand in the test.

func TfheEncryptDecrypt(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	}
	ct := new(tfheCiphertext)
	ct.encrypt(val, fheUintType)
	res := ct.decrypt()
	if res.Uint64() != val.Uint64() {
		t.Fatalf("%d != %d", val.Uint64(), res.Uint64())
	}
}

func TfheTrivialEncryptDecrypt(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	}
	ct := new(tfheCiphertext)
	ct.trivialEncrypt(val, fheUintType)
	res := ct.decrypt()
	if res.Uint64() != val.Uint64() {
		t.Fatalf("%d != %d", val.Uint64(), res.Uint64())
	}
}

func TfheSerializeDeserialize(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	}
	ct1 := new(tfheCiphertext)
	ct1.encrypt(val, fheUintType)
	ct1Ser := ct1.serialize()
	ct2 := new(tfheCiphertext)
	err := ct2.deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}
}

func TfheTrivialSerializeDeserialize(t *testing.T, fheUintType fheUintType) {
	var val big.Int
	switch fheUintType {
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	}
	ct1 := new(tfheCiphertext)
	ct1.trivialEncrypt(val, fheUintType)
	ct1Ser := ct1.serialize()
	ct2 := new(tfheCiphertext)
	err := ct2.deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("trivial serialization is non-deterministic")
	}
}

func TfheDeserializeFailure(t *testing.T, fheUintType fheUintType) {
	ct := new(tfheCiphertext)
	err := ct.deserialize(make([]byte, 10), fheUintType)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TfheDeserializeCompact(t *testing.T, fheUintType fheUintType) {
	var val uint32
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	}
	ser := encryptAndSerializeCompact(val, fheUintType)
	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("compact deserialization failed")
	}
	decryptedVal := ct.decrypt()
	if uint32(decryptedVal.Uint64()) != val {
		t.Fatalf("compact deserialization wrong decryption")
	}
}

func TfheDeserializeCompactFailure(t *testing.T, fheUintType fheUintType) {
	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(make([]byte, 10), fheUintType)
	if err == nil {
		t.Fatalf("compact deserialization must have failed")
	}
}

func TfheAdd(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.add(ctB)
	res := ctRes.decrypt()
	if res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheSub(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.sub(ctB)
	res := ctRes.decrypt()
	if res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheMul(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.mul(ctB)
	res := ctRes.decrypt()
	if res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheLte(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.lte(ctB)
	ctRes2, _ := ctB.lte(ctA)
	res1 := ctRes1.decrypt()
	res2 := ctRes2.decrypt()
	if res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheLt(t *testing.T, fheUintType fheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint8)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint8)
	ctRes1, _ := ctA.lte(ctB)
	ctRes2, _ := ctB.lte(ctA)
	res1 := ctRes1.decrypt()
	res2 := ctRes2.decrypt()
	if res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TestTfheEncryptDecrypt8(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint8)
}

func TestTfheEncryptDecrypt16(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint16)
}

func TestTfheEncryptDecrypt32(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint32)
}

func TestTfheTrivialEncryptDecrypt8(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint8)
}

func TestTfheTrivialEncryptDecrypt16(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint16)
}

func TestTfheTrivialEncryptDecrypt32(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint32)
}

func TestTfheSerializeDeserialize8(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint8)
}

func TestTfheSerializeDeserialize16(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint16)
}

func TestTfheSerializeDeserialize32(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint32)
}

func TestTfheTrivialSerializeDeserialize8(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint8)
}

func TestTfheTrivialSerializeDeserialize16(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint16)
}

func TestTfheTrivialSerializeDeserialize32(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint32)
}

func TestTfheDeserializeFailure8(t *testing.T) {
	TfheDeserializeFailure(t, FheUint8)
}

func TestTfheDeserializeFailure16(t *testing.T) {
	TfheDeserializeFailure(t, FheUint16)
}

func TestTfheDeserializeFailure32(t *testing.T) {
	TfheDeserializeFailure(t, FheUint32)
}

func TestTfheDeserializeCompact8(t *testing.T) {
	TfheDeserializeCompact(t, FheUint8)
}

func TestTfheDeserializeCompact16(t *testing.T) {
	TfheDeserializeCompact(t, FheUint16)
}

func TestTfheDeserializeCompatc32(t *testing.T) {
	TfheDeserializeCompact(t, FheUint32)
}

func TestTfheDeserializeCompactFailure8(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint8)
}

func TestTfheDeserializeCompactFailure16(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint16)
}

func TestTfheDeserializeCompatcFailure32(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint32)
}

func TestTfheAdd8(t *testing.T) {
	TfheAdd(t, FheUint8)
}

func TestTfheSub8(t *testing.T) {
	TfheSub(t, FheUint8)
}

func TestTfheMul8(t *testing.T) {
	TfheMul(t, FheUint8)
}

func TestTfheLte8(t *testing.T) {
	TfheLte(t, FheUint8)
}

func TestTfheLt8(t *testing.T) {
	TfheLte(t, FheUint8)
}
func TestTfheAdd16(t *testing.T) {
	TfheAdd(t, FheUint16)
}

func TestTfheSub16(t *testing.T) {
	TfheSub(t, FheUint16)
}

func TestTfheMul16(t *testing.T) {
	TfheMul(t, FheUint16)
}

func TestTfheLte16(t *testing.T) {
	TfheLte(t, FheUint16)
}

func TestTfheLt16(t *testing.T) {
	TfheLte(t, FheUint16)
}

func TestTfheAdd32(t *testing.T) {
	TfheAdd(t, FheUint32)
}

func TestTfheSub32(t *testing.T) {
	TfheSub(t, FheUint32)
}

func TestTfheMul32(t *testing.T) {
	TfheMul(t, FheUint32)
}

func TestTfheLte32(t *testing.T) {
	TfheLte(t, FheUint32)
}

func TestTfheLt32(t *testing.T) {
	TfheLte(t, FheUint32)
}
