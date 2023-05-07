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
	"testing"
)

// TODO: Don't rely on global keys that are loaded from disk in init(). Instead,
// generate keys on demand in the test.

func TfheCksEncryptDecrypt(t *testing.T, fheUintType fheUintType) {
	var val uint64
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	}
	ct := new(tfheCiphertext)
	ct.encrypt(val, fheUintType)
	res := ct.decrypt()
	if res != val {
		t.Fatalf("%d != %d", val, res)
	}
}

func TfheSerializeDeserialize(t *testing.T, fheUintType fheUintType) {
	var val uint64
	switch fheUintType {
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	}
	ctBytes := clientKeyEncrypt(val, fheUintType)
	ct := new(tfheCiphertext)
	err := ct.deserialize(ctBytes, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	serialized := ct.serialize()
	if !bytes.Equal(serialized, ctBytes) {
		t.Fatalf("serialization failed")
	}
}

func TfheDeserializeFailure(t *testing.T, fheUintType fheUintType) {
	ct := new(tfheCiphertext)
	err := ct.deserialize(make([]byte, 10), fheUintType)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TfheAdd(t *testing.T, fheUintType fheUintType) {
	var a, b uint64
	switch fheUintType {
	case FheUint8:
		a = 2
		b = 1
	case FheUint16:
		a = 4283
		b = 1337
	case FheUint32:
		a = 1333337
		b = 133337
	}
	expected := a + b
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.add(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TfheSub(t *testing.T, fheUintType fheUintType) {
	var a, b uint64
	switch fheUintType {
	case FheUint8:
		a = 2
		b = 1
	case FheUint16:
		a = 4283
		b = 1337
	case FheUint32:
		a = 1333337
		b = 133337
	}
	expected := a - b
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.sub(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TfheMul(t *testing.T, fheUintType fheUintType) {
	var a, b uint64
	switch fheUintType {
	case FheUint8:
		a = 2
		b = 1
	case FheUint16:
		a = 169
		b = 5
	case FheUint32:
		a = 137
		b = 17
	}
	expected := a * b
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes, _ := ctA.mul(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TfheLte(t *testing.T, fheUintType fheUintType) {
	var a, b uint64
	switch fheUintType {
	case FheUint8:
		a = 2
		b = 1
	case FheUint16:
		a = 4283
		b = 1337
	case FheUint32:
		a = 1333337
		b = 133337
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, fheUintType)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, fheUintType)
	ctRes1, _ := ctA.lte(ctB)
	ctRes2, _ := ctB.lte(ctA)
	res1 := ctRes1.decrypt()
	res2 := ctRes2.decrypt()
	if res1 != 0 {
		t.Fatalf("%d != %d", 0, res1)
	}
	if res2 != 1 {
		t.Fatalf("%d != %d", 0, res2)
	}
}
func TfheLt(t *testing.T, fheUintType fheUintType) {
	var a, b uint64
	switch fheUintType {
	case FheUint8:
		a = 2
		b = 1
	case FheUint16:
		a = 4283
		b = 1337
	case FheUint32:
		a = 1333337
		b = 133337
	}
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint8)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint8)
	ctRes1, _ := ctA.lte(ctB)
	ctRes2, _ := ctB.lte(ctA)
	res1 := ctRes1.decrypt()
	res2 := ctRes2.decrypt()
	if res1 != 0 {
		t.Fatalf("%d != %d", 0, res1)
	}
	if res2 != 1 {
		t.Fatalf("%d != %d", 0, res2)
	}
}

func TestTfheCksEncryptDecrypt8(t *testing.T) {
	TfheCksEncryptDecrypt(t, FheUint8)
}

func TestTfheCksEncryptDecrypt16(t *testing.T) {
	TfheCksEncryptDecrypt(t, FheUint16)
}

func TestTfheCksEncryptDecrypt32(t *testing.T) {
	TfheCksEncryptDecrypt(t, FheUint32)
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

func TestTfheDeserializeFailure8(t *testing.T) {
	TfheDeserializeFailure(t, FheUint8)
}

func TestTfheDeserializeFailure16(t *testing.T) {
	TfheDeserializeFailure(t, FheUint16)
}

func TestTfheDeserializeFailure32(t *testing.T) {
	TfheDeserializeFailure(t, FheUint32)
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

// func TestTfheTrivialEncryptDecrypt(t *testing.T) {
// 	val := uint64(2)
// 	ct := new(tfheCiphertext)
// 	ct.trivialEncrypt(val)
// 	res := ct.decrypt()
// 	if res != val {
// 		t.Fatalf("%d != %d", val, res)
// 	}
// }

// func TestTfheTrivialAndEncryptedLte(t *testing.T) {
// 	a := uint64(2)
// 	b := uint64(1)
// 	ctA := new(tfheCiphertext)
// 	ctA.encrypt(a)
// 	ctB := new(tfheCiphertext)
// 	ctB.trivialEncrypt(b)
// 	ctRes1 := ctA.lte(ctB)
// 	ctRes2 := ctB.lte(ctA)
// 	res1 := ctRes1.decrypt()
// 	res2 := ctRes2.decrypt()
// 	if res1 != 0 {
// 		t.Fatalf("%d != %d", 0, res1)
// 	}
// 	if res2 != 1 {
// 		t.Fatalf("%d != %d", 0, res2)
// 	}
// }

// func TestTfheTrivialAndEncryptedAdd(t *testing.T) {
// 	a := uint64(1)
// 	b := uint64(1)
// 	ctA := new(tfheCiphertext)
// 	ctA.encrypt(a)
// 	ctB := new(tfheCiphertext)
// 	ctB.trivialEncrypt(b)
// 	ctRes := ctA.add(ctB)
// 	res := ctRes.decrypt()
// 	if res != 2 {
// 		t.Fatalf("%d != %d", 0, res)
// 	}
// }

// func TestTfheTrivialSerializeSize(t *testing.T) {
// 	ct := new(tfheCiphertext)
// 	ct.trivialEncrypt(2)
// 	if len(ct.serialize()) != fheCiphertextSize {
// 		t.Fatalf("serialization of trivially encrypted unexpected size")
// 	}
// }
