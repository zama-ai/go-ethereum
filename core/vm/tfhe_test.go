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

func TestTfheCksEncryptDecrypt8(t *testing.T) {
	val := uint64(2)
	ct := new(tfheCiphertext)
	ct.encrypt(val, FheUint8)
	res := ct.decrypt()
	if res != val {
		t.Fatalf("%d != %d", val, res)
	}
}

func TestTfheSerializeDeserialize8(t *testing.T) {
	val := uint64(2)
	ctBytes := clientKeyEncrypt(val, FheUint8)
	ct := new(tfheCiphertext)
	err := ct.deserialize(ctBytes, FheUint8)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	serialized := ct.serialize()
	if !bytes.Equal(serialized, ctBytes) {
		t.Fatalf("serialization failed")
	}
}

func TestTfheDeserializeFailure8(t *testing.T) {
	ct := new(tfheCiphertext)
	err := ct.deserialize(make([]byte, 10), FheUint8)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TestTfheAdd8(t *testing.T) {
	a := uint64(1)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint8)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint8)
	ctRes, _ := ctA.add(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheSub8(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint8)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint8)
	ctRes, _ := ctA.sub(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheMul8(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint8)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint8)
	ctRes, _ := ctA.mul(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheLte8(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
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
func TestTfheLt8(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
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

func TestTfheCksEncryptDecrypt16(t *testing.T) {
	val := uint64(2)
	ct := new(tfheCiphertext)
	ct.encrypt(val, FheUint16)
	res := ct.decrypt()
	if res != val {
		t.Fatalf("%d != %d", val, res)
	}
}

func TestTfheSerializeDeserialize16(t *testing.T) {
	val := uint64(2)
	ctBytes := clientKeyEncrypt(val, FheUint16)
	ct := new(tfheCiphertext)
	err := ct.deserialize(ctBytes, FheUint16)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	serialized := ct.serialize()
	if !bytes.Equal(serialized, ctBytes) {
		t.Fatalf("serialization failed")
	}
}

func TestTfheDeserializeFailure16(t *testing.T) {
	ct := new(tfheCiphertext)
	err := ct.deserialize(make([]byte, 10), FheUint16)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TestTfheAdd16(t *testing.T) {
	a := uint64(1)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint16)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint16)
	ctRes, _ := ctA.add(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheSub16(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint16)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint16)
	ctRes, _ := ctA.sub(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheMul16(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint16)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint16)
	ctRes, _ := ctA.mul(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheLte16(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint16)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint16)
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
func TestTfheLt16(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint16)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint16)
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

func TestTfheCksEncryptDecrypt32(t *testing.T) {
	val := uint64(2)
	ct := new(tfheCiphertext)
	ct.encrypt(val, FheUint32)
	res := ct.decrypt()
	if res != val {
		t.Fatalf("%d != %d", val, res)
	}
}

func TestTfheSerializeDeserialize32(t *testing.T) {
	val := uint64(2)
	ctBytes := clientKeyEncrypt(val, FheUint32)
	ct := new(tfheCiphertext)
	err := ct.deserialize(ctBytes, FheUint32)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	serialized := ct.serialize()
	if !bytes.Equal(serialized, ctBytes) {
		t.Fatalf("serialization failed")
	}
}

func TestTfheDeserializeFailure32(t *testing.T) {
	ct := new(tfheCiphertext)
	err := ct.deserialize(make([]byte, 10), FheUint32)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TestTfheAdd32(t *testing.T) {
	a := uint64(1)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint32)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint32)
	ctRes, _ := ctA.add(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheSub32(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint32)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint32)
	ctRes, _ := ctA.sub(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheMul32(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint32)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint32)
	ctRes, _ := ctA.mul(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheLte32(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint32)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint32)
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
func TestTfheLt32(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a, FheUint32)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b, FheUint32)
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
