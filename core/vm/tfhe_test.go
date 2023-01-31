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

func TestTfheCksEncryptDecrypt(t *testing.T) {
	val := uint64(2)
	ct := new(tfheCiphertext)
	ct.encrypt(val)
	res := ct.decrypt()
	if res != val {
		t.Fatalf("%d != %d", val, res)
	}
}

func TestTfheSerializeDeserialize(t *testing.T) {
	val := uint64(2)
	ctBytes := clientKeyEncrypt(val)
	ct := new(tfheCiphertext)
	err := ct.deserialize(ctBytes)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	serialized := ct.serialize()
	if !bytes.Equal(serialized, ctBytes) {
		t.Fatalf("serialization failed")
	}
}

func TestTfheDeserializeFailure(t *testing.T) {
	ct := new(tfheCiphertext)
	err := ct.deserialize(make([]byte, 10))
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TestTfheAdd(t *testing.T) {
	a := uint64(1)
	b := uint64(1)
	expected := uint64(2)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b)
	ctRes := ctA.add(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheSub(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	expected := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b)
	ctRes := ctA.sub(ctB)
	res := ctRes.decrypt()
	if res != expected {
		t.Fatalf("%d != %d", expected, res)
	}
}

func TestTfheLte(t *testing.T) {
	a := uint64(2)
	b := uint64(1)
	ctA := new(tfheCiphertext)
	ctA.encrypt(a)
	ctB := new(tfheCiphertext)
	ctB.encrypt(b)
	ctRes1 := ctA.lte(ctB)
	ctRes2 := ctB.lte(ctA)
	res1 := ctRes1.decrypt()
	res2 := ctRes2.decrypt()
	if res1 != 0 {
		t.Fatalf("%d != %d", 0, res1)
	}
	if res2 != 1 {
		t.Fatalf("%d != %d", 0, res2)
	}
}
