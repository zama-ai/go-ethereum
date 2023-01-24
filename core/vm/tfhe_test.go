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

func mustPanic(t *testing.T, f func()) {
	defer func() { recover() }()
	f()
	t.Fatalf("did not panic")
}

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
	ct.deserialize(ctBytes)
	serialized := ct.serialize()
	if !bytes.Equal(serialized, ctBytes) {
		t.Fatalf("serialization failed")
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

func TestTfheEncryptOnExisting(t *testing.T) {
	ct := new(tfheCiphertext)
	ct.encrypt(1)
	mustPanic(t, func() { ct.encrypt(2) })
}

func TestTfheDeserializeOnExisting(t *testing.T) {
	ct := new(tfheCiphertext)
	ct.encrypt(1)
	ctBytes := ct.serialize()
	mustPanic(t, func() { ct.deserialize(ctBytes) })
}

func TestTfheSerializeOnNonExisting(t *testing.T) {
	ct := new(tfheCiphertext)
	mustPanic(t, func() { ct.serialize() })
}

func TestTfheAddOnNonExisting(t *testing.T) {
	a := new(tfheCiphertext)
	a.encrypt(1)
	b := new(tfheCiphertext)
	mustPanic(t, func() { a.add(b) })
	mustPanic(t, func() { b.add(a) })
}

func TestTfheSubOnNonExisting(t *testing.T) {
	a := new(tfheCiphertext)
	a.encrypt(1)
	b := new(tfheCiphertext)
	mustPanic(t, func() { a.sub(b) })
	mustPanic(t, func() { b.sub(a) })
}

func TestTfheLteOnNonExisting(t *testing.T) {
	a := new(tfheCiphertext)
	a.encrypt(1)
	b := new(tfheCiphertext)
	mustPanic(t, func() { a.lte(b) })
	mustPanic(t, func() { b.lte(a) })
}

func TestTfheDecryptOnNonExisting(t *testing.T) {
	ct := new(tfheCiphertext)
	mustPanic(t, func() { ct.decrypt() })
}

func TestTfheGetHashOnNonExisting(t *testing.T) {
	ct := new(tfheCiphertext)
	mustPanic(t, func() { ct.getHash() })
}
