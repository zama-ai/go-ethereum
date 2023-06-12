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
#cgo CFLAGS: -O3
#cgo LDFLAGS: -Llib -ltfhe

#include "tfhe.h"

#undef NDEBUG
#include <assert.h>

void* deserialize_server_key(BufferView in) {
	ServerKey* sks = NULL;
	const int r = server_key_deserialize(in, &sks);
	assert(r == 0);
	return sks;
}

void* deserialize_client_key(BufferView in) {
	ClientKey* cks = NULL;
	const int r = client_key_deserialize(in, &cks);
	assert(r == 0);
	return cks;
}

void* deserialize_compact_public_key(BufferView in) {
	CompactPublicKey* pks = NULL;
	const int r = compact_public_key_deserialize(in, &pks);
	assert(r == 0);
	return pks;
}

void checked_set_server_key(void *sks) {
	const int r = set_server_key(sks);
	assert(r == 0);
}

void serialize_fhe_uint8(void *ct, Buffer* out) {
	const int r = fhe_uint8_serialize(ct, out);
	assert(r == 0);
}

void* deserialize_fhe_uint8(BufferView in) {
	FheUint8* ct = NULL;
	const int r = fhe_uint8_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint8(BufferView in) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint8_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint8_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);
	return ct;
}

void serialize_fhe_uint16(void *ct, Buffer* out) {
	const int r = fhe_uint16_serialize(ct, out);
	assert(r == 0);
}

void* deserialize_fhe_uint16(BufferView in) {
	FheUint16* ct = NULL;
	const int r = fhe_uint16_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint16(BufferView in) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint16_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint16_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);
	return ct;
}

void serialize_fhe_uint32(void *ct, Buffer* out) {
	const int r = fhe_uint32_serialize(ct, out);
	assert(r == 0);
}

void* deserialize_fhe_uint32(BufferView in) {
	FheUint32* ct = NULL;
	const int r = fhe_uint32_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint32(BufferView in) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint32_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint32_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);
	return ct;
}

void destroy_fhe_uint8(void* ct) {
	fhe_uint8_destroy(ct);
}

void destroy_fhe_uint16(void* ct) {
	fhe_uint16_destroy(ct);
}

void destroy_fhe_uint32(void* ct) {
	fhe_uint32_destroy(ct);
}

void* add_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* add_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* add_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

uint8_t decrypt_fhe_uint8(void* cks, void* ct)
{
	uint8_t res = 0;
	const int r = fhe_uint8_decrypt(ct, cks, &res);
	assert(r == 0);
	return res;
}

uint16_t decrypt_fhe_uint16(void* cks, void* ct)
{
	uint16_t res = 0;
	const int r = fhe_uint16_decrypt(ct, cks, &res);
	assert(r == 0);
	return res;
}

uint32_t decrypt_fhe_uint32(void* cks, void* ct)
{
	uint32_t res = 0;
	const int r = fhe_uint32_decrypt(ct, cks, &res);
	assert(r == 0);
	return res;
}

void* public_key_encrypt_fhe_uint8(void* pks, uint8_t value) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint16(void* pks, uint16_t value) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint32(void* pks, uint32_t value) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint8(void* sks, uint8_t value) {
	FheUint8* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint8_try_encrypt_trivial_u8(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint16(void* sks, uint16_t value) {
	FheUint16* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint16_try_encrypt_trivial_u16(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint32(void* sks, uint32_t value) {
	FheUint32* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint32_try_encrypt_trivial_u32(value, &ct);
  	assert(r == 0);

	return ct;
}

void public_key_encrypt_and_serialize_fhe_uint8_list(void* pks, uint8_t value, Buffer* out) {
	CompactFheUint8List* list = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_serialize(list, out);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint16_list(void* pks, uint16_t value, Buffer* out) {
	CompactFheUint16List* list = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_serialize(list, out);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint32_list(void* pks, uint32_t value, Buffer* out) {
	CompactFheUint32List* list = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_serialize(list, out);
	assert(r == 0);
}

*/
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func toBufferView(in []byte) C.BufferView {
	return C.BufferView{
		pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
		length:  (C.size_t)(len(in)),
	}
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return home
}

// TFHE ciphertext sizes by type, in bytes.
// Note: These sizes are for expanded (non-compacted) ciphertexts.
var expandedFheCiphertextSize map[fheUintType]uint

var sks unsafe.Pointer
var cks unsafe.Pointer
var pks unsafe.Pointer
var networkKeysDir string
var usersKeysDir string

var allocatedCiphertexts uint64

// TODO: We assume that contracts.go's init() runs before the init() in this file,
// making the TOML configuration available here.
func runGc() {
	for range time.Tick(time.Duration(tomlConfig.Tfhe.CiphertextsGarbageCollectIntervalSecs) * time.Second) {
		if atomic.LoadUint64(&allocatedCiphertexts) >= tomlConfig.Tfhe.CiphertextsToGarbageCollect {
			atomic.StoreUint64(&allocatedCiphertexts, 0)
			runtime.GC()
		}
	}
}

func init() {
	expandedFheCiphertextSize = make(map[fheUintType]uint)

	go runGc()

	home := homeDir()
	networkKeysDir = home + "/.evmosd/zama/keys/network-fhe-keys/"
	usersKeysDir = home + "/.evmosd/zama/keys/users-fhe-keys/"

	sksBytes, err := os.ReadFile(networkKeysDir + "sks")
	if err != nil {
		fmt.Println("WARNING: file sks not found.")
		return
	}
	sks = C.deserialize_server_key(toBufferView(sksBytes))

	expandedFheCiphertextSize[FheUint8] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint8).serialize()))
	expandedFheCiphertextSize[FheUint16] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint16).serialize()))
	expandedFheCiphertextSize[FheUint32] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint32).serialize()))

	cksBytes, err := os.ReadFile(networkKeysDir + "cks")
	if err != nil {
		fmt.Println("WARNING: file cks not found.")
		return
	}
	cks = C.deserialize_client_key(toBufferView(cksBytes))

	pksBytes, err := os.ReadFile(networkKeysDir + "pks")
	if err != nil {
		fmt.Println("WARNING: file pks not found.")
		return
	}
	pks = C.deserialize_compact_public_key(toBufferView(pksBytes))
}

// Represents a TFHE ciphertext type, i.e. its bit capacity.
type fheUintType uint8

const (
	FheUint8  fheUintType = 0
	FheUint16 fheUintType = 1
	FheUint32 fheUintType = 2
)

// Represents an expanded TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.
type tfheCiphertext struct {
	ptr           unsafe.Pointer
	serialization []byte
	hash          []byte
	value         *big.Int
	random        bool
	fheUintType   fheUintType
}

// Deserializes a TFHE ciphertext.
func (ct *tfheCiphertext) deserialize(in []byte, t fheUintType) error {
	if ct.initialized() {
		panic("cannot deserialize to an existing ciphertext")
	}
	var ptr unsafe.Pointer
	switch t {
	case FheUint8:
		ptr = C.deserialize_fhe_uint8(toBufferView((in)))
	case FheUint16:
		ptr = C.deserialize_fhe_uint16(toBufferView((in)))
	case FheUint32:
		ptr = C.deserialize_fhe_uint32(toBufferView((in)))
	}
	if ptr == nil {
		return errors.New("TFHE ciphertext deserialization failed")
	}
	ct.setPtr(ptr)
	ct.fheUintType = t
	ct.serialization = in
	return nil
}

// Deserializes a compact TFHE ciphetext.
// Note: After the compact thfe ciphertext has been serialized, subsequent calls to serialize()
// will produce non-compact ciphertext serialziations.
func (ct *tfheCiphertext) deserializeCompact(in []byte, t fheUintType) error {
	if ct.initialized() {
		panic("cannot deserialize to an existing ciphertext")
	}
	var ptr unsafe.Pointer
	switch t {
	case FheUint8:
		ptr = C.deserialize_compact_fhe_uint8(toBufferView((in)))
	case FheUint16:
		ptr = C.deserialize_compact_fhe_uint16(toBufferView((in)))
	case FheUint32:
		ptr = C.deserialize_compact_fhe_uint32(toBufferView((in)))
	}
	if ptr == nil {
		return errors.New("TFHE ciphertext deserialization failed")
	}
	ct.setPtr(ptr)
	ct.fheUintType = t
	ct.serialization = in
	return nil
}

// Encrypts a value as a TFHE ciphertext, using the compact public FHE key.
// The resulting ciphertext is automaticaly expanded.
func (ct *tfheCiphertext) encrypt(value big.Int, t fheUintType) *tfheCiphertext {
	if ct.initialized() {
		panic("cannot encrypt to an existing ciphertext")
	}

	switch t {
	case FheUint8:
		ct.setPtr(C.public_key_encrypt_fhe_uint8(pks, C.uint8_t(value.Uint64())))
	case FheUint16:
		ct.setPtr(C.public_key_encrypt_fhe_uint16(pks, C.uint16_t(value.Uint64())))
	case FheUint32:
		ct.setPtr(C.public_key_encrypt_fhe_uint32(pks, C.uint32_t(value.Uint64())))
	}
	ct.fheUintType = t
	ct.value = &value
	return ct
}

func (ct *tfheCiphertext) trivialEncrypt(value big.Int, t fheUintType) *tfheCiphertext {
	if ct.initialized() {
		panic("cannot encrypt to an existing ciphertext")
	}

	switch t {
	case FheUint8:
		ct.setPtr(C.trivial_encrypt_fhe_uint8(sks, C.uint8_t(value.Uint64())))
	case FheUint16:
		ct.setPtr(C.trivial_encrypt_fhe_uint16(sks, C.uint16_t(value.Uint64())))
	case FheUint32:
		ct.setPtr(C.trivial_encrypt_fhe_uint32(sks, C.uint32_t(value.Uint64())))
	}
	ct.fheUintType = t
	ct.value = &value
	return ct
}

func (ct *tfheCiphertext) makeRandom(t fheUintType) *tfheCiphertext {
	if ct.initialized() {
		panic("cannot make an existing ciphertext random")
	}
	ct.serialization = make([]byte, expandedFheCiphertextSize[t])
	rand.Read(ct.serialization)
	ct.fheUintType = t
	ct.random = true
	return ct
}

func (ct *tfheCiphertext) serialize() []byte {
	if !ct.initialized() {
		panic("cannot serialize a non-initialized ciphertext")
	} else if ct.serialization != nil {
		return ct.serialization
	}
	out := &C.Buffer{}
	switch ct.fheUintType {
	case FheUint8:
		C.serialize_fhe_uint8(ct.ptr, out)
	case FheUint16:
		C.serialize_fhe_uint16(ct.ptr, out)
	case FheUint32:
		C.serialize_fhe_uint32(ct.ptr, out)
	}
	ct.serialization = C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ct.serialization
}

func (lhs *tfheCiphertext) add(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot add on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.add_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.add_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.add_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) sub(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot sub on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.sub_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.sub_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.sub_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) mul(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot mul on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.mul_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.mul_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.mul_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) lte(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot lte on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.le_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.le_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.le_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) lt(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot lt on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.lt_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.lt_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.lt_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (ct *tfheCiphertext) decrypt() big.Int {
	if !ct.availableForOps() {
		panic("cannot decrypt a null ciphertext")
	} else if ct.value != nil {
		return *ct.value
	}
	var value uint64
	switch ct.fheUintType {
	case FheUint8:
		value = uint64(C.decrypt_fhe_uint8(cks, ct.ptr))
	case FheUint16:
		value = uint64(C.decrypt_fhe_uint16(cks, ct.ptr))
	case FheUint32:
		value = uint64(C.decrypt_fhe_uint32(cks, ct.ptr))
	}
	ct.value = new(big.Int).SetUint64(value)
	return *ct.value
}

func (ct *tfheCiphertext) setPtr(ptr unsafe.Pointer) {
	if ptr == nil {
		panic("setPtr called with nil")
	}
	ct.ptr = ptr
	atomic.AddUint64(&allocatedCiphertexts, 1)
	switch ct.fheUintType {
	case FheUint8:
		runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
			C.destroy_fhe_uint8(ct.ptr)
		})
	case FheUint16:
		runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
			C.destroy_fhe_uint16(ct.ptr)
		})
	case FheUint32:
		runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
			C.destroy_fhe_uint32(ct.ptr)
		})
	}
}

func (ct *tfheCiphertext) getHash() common.Hash {
	if !ct.initialized() {
		panic("cannot get hash of non-initialized ciphertext")
	}
	if ct.hash == nil {
		ct.hash = crypto.Keccak256(ct.serialize())
	}
	return common.BytesToHash(ct.hash)
}

func (ct *tfheCiphertext) availableForOps() bool {
	return (ct.initialized() && ct.ptr != nil && !ct.random)
}

func (ct *tfheCiphertext) initialized() bool {
	return (ct.ptr != nil || ct.random)
}

// Used for testing.
func encryptAndSerializeCompact(value uint32, fheUintType fheUintType) []byte {
	out := &C.Buffer{}
	switch fheUintType {
	case FheUint8:
		C.public_key_encrypt_and_serialize_fhe_uint8_list(pks, C.uint8_t(value), out)
	case FheUint16:
		C.public_key_encrypt_and_serialize_fhe_uint16_list(pks, C.uint16_t(value), out)
	case FheUint32:
		C.public_key_encrypt_and_serialize_fhe_uint32_list(pks, C.uint32_t(value), out)
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ser
}
