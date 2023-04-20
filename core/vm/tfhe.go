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

void tfhe_set_server_key(void *sks) {
	int r = set_server_key(sks);
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

void destroy_fhe_uint8(void* ct) {
	fhe_uint8_destroy(ct);
}

void destroy_fhe_uint16(void* ct) {
	fhe_uint16_destroy(ct);
}

void destroy_fhe_uint32(void* ct) {
	fhe_uint32_destroy(ct);
}

void* add_fhe_uint8(void* ct1, void* ct2)
{
	FheUint8* result = NULL;
	const int r = fhe_uint8_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* add_fhe_uint16(void* ct1, void* ct2)
{
	FheUint16* result = NULL;
	const int r = fhe_uint16_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* add_fhe_uint32(void* ct1, void* ct2)
{
	FheUint32* result = NULL;
	const int r = fhe_uint32_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint8(void* ct1, void* ct2)
{
	FheUint8* result = NULL;
	const int r = fhe_uint8_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint16(void* ct1, void* ct2)
{
	FheUint16* result = NULL;
	const int r = fhe_uint16_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint32(void* ct1, void* ct2)
{
	FheUint32* result = NULL;
	const int r = fhe_uint32_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint8(void* ct1, void* ct2)
{
	FheUint8* result = NULL;
	const int r = fhe_uint8_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint16(void* ct1, void* ct2)
{
	FheUint16* result = NULL;
	const int r = fhe_uint16_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint32(void* ct1, void* ct2)
{
	FheUint32* result = NULL;
	const int r = fhe_uint32_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint8(void* ct1, void* ct2)
{
	FheUint8* result = NULL;
	const int r = fhe_uint8_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint16(void* ct1, void* ct2)
{
	FheUint16* result = NULL;
	const int r = fhe_uint16_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint32(void* ct1, void* ct2)
{
	FheUint32* result = NULL;
	const int r = fhe_uint32_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint8(void* ct1, void* ct2)
{
	FheUint8* result = NULL;
	const int r = fhe_uint8_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint16(void* ct1, void* ct2)
{
	FheUint16* result = NULL;
	const int r = fhe_uint16_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint32(void* ct1, void* ct2)
{
	FheUint32* result = NULL;
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

void client_key_encrypt_and_ser_fhe_uint8(void* cks, uint8_t value, Buffer* out) {
	FheUint8* ct = NULL;

	const int encrypt_ok = fhe_uint8_try_encrypt_with_client_key_u8(value, cks, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = fhe_uint8_serialize(ct, out);
	assert(ser_ok == 0);

	fhe_uint8_destroy(ct);
}

void client_key_encrypt_and_ser_fhe_uint16(void* cks, uint16_t value, Buffer* out) {
	FheUint16* ct = NULL;

	const int encrypt_ok = fhe_uint16_try_encrypt_with_client_key_u16(value, cks, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = fhe_uint16_serialize(ct, out);
	assert(ser_ok == 0);

	fhe_uint16_destroy(ct);
}

void client_key_encrypt_and_ser_fhe_uint32(void* cks, uint32_t value, Buffer* out) {
	FheUint32* ct = NULL;

	const int encrypt_ok = fhe_uint32_try_encrypt_with_client_key_u32(value, cks, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = fhe_uint32_serialize(ct, out);
	assert(ser_ok == 0);

	fhe_uint32_destroy(ct);
}

void* client_key_encrypt_fhe_uint8(void* cks, uint8_t value) {
	FheUint8* ct = NULL;

	const int r = fhe_uint8_try_encrypt_with_client_key_u8(value, cks, &ct);
  	assert(r == 0);

	return ct;
}

void* client_key_encrypt_fhe_uint16(void* cks, uint16_t value) {
	FheUint16* ct = NULL;

	const int r = fhe_uint16_try_encrypt_with_client_key_u16(value, cks, &ct);
  	assert(r == 0);

	return ct;
}

void* client_key_encrypt_fhe_uint32(void* cks, uint32_t value) {
	FheUint32* ct = NULL;

	const int r = fhe_uint32_try_encrypt_with_client_key_u32(value, cks, &ct);
  	assert(r == 0);

	return ct;
}

void public_key_encrypt_fhe_uint8(BufferView pks_buf, uint8_t value, Buffer* out)
{
	FheUint8 *ct = NULL;
	PublicKey *pks = NULL;

	const int deser_ok = public_key_deserialize(pks_buf, &pks);
	assert(deser_ok == 0);

	const int encrypt_ok = fhe_uint8_try_encrypt_with_public_key_u8(value, pks, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = fhe_uint8_serialize(ct, out);
	assert(ser_ok == 0);

	public_key_destroy(pks);
	fhe_uint8_destroy(ct);
}

void public_key_encrypt_fhe_uint16(BufferView pks_buf, uint16_t value, Buffer* out)
{
	FheUint16 *ct = NULL;
	PublicKey *pks = NULL;

	const int deser_ok = public_key_deserialize(pks_buf, &pks);
	assert(deser_ok == 0);

	const int encrypt_ok = fhe_uint16_try_encrypt_with_public_key_u16(value, pks, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = fhe_uint16_serialize(ct, out);
	assert(ser_ok == 0);

	public_key_destroy(pks);
	fhe_uint16_destroy(ct);
}

void public_key_encrypt_fhe_uint32(BufferView pks_buf, uint32_t value, Buffer* out)
{
	FheUint32 *ct = NULL;
	PublicKey *pks = NULL;

	const int deser_ok = public_key_deserialize(pks_buf, &pks);
	assert(deser_ok == 0);

	const int encrypt_ok = fhe_uint32_try_encrypt_with_public_key_u32(value, pks, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = fhe_uint32_serialize(ct, out);
	assert(ser_ok == 0);

	public_key_destroy(pks);
	fhe_uint32_destroy(ct);
}
*/
import "C"

// TODO trivial encrypt

import (
	"crypto/rand"
	"errors"
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

// The TFHE ciphertext size, in bytes.
var fheCiphertextSize map[fheUintType]uint

var sks unsafe.Pointer
var cks unsafe.Pointer
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
	home := homeDir()
	networkKeysDir = home + "/.evmosd/zama/keys/network-fhe-keys/"
	usersKeysDir = home + "/.evmosd/zama/keys/users-fhe-keys/"

	sks_bytes, err := os.ReadFile(networkKeysDir + "sks")
	if err != nil {
		return
	}

	cks_bytes, err := os.ReadFile(networkKeysDir + "cks")
	if err != nil {
		return
	}

	sks = C.deserialize_server_key(toBufferView(sks_bytes))
	cks = C.deserialize_client_key(toBufferView(cks_bytes))

	// Cannot use trivial encryption yet as it is not exposed by tfhe-rs
	// ct := new(tfheCiphertext)
	// ct.trivialEncrypt(1)
	// fheCiphertextSize = len(ct.serialize())

	fheCiphertextSize = make(map[fheUintType]uint)

	fheCiphertextSize[FheUint8] = 28124
	fheCiphertextSize[FheUint16] = 56236
	fheCiphertextSize[FheUint32] = 112460

	// TODO: understand when and how to set the server key
	// C.tfhe_set_server_key(sks)

	go runGc()
}

// Represents a TFHE ciphertext type (i.e., its bit capacity)

type fheUintType uint8

const (
	FheUint8  fheUintType = 0
	FheUint16 fheUintType = 1
	FheUint32 fheUintType = 2
)

// Represents a TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.
type tfheCiphertext struct {
	ptr           unsafe.Pointer
	serialization []byte
	hash          []byte
	value         *uint64
	random        bool
	fheUintType   fheUintType
}

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
		return errors.New("tfhe ciphertext deserialization failed")
	}
	ct.setPtr(ptr)
	ct.serialization = in
	return nil
}

func (ct *tfheCiphertext) encrypt(value uint64, t fheUintType) {
	if ct.initialized() {
		panic("cannot encrypt to an existing ciphertext")
	}
	switch t {
	case FheUint8:
		ct.setPtr(C.client_key_encrypt_fhe_uint8(cks, C.uchar(value)))
	case FheUint16:
		ct.setPtr(C.client_key_encrypt_fhe_uint16(cks, C.ushort(value)))
	case FheUint32:
		ct.setPtr(C.client_key_encrypt_fhe_uint32(cks, C.uint(value)))
	}
	ct.value = &value
}

func (ct *tfheCiphertext) makeRandom(t fheUintType) {
	if ct.initialized() {
		panic("cannot make an existing ciphertext random")
	}
	ct.serialization = make([]byte, fheCiphertextSize[t])
	rand.Read(ct.serialization)
	ct.fheUintType = t
	ct.random = true
}

// func (ct *tfheCiphertext) trivialEncrypt(value uint64) {
// 	if ct.initialized() {
// 		panic("cannot trivially encrypt to an existing ciphertext")
// 	}
// 	ct.setPtr(C.trivial_encrypt(sks, C.ulong(value)))
// 	ct.value = &value
// }

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

func (lhs *tfheCiphertext) add(rhs *tfheCiphertext) *tfheCiphertext {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot add on a non-initialized ciphertext")
	}
	C.tfhe_set_server_key(sks)
	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.add_fhe_uint8(lhs.ptr, rhs.ptr))
	case FheUint16:
		res.setPtr(C.add_fhe_uint16(lhs.ptr, rhs.ptr))
	case FheUint32:
		res.setPtr(C.add_fhe_uint32(lhs.ptr, rhs.ptr))
	}
	return res
}

func (lhs *tfheCiphertext) sub(rhs *tfheCiphertext) *tfheCiphertext {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot sub on a non-initialized ciphertext")
	}
	C.tfhe_set_server_key(sks)
	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.sub_fhe_uint8(lhs.ptr, rhs.ptr))
	case FheUint16:
		res.setPtr(C.sub_fhe_uint16(lhs.ptr, rhs.ptr))
	case FheUint32:
		res.setPtr(C.sub_fhe_uint32(lhs.ptr, rhs.ptr))
	}
	return res
}

func (lhs *tfheCiphertext) mul(rhs *tfheCiphertext) *tfheCiphertext {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot mul on a non-initialized ciphertext")
	}
	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.mul_fhe_uint8(lhs.ptr, rhs.ptr))
	case FheUint16:
		res.setPtr(C.mul_fhe_uint16(lhs.ptr, rhs.ptr))
	case FheUint32:
		res.setPtr(C.mul_fhe_uint32(lhs.ptr, rhs.ptr))
	}
	return res
}

func (lhs *tfheCiphertext) lte(rhs *tfheCiphertext) *tfheCiphertext {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot lte on a non-initialized ciphertext")
	}
	C.tfhe_set_server_key(sks)
	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.le_fhe_uint8(lhs.ptr, rhs.ptr))
	case FheUint16:
		res.setPtr(C.le_fhe_uint16(lhs.ptr, rhs.ptr))
	case FheUint32:
		res.setPtr(C.le_fhe_uint32(lhs.ptr, rhs.ptr))
	}
	return res
}

func (lhs *tfheCiphertext) lt(rhs *tfheCiphertext) *tfheCiphertext {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot lt on a non-initialized ciphertext")
	}
	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.lt_fhe_uint8(lhs.ptr, rhs.ptr))
	case FheUint16:
		res.setPtr(C.lt_fhe_uint16(lhs.ptr, rhs.ptr))
	case FheUint32:
		res.setPtr(C.lt_fhe_uint32(lhs.ptr, rhs.ptr))
	}
	return res
}

func (ct *tfheCiphertext) decrypt() uint64 {
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
	ct.value = &value
	return value
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
	runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
		C.destroy_fhe_uint8(ct.ptr)
	})
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

func clientKeyEncrypt(value uint64, t fheUintType) []byte {
	out := &C.Buffer{}
	switch t {
	case FheUint8:
		C.client_key_encrypt_and_ser_fhe_uint8(cks, C.uchar(value), out)
	case FheUint16:
		C.client_key_encrypt_and_ser_fhe_uint16(cks, C.ushort(value), out)
	case FheUint32:
		C.client_key_encrypt_and_ser_fhe_uint32(cks, C.uint(value), out)
	}
	result := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return result
}

func publicKeyEncrypt(pks []byte, value uint64, t fheUintType) []byte {
	out := &C.Buffer{}
	switch t {
	case FheUint8:
		C.public_key_encrypt_fhe_uint8(toBufferView(pks), C.uchar(value), out)
	case FheUint16:
		C.public_key_encrypt_fhe_uint16(toBufferView(pks), C.ushort(value), out)
	case FheUint32:
		C.public_key_encrypt_fhe_uint32(toBufferView(pks), C.uint(value), out)
	}
	result := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return result
}
