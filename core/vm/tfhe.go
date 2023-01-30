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
	ShortintServerKey* sks = NULL;
	const int r = shortint_deserialize_server_key(in, &sks);
	assert(r == 0);
	return sks;
}

void* deserialize_client_key(BufferView in) {
	ShortintClientKey* cks = NULL;
	const int r = shortint_deserialize_client_key(in, &cks);
	assert(r == 0);
	return cks;
}

void* deserialize_tfhe_ciphertext(BufferView in) {
	ShortintCiphertext* ct = NULL;
	const int r = shortint_deserialize_ciphertext(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void serialize_tfhe_ciphertext(void *ct, Buffer* out) {
	const int r = shortint_serialize_ciphertext(ct, out);
	assert(r == 0);
}

void destroy_tfhe_ciphertext(void* ct) {
	destroy_shortint_ciphertext(ct);
}

void* tfhe_add(void* sks, void* ct1, void* ct2)
{
	ShortintCiphertext *result = NULL;
	const int r = shortint_bc_server_key_smart_add(sks, ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* tfhe_sub(void* sks, void* ct1, void* ct2)
{
	ShortintCiphertext *result = NULL;
	const int r = shortint_bc_server_key_smart_sub(sks, ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* tfhe_lte(void* sks, void* ct1, void* ct2)
{
	ShortintCiphertext *result = NULL;
	const int r = shortint_bc_server_key_smart_less_or_equal(sks, ct1, ct2, &result);
	assert(r == 0);
	return result;
}

uint64_t decrypt(void* cks, void* ct)
{
	uint64_t res = 0;
	const int r = shortint_bc_client_key_decrypt(cks, ct, &res);
	assert(r == 0);
	return res;
}

void client_key_encrypt_and_ser(void* cks, uint64_t value, Buffer* out) {
	ShortintCiphertext *ct = NULL;

	const int encrypt_ok = shortint_bc_client_key_encrypt(cks, value, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = shortint_serialize_ciphertext(ct, out);
	assert(ser_ok == 0);

	destroy_shortint_ciphertext(ct);
}

void* client_key_encrypt(void* cks, uint64_t value) {
	ShortintCiphertext *ct = NULL;

	const int r = shortint_bc_client_key_encrypt(cks, value, &ct);
  	assert(r == 0);

	return ct;
}

void public_key_encrypt(BufferView pks_buf, uint64_t value, Buffer* out)
{
	ShortintCiphertext *ct = NULL;
	ShortintPublicKey *pks = NULL;

	const int deser_ok = shortint_deserialize_public_key(pks_buf, &pks);
	assert(deser_ok == 0);

	const int encrypt_ok = shortint_bc_public_key_encrypt(pks, value, &ct);
  	assert(encrypt_ok == 0);

	const int ser_ok = shortint_serialize_ciphertext(ct, out);
	assert(ser_ok == 0);

	destroy_shortint_public_key(pks);
	destroy_shortint_ciphertext(ct);
}
*/
import "C"
import (
	"errors"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const ciphertextSize = 7008

func toBufferView(in []byte) C.BufferView {
	return C.BufferView{
		pointer: (*C.uchar)(unsafe.Pointer(&in[0])),
		length:  (C.ulong)(len(in)),
	}
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return home
}

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

	go runGc()
}

type tfheCiphertext struct {
	ptr           unsafe.Pointer
	serialization []byte
	hash          []byte
	value         *uint64
}

func (ct *tfheCiphertext) deserialize(in []byte) error {
	if ct.ptr != nil {
		panic("cannot deserialize to an existing ciphertext")
	}
	ptr := C.deserialize_tfhe_ciphertext(toBufferView((in)))
	if ptr == nil {
		return errors.New("tfhe ciphertext deserialization failed")
	}
	ct.setPtr(ptr)
	ct.serialization = in
	return nil
}

func (ct *tfheCiphertext) encrypt(value uint64) {
	if ct.ptr != nil {
		panic("cannot encrypt to an existing ciphertext")
	}
	ct.setPtr(C.client_key_encrypt(cks, C.ulong(value)))
	ct.value = &value
}

func (ct *tfheCiphertext) serialize() []byte {
	if ct.serialization != nil {
		return ct.serialization
	}
	if ct.ptr == nil {
		panic("cannot serialize a null ciphertext")
	}
	out := &C.Buffer{}
	C.serialize_tfhe_ciphertext(ct.ptr, out)
	ct.serialization = C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ct.serialization
}

func (lhs *tfheCiphertext) add(rhs *tfheCiphertext) *tfheCiphertext {
	if lhs.ptr == nil || rhs.ptr == nil {
		panic("cannot add on a null ciphertext")
	}
	res := new(tfheCiphertext)
	res.setPtr(C.tfhe_add(sks, lhs.ptr, rhs.ptr))
	return res
}

func (lhs *tfheCiphertext) sub(rhs *tfheCiphertext) *tfheCiphertext {
	if lhs.ptr == nil || rhs.ptr == nil {
		panic("cannot sub on a null ciphertext")
	}
	res := new(tfheCiphertext)
	res.setPtr(C.tfhe_sub(sks, lhs.ptr, rhs.ptr))
	return res
}

func (lhs *tfheCiphertext) lte(rhs *tfheCiphertext) *tfheCiphertext {
	if lhs.ptr == nil || rhs.ptr == nil {
		panic("cannot lte on a null ciphertext")
	}
	res := new(tfheCiphertext)
	res.setPtr(C.tfhe_lte(sks, lhs.ptr, rhs.ptr))
	return res
}

func (ct *tfheCiphertext) decrypt() uint64 {
	if ct.ptr == nil {
		panic("cannot decrypt a null ciphertext")
	}
	if ct.value != nil {
		return *ct.value
	}
	value := uint64(C.decrypt(cks, ct.ptr))
	ct.value = &value
	return value
}

func (ct *tfheCiphertext) setPtr(ptr unsafe.Pointer) {
	if ptr == nil {
		panic("setPtr called with nil")
	}
	ct.ptr = ptr
	atomic.AddUint64(&allocatedCiphertexts, 1)
	runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
		C.destroy_tfhe_ciphertext(ct.ptr)
	})
}

func (ct *tfheCiphertext) getHash() common.Hash {
	if ct.ptr == nil {
		panic("cannot get hash of a null ciphertext")
	}
	if ct.hash == nil {
		ct.hash = crypto.Keccak256(ct.serialize())
	}
	return common.BytesToHash(ct.hash)
}

func clientKeyEncrypt(value uint64) []byte {
	out := &C.Buffer{}
	C.client_key_encrypt_and_ser(cks, C.ulong(value), out)
	result := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return result
}

func publicKeyEncrypt(pks []byte, value uint64) []byte {
	out := &C.Buffer{}
	C.public_key_encrypt(toBufferView(pks), C.ulong(value), out)
	result := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return result
}
