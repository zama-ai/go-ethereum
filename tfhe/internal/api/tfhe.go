package api

import (
	"math/big"
)

// import "C"
// import (
//
//	"crypto/rand"
//	"errors"
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/crypto"
//	"math/big"
//	"runtime"
//	"sync/atomic"
//	"unsafe"
//
// )
//
//	func toBufferView(in []byte) C.BufferView {
//		return C.BufferView{
//			pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
//			length:  (C.size_t)(len(in)),
//		}
//	}
//
// //func homeDir() string {
// //	home, err := os.UserHomeDir()
// //	if err != nil {
// //		panic(err)
// //	}
// //	return home
// //}
//
// // The TFHE ciphertext size, in bytes.
// var fheCiphertextSize map[FheUintType]uint
//
// var sks unsafe.Pointer
// var cks unsafe.Pointer
// var networkKeysDir string
// var usersKeysDir string
//
// var allocatedCiphertexts uint64
//
// // TODO: We assume that contracts.go's init() runs before the init() in this file,
// // making the TOML configuration available here.
// //func runGc() {
// //	for range time.Tick(time.Duration(tomlConfig.Tfhe.CiphertextsGarbageCollectIntervalSecs) * time.Second) {
// //		if atomic.LoadUint64(&allocatedCiphertexts) >= tomlConfig.Tfhe.CiphertextsToGarbageCollect {
// //			atomic.StoreUint64(&allocatedCiphertexts, 0)
// //			runtime.GC()
// //		}
// //	}
// //}
//
// //func init() {
// //	fheCiphertextSize = make(map[FheUintType]uint)
// //
// //	fheCiphertextSize[FheUint8] = 28124
// //	fheCiphertextSize[FheUint16] = 56236
// //	fheCiphertextSize[FheUint32] = 112460
// //
// //	go runGc()
// //
// //	home := homeDir()
// //	networkKeysDir = home + "/.evmosd/zama/keys/network-fhe-keys/"
// //	usersKeysDir = home + "/.evmosd/zama/keys/users-fhe-keys/"
// //
// //	sksBytes, err := os.ReadFile(networkKeysDir + "sks")
// //	if err != nil {
// //		fmt.Print("WARNING: file sks not found.\n")
// //		return
// //	}
// //	sks = C.deserialize_server_key(toBufferView(sksBytes))
// //
// //	cksBytes, err := os.ReadFile(networkKeysDir + "cks")
// //	if err != nil {
// //		fmt.Print("WARNING: file cks not found.\n")
// //		return
// //	}
// //	cks = C.deserialize_client_key(toBufferView(cksBytes))
// //
// //	// Cannot use trivial encryption yet as it is not exposed by tfhe-rs
// //	// ct := new(TfheCiphertext)
// //	// ct.trivialEncrypt(1)
// //	// fheCiphertextSize = len(ct.serialize())
// //}
//
// // Represents a TFHE ciphertext type (i.e., its bit capacity)
type FheUintType uint8

const (
	FheUint8  FheUintType = 0
	FheUint16 FheUintType = 1
	FheUint32 FheUintType = 2
)

// // Represents a TFHE ciphertext.
// //
// // Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// // it must not be set another value. If that is needed, a new ciphertext must be created.
type TfheCiphertext struct {
	// ptr           unsafe.Pointer
	serialization []byte
	hash          []byte
	value         *big.Int
	random        bool
	fheUintType   FheUintType
}

//
//func (ct *TfheCiphertext) deserialize(in []byte, t FheUintType) error {
//	if ct.initialized() {
//		panic("cannot deserialize to an existing ciphertext")
//	}
//	var ptr unsafe.Pointer
//	switch t {
//	case FheUint8:
//		ptr = C.deserialize_fhe_uint8(toBufferView((in)))
//	case FheUint16:
//		ptr = C.deserialize_fhe_uint16(toBufferView((in)))
//	case FheUint32:
//		ptr = C.deserialize_fhe_uint32(toBufferView((in)))
//	}
//	if ptr == nil {
//		return errors.New("tfhe ciphertext deserialization failed")
//	}
//	ct.setPtr(ptr)
//	ct.fheUintType = t
//	ct.serialization = in
//	return nil
//}
//
//func (ct *TfheCiphertext) encrypt(value big.Int, t FheUintType) {
//	if ct.initialized() {
//		panic("cannot encrypt to an existing ciphertext")
//	}
//
//	switch t {
//	case FheUint8:
//		ct.setPtr(C.client_key_encrypt_fhe_uint8(cks, C.uchar(value.Uint64())))
//	case FheUint16:
//		ct.setPtr(C.client_key_encrypt_fhe_uint16(cks, C.ushort(value.Uint64())))
//	case FheUint32:
//		ct.setPtr(C.client_key_encrypt_fhe_uint32(cks, C.uint(value.Uint64())))
//	}
//	ct.fheUintType = t
//	ct.value = &value
//}
//
//func (ct *TfheCiphertext) makeRandom(t FheUintType) {
//	if ct.initialized() {
//		panic("cannot make an existing ciphertext random")
//	}
//	ct.serialization = make([]byte, fheCiphertextSize[t])
//	rand.Read(ct.serialization)
//	ct.fheUintType = t
//	ct.random = true
//}
//
//// func (ct *TfheCiphertext) trivialEncrypt(value uint64) {
//// 	if ct.initialized() {
//// 		panic("cannot trivially encrypt to an existing ciphertext")
//// 	}
//// 	ct.setPtr(C.trivial_encrypt(sks, C.ulong(value)))
//// 	ct.value = &value
//// }
//
//func SerializeCipherText(ct *TfheCiphertext) []byte {
//	if !ct.initialized() {
//		panic("cannot serialize a non-initialized ciphertext")
//	} else if ct.serialization != nil {
//		return ct.serialization
//	}
//	out := &C.Buffer{}
//	switch ct.fheUintType {
//	case FheUint8:
//		C.serialize_fhe_uint8(ct.ptr, out)
//	case FheUint16:
//		C.serialize_fhe_uint16(ct.ptr, out)
//	case FheUint32:
//		C.serialize_fhe_uint32(ct.ptr, out)
//	}
//	ct.serialization = C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
//	C.destroy_buffer(out)
//	return ct.serialization
//}
//
//func (lhs *TfheCiphertext) add(rhs *TfheCiphertext) (*TfheCiphertext, error) {
//	if !lhs.availableForOps() || !rhs.availableForOps() {
//		panic("cannot add on a non-initialized ciphertext")
//	}
//
//	if lhs.fheUintType != rhs.fheUintType {
//		return nil, errors.New("binary operations are only well-defined for identical types")
//	}
//
//	res := new(TfheCiphertext)
//	res.fheUintType = lhs.fheUintType
//	switch lhs.fheUintType {
//	case FheUint8:
//		res.setPtr(C.add_fhe_uint8(lhs.ptr, rhs.ptr, sks))
//	case FheUint16:
//		res.setPtr(C.add_fhe_uint16(lhs.ptr, rhs.ptr, sks))
//	case FheUint32:
//		res.setPtr(C.add_fhe_uint32(lhs.ptr, rhs.ptr, sks))
//	}
//	return res, nil
//}
//
//func (lhs *TfheCiphertext) sub(rhs *TfheCiphertext) (*TfheCiphertext, error) {
//	if !lhs.availableForOps() || !rhs.availableForOps() {
//		panic("cannot sub on a non-initialized ciphertext")
//	}
//
//	if lhs.fheUintType != rhs.fheUintType {
//		return nil, errors.New("binary operations are only well-defined for identical types")
//	}
//
//	res := new(TfheCiphertext)
//	res.fheUintType = lhs.fheUintType
//	switch lhs.fheUintType {
//	case FheUint8:
//		res.setPtr(C.sub_fhe_uint8(lhs.ptr, rhs.ptr, sks))
//	case FheUint16:
//		res.setPtr(C.sub_fhe_uint16(lhs.ptr, rhs.ptr, sks))
//	case FheUint32:
//		res.setPtr(C.sub_fhe_uint32(lhs.ptr, rhs.ptr, sks))
//	}
//	return res, nil
//}
//
//func (lhs *TfheCiphertext) mul(rhs *TfheCiphertext) (*TfheCiphertext, error) {
//	if !lhs.availableForOps() || !rhs.availableForOps() {
//		panic("cannot mul on a non-initialized ciphertext")
//	}
//
//	if lhs.fheUintType != rhs.fheUintType {
//		return nil, errors.New("binary operations are only well-defined for identical types")
//	}
//
//	res := new(TfheCiphertext)
//	res.fheUintType = lhs.fheUintType
//	switch lhs.fheUintType {
//	case FheUint8:
//		res.setPtr(C.mul_fhe_uint8(lhs.ptr, rhs.ptr, sks))
//	case FheUint16:
//		res.setPtr(C.mul_fhe_uint16(lhs.ptr, rhs.ptr, sks))
//	case FheUint32:
//		res.setPtr(C.mul_fhe_uint32(lhs.ptr, rhs.ptr, sks))
//	}
//	return res, nil
//}
//
//func (lhs *TfheCiphertext) lte(rhs *TfheCiphertext) (*TfheCiphertext, error) {
//	if !lhs.availableForOps() || !rhs.availableForOps() {
//		panic("cannot lte on a non-initialized ciphertext")
//	}
//
//	if lhs.fheUintType != rhs.fheUintType {
//		return nil, errors.New("binary operations are only well-defined for identical types")
//	}
//
//	res := new(TfheCiphertext)
//	res.fheUintType = lhs.fheUintType
//	switch lhs.fheUintType {
//	case FheUint8:
//		res.setPtr(C.le_fhe_uint8(lhs.ptr, rhs.ptr, sks))
//	case FheUint16:
//		res.setPtr(C.le_fhe_uint16(lhs.ptr, rhs.ptr, sks))
//	case FheUint32:
//		res.setPtr(C.le_fhe_uint32(lhs.ptr, rhs.ptr, sks))
//	}
//	return res, nil
//}
//
//func (lhs *TfheCiphertext) lt(rhs *TfheCiphertext) (*TfheCiphertext, error) {
//	if !lhs.availableForOps() || !rhs.availableForOps() {
//		panic("cannot lt on a non-initialized ciphertext")
//	}
//
//	if lhs.fheUintType != rhs.fheUintType {
//		return nil, errors.New("binary operations are only well-defined for identical types")
//	}
//
//	res := new(TfheCiphertext)
//	res.fheUintType = lhs.fheUintType
//	switch lhs.fheUintType {
//	case FheUint8:
//		res.setPtr(C.lt_fhe_uint8(lhs.ptr, rhs.ptr, sks))
//	case FheUint16:
//		res.setPtr(C.lt_fhe_uint16(lhs.ptr, rhs.ptr, sks))
//	case FheUint32:
//		res.setPtr(C.lt_fhe_uint32(lhs.ptr, rhs.ptr, sks))
//	}
//	return res, nil
//}
//
//func (ct *TfheCiphertext) decrypt() big.Int {
//	if !ct.availableForOps() {
//		panic("cannot decrypt a null ciphertext")
//	} else if ct.value != nil {
//		return *ct.value
//	}
//	var value uint64
//	switch ct.fheUintType {
//	case FheUint8:
//		value = uint64(C.decrypt_fhe_uint8(cks, ct.ptr))
//	case FheUint16:
//		value = uint64(C.decrypt_fhe_uint16(cks, ct.ptr))
//	case FheUint32:
//		value = uint64(C.decrypt_fhe_uint32(cks, ct.ptr))
//	}
//	ct.value = new(big.Int).SetUint64(value)
//	return *ct.value
//}
//
//func (ct *TfheCiphertext) setPtr(ptr unsafe.Pointer) {
//	if ptr == nil {
//		panic("setPtr called with nil")
//	}
//	ct.ptr = ptr
//	atomic.AddUint64(&allocatedCiphertexts, 1)
//	switch ct.fheUintType {
//	case FheUint8:
//		runtime.SetFinalizer(ct, func(ct *TfheCiphertext) {
//			C.destroy_fhe_uint8(ct.ptr)
//		})
//	case FheUint16:
//		runtime.SetFinalizer(ct, func(ct *TfheCiphertext) {
//			C.destroy_fhe_uint16(ct.ptr)
//		})
//	case FheUint32:
//		runtime.SetFinalizer(ct, func(ct *TfheCiphertext) {
//			C.destroy_fhe_uint32(ct.ptr)
//		})
//	}
//}
//
//func (ct *TfheCiphertext) getHash() common.Hash {
//	if !ct.initialized() {
//		panic("cannot get hash of non-initialized ciphertext")
//	}
//	if ct.hash == nil {
//		ct.hash = crypto.Keccak256(ct.serialize())
//	}
//	return common.BytesToHash(ct.hash)
//}
//
//func (ct *TfheCiphertext) availableForOps() bool {
//	return (ct.initialized() && ct.ptr != nil && !ct.random)
//}
//
//func (ct *TfheCiphertext) initialized() bool {
//	return (ct.ptr != nil || ct.random)
//}
//
//func clientKeyEncrypt(value uint64, t FheUintType) []byte {
//	out := &C.Buffer{}
//	switch t {
//	case FheUint8:
//		C.client_key_encrypt_and_ser_fhe_uint8(cks, C.uchar(value), out)
//	case FheUint16:
//		C.client_key_encrypt_and_ser_fhe_uint16(cks, C.ushort(value), out)
//	case FheUint32:
//		C.client_key_encrypt_and_ser_fhe_uint32(cks, C.uint(value), out)
//	}
//	result := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
//	C.destroy_buffer(out)
//	return result
//}
//
//func publicKeyEncrypt(pks []byte, value uint64, t FheUintType) []byte {
//	out := &C.Buffer{}
//	switch t {
//	case FheUint8:
//		C.public_key_encrypt_fhe_uint8(toBufferView(pks), C.uchar(value), out)
//	case FheUint16:
//		C.public_key_encrypt_fhe_uint16(toBufferView(pks), C.ushort(value), out)
//	case FheUint32:
//		C.public_key_encrypt_fhe_uint32(toBufferView(pks), C.uint(value), out)
//	}
//	result := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
//	C.destroy_buffer(out)
//	return result
//}
