package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"
import (
	"fmt"
	"go/types"
	"math/big"
	"runtime"
	"syscall"
)

// Value types
type (
	cint   = C.int
	cbool  = C.bool
	cusize = C.size_t
	cu8    = C.uint8_t
	cu32   = C.uint32_t
	cu64   = C.uint64_t
	ci8    = C.int8_t
	ci32   = C.int32_t
	ci64   = C.int64_t
)

// Pointers
type (
	cu8_ptr = *C.uint8_t
)

func DeserializeServerKey(serverKeyBytes []byte) (bool, error) {

	sks := makeView(serverKeyBytes)
	defer runtime.KeepAlive(sks)

	errmsg := uninitializedUnmanagedVector()

	_, err := C.deserialize_server_key(sks, &errmsg)
	if err != nil {
		return false, errorWithMessage(err, errmsg)
	}
	return true, nil
}

func DeserializeClientKey(clientKeyBytes []byte) (bool, error) {

	clientKeyView := makeView(clientKeyBytes)
	defer runtime.KeepAlive(clientKeyView)

	errmsg := uninitializedUnmanagedVector()

	_, err := C.deserialize_client_key(clientKeyView, &errmsg)
	if err != nil {
		return false, errorWithMessage(err, errmsg)
	}
	return true, nil
}

func Encrypt(value big.Int, intType FheUintType) ([]byte, error) {
	val := value.Uint64()

	errmsg := uninitializedUnmanagedVector()

	res, err := C.client_key_encrypt_fhe_uint8(cu64(val), &errmsg)
	if err != nil {
		return nil, errorWithMessage(err, errmsg)
	}

	return copyAndDestroyUnmanagedVector(res), nil
}

//func (ct *TfheCiphertext) encrypt(value big.Int, t FheUintType) {

//func DecryptFheUint8(clientKeyBytes []byte, CipherText []byte) (uint8, error) {
//
//	cks := makeView(clientKeyBytes)
//	defer runtime.KeepAlive(cks)
//
//	ct := makeView(CipherText)
//	defer runtime.KeepAlive(ct)
//
//	errmsg := uninitializedUnmanagedVector()
//
//	res, err := C.decrypt_fhe_uint8(cks, ct)
//	if err != nil {
//		return 0, errorWithMessage(err, errmsg)
//	}
//	return uint8(res), nil
//}

/**** To error module ***/

func errorWithMessage(err error, b C.UnmanagedVector) error {
	// this checks for out of gas as a special case
	if errno, ok := err.(syscall.Errno); ok && int(errno) == 2 {
		return types.Error{}
	}
	msg := copyAndDestroyUnmanagedVector(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}
