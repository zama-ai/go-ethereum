//go:build cgo

package tfhe

import (
	"github.com/ethereum/go-ethereum/tfhe/internal/api"
)

type UintType uint8

const (
	Uint8  UintType = 0
	Uint16 UintType = 1
	Uint32 UintType = 2
)

// Represents a TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.
// todo (Itzik): Testing whether or not passing the serialized data and not the raw pointer.
// Obviously it will come at a performance cost, but possibly the security/clarity of the code during the
// early days could be worth it? For the part seems serialization of FHEu8 is about 20us

// Represents a TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.

func LoadClientKey(clientKeyBytes []byte) (bool, error) {
	return api.DeserializeClientKey(clientKeyBytes)
}

func LoadServerKey(serverKeyBytes []byte) (bool, error) {
	return api.DeserializeServerKey(serverKeyBytes)
}

func (lhs *Ciphertext) makeRandom(t api.FheUintType) {

}

func publicKeyEncrypt(pks []byte, value uint64, t api.FheUintType) []byte {
	return nil
}

func Version() (string, error) {
	version, err := api.LibTfheVersion()

	return version, err
}
