//go:build cgo

package tfhe

import (
	"github.com/ethereum/go-ethereum/tfhe/internal/api"
	"math/big"
)

type FheUintType uint8

const (
	FheUint8  FheUintType = 0
	FheUint16 FheUintType = 1
	FheUint32 FheUintType = 2
)

// Represents a TFHE ciphertext.
//
// Once a ciphertext has a value (either from deserialization, encryption or makeRandom()),
// it must not be set another value. If that is needed, a new ciphertext must be created.
type TfheCiphertext struct {
	//ptr           unsafe.Pointer
	Serialization []byte
	hash          []byte
	value         *big.Int
	random        bool
	fheUintType   FheUintType
}

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

func (lhs *TfheCiphertext) add(rhs *api.TfheCiphertext) (*TfheCiphertext, error) {
	return nil, nil

}

func (lhs *TfheCiphertext) sub(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return nil, nil

}

func (lhs *TfheCiphertext) mul(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return nil, nil
}

func (lhs *TfheCiphertext) lt(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs, nil
}

func (lhs *TfheCiphertext) lte(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return nil, nil
}

func FheEncrypt(value big.Int, t api.FheUintType) (*TfheCiphertext, error) {

	res, err := api.Encrypt(value, 0)
	if err != nil {
		return nil, err
	}

	return &TfheCiphertext{
		Serialization: res,
	}, nil
}

func (lhs *TfheCiphertext) makeRandom(t api.FheUintType) {

}

//func (lhs *TfheCiphertext) serialize() []byte {
//	return api.SerializeCipherText(lhs)
//}

func publicKeyEncrypt(pks []byte, value uint64, t api.FheUintType) []byte {
	return nil
}

func Version() (string, error) {
	version, err := api.LibTfheVersion()

	return version, err
}
