package tfhe

import (
	"fmt"
	"github.com/ethereum/go-ethereum/tfhe/internal/api"
	"math/big"
)

type Ciphertext struct {
	//ptr           unsafe.Pointer
	Serialization []byte
	hash          []byte
	value         *big.Int
	random        bool
	fheUintType   UintType
}

func NewCipherText(value big.Int, t api.FheUintType) (*Ciphertext, error) {

	res, err := api.Encrypt(value, 0)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

//func NewCipherTextWithKey(value big.Int, sks []byte, t api.FheUintType) (*Ciphertext, error) {
//
//	res, err := api.Encrypt(value, 0)
//	if err != nil {
//		return nil, err
//	}
//
//	return &Ciphertext{
//		Serialization: res,
//	}, nil
//}

func (lhs *Ciphertext) Add(rhs *Ciphertext) (*Ciphertext, error) {

	if lhs.fheUintType != rhs.fheUintType {
		return nil, fmt.Errorf("cannot add uints of different types")
	}

	res, err := api.Add(lhs.Serialization, rhs.Serialization, uint8(lhs.fheUintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (lhs *Ciphertext) Sub(rhs *Ciphertext) (*Ciphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, fmt.Errorf("cannot subtract uints of different types")
	}

	res, err := api.Sub(lhs.Serialization, rhs.Serialization, uint8(lhs.fheUintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (lhs *Ciphertext) Mul(rhs *Ciphertext) (*Ciphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, fmt.Errorf("cannot multiply uints of different types")
	}

	res, err := api.Mul(lhs.Serialization, rhs.Serialization, uint8(lhs.fheUintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (lhs *Ciphertext) Lt(rhs *Ciphertext) (*Ciphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, fmt.Errorf("cannot compare uints of different types")
	}

	res, err := api.Lt(lhs.Serialization, rhs.Serialization, uint8(lhs.fheUintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}

func (lhs *Ciphertext) Lte(rhs *Ciphertext) (*Ciphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, fmt.Errorf("cannot compare uints of different types")
	}

	res, err := api.Lte(lhs.Serialization, rhs.Serialization, uint8(lhs.fheUintType))
	if err != nil {
		return nil, err
	}

	return &Ciphertext{
		Serialization: res,
	}, nil
}
