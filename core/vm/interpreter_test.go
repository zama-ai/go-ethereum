// Copyright 2021 The go-ethereum Authors
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
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/params"
)

var loopInterruptTests = []string{
	// infinite loop using JUMP: push(2) jumpdest dup1 jump
	"60025b8056",
	// infinite loop using JUMPI: push(1) push(4) jumpdest dup2 dup2 jumpi
	"600160045b818157",
}

func TestLoopInterrupt(t *testing.T) {
	address := common.BytesToAddress([]byte("contract"))
	vmctx := BlockContext{
		Transfer: func(StateDB, common.Address, common.Address, *big.Int) {},
	}

	for i, tt := range loopInterruptTests {
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.CreateAccount(address)
		statedb.SetCode(address, common.Hex2Bytes(tt))
		statedb.Finalise(true)

		evm := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})

		errChannel := make(chan error)
		timeout := make(chan bool)

		go func(evm *EVM) {
			_, _, err := evm.Call(AccountRef(common.Address{}), address, nil, math.MaxUint64, new(big.Int))
			errChannel <- err
		}(evm)

		go func() {
			<-time.After(time.Second)
			timeout <- true
		}()

		evm.Cancel()

		select {
		case <-timeout:
			t.Errorf("test %d timed out", i)
		case err := <-errChannel:
			if err != nil {
				t.Errorf("test %d failure: %v", i, err)
			}
		}
	}

}

// Generates a contract that reverts immediately.
func newRevertingContract() *Contract {
	addr := AccountRef{}
	c := NewContract(addr, addr, big.NewInt(0), 100000)
	c.Code = make([]byte, 5)
	c.Code[0] = byte(PUSH1)
	c.Code[1] = byte(0)
	c.Code[2] = byte(PUSH1)
	c.Code[3] = byte(0)
	c.Code[4] = byte(REVERT)
	return c
}

func TestDepthRemovalOnRevert(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	evm := NewEVM(BlockContext{}, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})
	evm.depth = 1 // simulate first "call"

	contract := newRevertingContract()

	h := common.BytesToHash([]byte("1337"))

	verifiedCt := verifiedCiphertext{
		newDepthSet(),
		&tfheCiphertext{
			make([]byte, 0),
			&h,
			FheUint8,
		},
	}
	verifiedCt.verifiedDepths.add(1)
	verifiedCt.verifiedDepths.add(2) // simulate passing `h` as a call argument to `contract`

	evm.interpreter.verifiedCiphertexts[h] = &verifiedCt

	evm.interpreter.Run(contract, make([]byte, 0), false)

	resultingVerifiedDepths := evm.interpreter.verifiedCiphertexts[h].verifiedDepths
	if resultingVerifiedDepths.has(2) {
		t.Fatalf("verified depth should have been removed after revert")
	}
}
