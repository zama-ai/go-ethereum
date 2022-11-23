package vm

import (
	"github.com/ethereum/go-ethereum/common"
)

type PrecompileAccessibleState interface {
	GetStateDB() StateDB
	GetBlockContext() BlockContext
}

// StatefulPrecompiledContract is the interface for executing a precompiled contract
type StatefulPrecompiledContract interface {
	// RequiredGas computes the required gas for the given operation
	RequiredGas(input []byte) uint64
	// Run executes the precompiled contract.
	Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error)
}

// wrappedPrecompiledContract implements StatefulPrecompiledContract by wrapping stateless native precompiled contracts
// in Ethereum.
type wrappedPrecompiledContract struct {
	p PrecompiledContract
}

// RequiredGas implements the StatefulPrecompiledContract interface
func (w *wrappedPrecompiledContract) RequiredGas(input []byte) uint64 {
	return w.p.RequiredGas(input)
}

// Run implements the StatefulPrecompiledContract interface
func (w *wrappedPrecompiledContract) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	return RunPrecompiledContract(w.p, input, suppliedGas)
}

// newWrappedPrecompiledContract returns a wrapped version of [PrecompiledContract] to be executed according to the StatefulPrecompiledContract
// interface.
func newWrappedPrecompiledContract(p PrecompiledContract) StatefulPrecompiledContract {
	return &wrappedPrecompiledContract{p: p}
}

func RunStatefulPrecompiledContract(sp StatefulPrecompiledContract, accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	gasCost := sp.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	suppliedGas -= gasCost

	return sp.Run(accessibleState, caller, addr, input, suppliedGas, readOnly)
}

type fheAdd struct{}

func (e *fheAdd) RequiredGas(input []byte) uint64 {
	return 8
}

func (e *fheAdd) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	// state is editable here, e.g.
	// accessibleState.GetStateDB().SetNonce(caller, 233)
	// will change the caller's (contract that called this precompiled contract) to 233.

	return input, suppliedGas, nil
}

type setMemoryState struct{}

func (c *setMemoryState) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *setMemoryState) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	return []byte{}, suppliedGas, nil
}

type getMemoryState struct{}

func (c *getMemoryState) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *getMemoryState) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	return []byte{}, suppliedGas, nil
}
