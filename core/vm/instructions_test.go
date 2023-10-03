// Copyright 2017 The go-ethereum Authors
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
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type TwoOperandTestcase struct {
	X        string
	Y        string
	Expected string
}

type twoOperandParams struct {
	x string
	y string
}

var alphabetSoup = "ABCDEF090807060504030201ffffffffffffffffffffffffffffffffffffffff"
var commonParams []*twoOperandParams
var twoOpMethods map[string]executionFunc

func init() {

	// Params is a list of common edgecases that should be used for some common tests
	params := []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		"0000000000000000000000000000000000000000000000000000000000000001", // +1
		"0000000000000000000000000000000000000000000000000000000000000005", // +5
		"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe", // + max -1
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // + max
		"8000000000000000000000000000000000000000000000000000000000000000", // - max
		"8000000000000000000000000000000000000000000000000000000000000001", // - max+1
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb", // - 5
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // - 1
	}
	// Params are combined so each param is used on each 'side'
	commonParams = make([]*twoOperandParams, len(params)*len(params))
	for i, x := range params {
		for j, y := range params {
			commonParams[i*len(params)+j] = &twoOperandParams{x, y}
		}
	}
	twoOpMethods = map[string]executionFunc{
		"add":     opAdd,
		"sub":     opSub,
		"mul":     opMul,
		"div":     opDiv,
		"sdiv":    opSdiv,
		"mod":     opMod,
		"smod":    opSmod,
		"exp":     opExp,
		"signext": opSignExtend,
		"lt":      opLt,
		"gt":      opGt,
		"slt":     opSlt,
		"sgt":     opSgt,
		"eq":      opEq,
		"and":     opAnd,
		"or":      opOr,
		"xor":     opXor,
		"byte":    opByte,
		"shl":     opSHL,
		"shr":     opSHR,
		"sar":     opSAR,
	}
}

func testTwoOperandOp(t *testing.T, tests []TwoOperandTestcase, opFn executionFunc, name string) {

	var (
		env            = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		stack          = newstack()
		pc             = uint64(0)
		evmInterpreter = env.interpreter
	)

	for i, test := range tests {
		x := new(uint256.Int).SetBytes(common.Hex2Bytes(test.X))
		y := new(uint256.Int).SetBytes(common.Hex2Bytes(test.Y))
		expected := new(uint256.Int).SetBytes(common.Hex2Bytes(test.Expected))
		stack.push(x)
		stack.push(y)
		opFn(&pc, evmInterpreter, &ScopeContext{nil, stack, nil})
		if len(stack.data) != 1 {
			t.Errorf("Expected one item on stack after %v, got %d: ", name, len(stack.data))
		}
		actual := stack.pop()

		if actual.Cmp(expected) != 0 {
			t.Errorf("Testcase %v %d, %v(%x, %x): expected  %x, got %x", name, i, name, x, y, expected, actual)
		}
	}
}

func TestByteOp(t *testing.T) {
	tests := []TwoOperandTestcase{
		{"ABCDEF0908070605040302010000000000000000000000000000000000000000", "00", "AB"},
		{"ABCDEF0908070605040302010000000000000000000000000000000000000000", "01", "CD"},
		{"00CDEF090807060504030201ffffffffffffffffffffffffffffffffffffffff", "00", "00"},
		{"00CDEF090807060504030201ffffffffffffffffffffffffffffffffffffffff", "01", "CD"},
		{"0000000000000000000000000000000000000000000000000000000000102030", "1F", "30"},
		{"0000000000000000000000000000000000000000000000000000000000102030", "1E", "20"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "20", "00"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "FFFFFFFFFFFFFFFF", "00"},
	}
	testTwoOperandOp(t, tests, opByte, "byte")
}

func TestSHL(t *testing.T) {
	// Testcases from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#shl-shift-left
	tests := []TwoOperandTestcase{
		{"0000000000000000000000000000000000000000000000000000000000000001", "01", "0000000000000000000000000000000000000000000000000000000000000002"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "ff", "8000000000000000000000000000000000000000000000000000000000000000"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "0100", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "0101", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "00", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "01", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ff", "8000000000000000000000000000000000000000000000000000000000000000"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0100", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"0000000000000000000000000000000000000000000000000000000000000000", "01", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "01", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"},
	}
	testTwoOperandOp(t, tests, opSHL, "shl")
}

func TestSHR(t *testing.T) {
	// Testcases from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#shr-logical-shift-right
	tests := []TwoOperandTestcase{
		{"0000000000000000000000000000000000000000000000000000000000000001", "00", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "01", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "01", "4000000000000000000000000000000000000000000000000000000000000000"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "ff", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "0100", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "0101", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "00", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "01", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ff", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0100", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"0000000000000000000000000000000000000000000000000000000000000000", "01", "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	testTwoOperandOp(t, tests, opSHR, "shr")
}

func TestSAR(t *testing.T) {
	// Testcases from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#sar-arithmetic-shift-right
	tests := []TwoOperandTestcase{
		{"0000000000000000000000000000000000000000000000000000000000000001", "00", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "01", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "01", "c000000000000000000000000000000000000000000000000000000000000000"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "ff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "0100", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "0101", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "00", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "01", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0100", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"0000000000000000000000000000000000000000000000000000000000000000", "01", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"4000000000000000000000000000000000000000000000000000000000000000", "fe", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "f8", "000000000000000000000000000000000000000000000000000000000000007f"},
		{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "fe", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ff", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0100", "0000000000000000000000000000000000000000000000000000000000000000"},
	}

	testTwoOperandOp(t, tests, opSAR, "sar")
}

func TestAddMod(t *testing.T) {
	var (
		env            = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		stack          = newstack()
		evmInterpreter = NewEVMInterpreter(env, env.Config)
		pc             = uint64(0)
	)
	tests := []struct {
		x        string
		y        string
		z        string
		expected string
	}{
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
		},
	}
	// x + y = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
	// in 256 bit repr, fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd

	for i, test := range tests {
		x := new(uint256.Int).SetBytes(common.Hex2Bytes(test.x))
		y := new(uint256.Int).SetBytes(common.Hex2Bytes(test.y))
		z := new(uint256.Int).SetBytes(common.Hex2Bytes(test.z))
		expected := new(uint256.Int).SetBytes(common.Hex2Bytes(test.expected))
		stack.push(z)
		stack.push(y)
		stack.push(x)
		opAddmod(&pc, evmInterpreter, &ScopeContext{nil, stack, nil})
		actual := stack.pop()
		if actual.Cmp(expected) != 0 {
			t.Errorf("Testcase %d, expected  %x, got %x", i, expected, actual)
		}
	}
}

// utility function to fill the json-file with testcases
// Enable this test to generate the 'testcases_xx.json' files
func TestWriteExpectedValues(t *testing.T) {
	t.Skip("Enable this test to create json test cases.")

	// getResult is a convenience function to generate the expected values
	getResult := func(args []*twoOperandParams, opFn executionFunc) []TwoOperandTestcase {
		var (
			env         = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
			stack       = newstack()
			pc          = uint64(0)
			interpreter = env.interpreter
		)
		result := make([]TwoOperandTestcase, len(args))
		for i, param := range args {
			x := new(uint256.Int).SetBytes(common.Hex2Bytes(param.x))
			y := new(uint256.Int).SetBytes(common.Hex2Bytes(param.y))
			stack.push(x)
			stack.push(y)
			opFn(&pc, interpreter, &ScopeContext{nil, stack, nil})
			actual := stack.pop()
			result[i] = TwoOperandTestcase{param.x, param.y, fmt.Sprintf("%064x", actual)}
		}
		return result
	}

	for name, method := range twoOpMethods {
		data, err := json.Marshal(getResult(commonParams, method))
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(fmt.Sprintf("testdata/testcases_%v.json", name), data, 0644)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestJsonTestcases runs through all the testcases defined as json-files
func TestJsonTestcases(t *testing.T) {
	for name := range twoOpMethods {
		data, err := os.ReadFile(fmt.Sprintf("testdata/testcases_%v.json", name))
		if err != nil {
			t.Fatal("Failed to read file", err)
		}
		var testcases []TwoOperandTestcase
		json.Unmarshal(data, &testcases)
		testTwoOperandOp(t, testcases, twoOpMethods[name], name)
	}
}

func opBenchmark(bench *testing.B, op executionFunc, args ...string) {
	var (
		env            = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		stack          = newstack()
		scope          = &ScopeContext{nil, stack, nil}
		evmInterpreter = NewEVMInterpreter(env, env.Config)
	)

	env.interpreter = evmInterpreter
	// convert args
	intArgs := make([]*uint256.Int, len(args))
	for i, arg := range args {
		intArgs[i] = new(uint256.Int).SetBytes(common.Hex2Bytes(arg))
	}
	pc := uint64(0)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		for _, arg := range intArgs {
			stack.push(arg)
		}
		op(&pc, evmInterpreter, scope)
		stack.pop()
	}
	bench.StopTimer()

	for i, arg := range args {
		want := new(uint256.Int).SetBytes(common.Hex2Bytes(arg))
		if have := intArgs[i]; !want.Eq(have) {
			bench.Fatalf("input #%d mutated, have %x want %x", i, have, want)
		}
	}
}

func BenchmarkOpAdd64(b *testing.B) {
	x := "ffffffff"
	y := "fd37f3e2bba2c4f"

	opBenchmark(b, opAdd, x, y)
}

func BenchmarkOpAdd128(b *testing.B) {
	x := "ffffffffffffffff"
	y := "f5470b43c6549b016288e9a65629687"

	opBenchmark(b, opAdd, x, y)
}

func BenchmarkOpAdd256(b *testing.B) {
	x := "0802431afcbce1fc194c9eaa417b2fb67dc75a95db0bc7ec6b1c8af11df6a1da9"
	y := "a1f5aac137876480252e5dcac62c354ec0d42b76b0642b6181ed099849ea1d57"

	opBenchmark(b, opAdd, x, y)
}

func BenchmarkOpSub64(b *testing.B) {
	x := "51022b6317003a9d"
	y := "a20456c62e00753a"

	opBenchmark(b, opSub, x, y)
}

func BenchmarkOpSub128(b *testing.B) {
	x := "4dde30faaacdc14d00327aac314e915d"
	y := "9bbc61f5559b829a0064f558629d22ba"

	opBenchmark(b, opSub, x, y)
}

func BenchmarkOpSub256(b *testing.B) {
	x := "4bfcd8bb2ac462735b48a17580690283980aa2d679f091c64364594df113ea37"
	y := "97f9b1765588c4e6b69142eb00d20507301545acf3e1238c86c8b29be227d46e"

	opBenchmark(b, opSub, x, y)
}

func BenchmarkOpMul(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opMul, x, y)
}

func BenchmarkOpDiv256(b *testing.B) {
	x := "ff3f9014f20db29ae04af2c2d265de17"
	y := "fe7fb0d1f59dfe9492ffbf73683fd1e870eec79504c60144cc7f5fc2bad1e611"
	opBenchmark(b, opDiv, x, y)
}

func BenchmarkOpDiv128(b *testing.B) {
	x := "fdedc7f10142ff97"
	y := "fbdfda0e2ce356173d1993d5f70a2b11"
	opBenchmark(b, opDiv, x, y)
}

func BenchmarkOpDiv64(b *testing.B) {
	x := "fcb34eb3"
	y := "f97180878e839129"
	opBenchmark(b, opDiv, x, y)
}

func BenchmarkOpSdiv(b *testing.B) {
	x := "ff3f9014f20db29ae04af2c2d265de17"
	y := "fe7fb0d1f59dfe9492ffbf73683fd1e870eec79504c60144cc7f5fc2bad1e611"

	opBenchmark(b, opSdiv, x, y)
}

func BenchmarkOpMod(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opMod, x, y)
}

func BenchmarkOpSmod(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opSmod, x, y)
}

func BenchmarkOpExp(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opExp, x, y)
}

func BenchmarkOpSignExtend(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opSignExtend, x, y)
}

func BenchmarkOpLt(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opLt, x, y)
}

func BenchmarkOpGt(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opGt, x, y)
}

func BenchmarkOpSlt(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opSlt, x, y)
}

func BenchmarkOpSgt(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opSgt, x, y)
}

func BenchmarkOpEq(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opEq, x, y)
}
func BenchmarkOpEq2(b *testing.B) {
	x := "FBCDEF090807060504030201ffffffffFBCDEF090807060504030201ffffffff"
	y := "FBCDEF090807060504030201ffffffffFBCDEF090807060504030201fffffffe"
	opBenchmark(b, opEq, x, y)
}
func BenchmarkOpAnd(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opAnd, x, y)
}

func BenchmarkOpOr(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opOr, x, y)
}

func BenchmarkOpXor(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opXor, x, y)
}

func BenchmarkOpByte(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup

	opBenchmark(b, opByte, x, y)
}

func BenchmarkOpAddmod(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup
	z := alphabetSoup

	opBenchmark(b, opAddmod, x, y, z)
}

func BenchmarkOpMulmod(b *testing.B) {
	x := alphabetSoup
	y := alphabetSoup
	z := alphabetSoup

	opBenchmark(b, opMulmod, x, y, z)
}

func BenchmarkOpSHL(b *testing.B) {
	x := "FBCDEF090807060504030201ffffffffFBCDEF090807060504030201ffffffff"
	y := "ff"

	opBenchmark(b, opSHL, x, y)
}
func BenchmarkOpSHR(b *testing.B) {
	x := "FBCDEF090807060504030201ffffffffFBCDEF090807060504030201ffffffff"
	y := "ff"

	opBenchmark(b, opSHR, x, y)
}
func BenchmarkOpSAR(b *testing.B) {
	x := "FBCDEF090807060504030201ffffffffFBCDEF090807060504030201ffffffff"
	y := "ff"

	opBenchmark(b, opSAR, x, y)
}
func BenchmarkOpIsZero(b *testing.B) {
	x := "FBCDEF090807060504030201ffffffffFBCDEF090807060504030201ffffffff"
	opBenchmark(b, opIszero, x)
}

func TestOpMstore(t *testing.T) {
	var (
		env            = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		stack          = newstack()
		mem            = NewMemory()
		evmInterpreter = NewEVMInterpreter(env, env.Config)
	)

	env.interpreter = evmInterpreter
	mem.Resize(64)
	pc := uint64(0)
	v := "abcdef00000000000000abba000000000deaf000000c0de00100000000133700"
	stack.push(new(uint256.Int).SetBytes(common.Hex2Bytes(v)))
	stack.push(new(uint256.Int))
	opMstore(&pc, evmInterpreter, &ScopeContext{mem, stack, nil})
	if got := common.Bytes2Hex(mem.GetCopy(0, 32)); got != v {
		t.Fatalf("Mstore fail, got %v, expected %v", got, v)
	}
	stack.push(new(uint256.Int).SetUint64(0x1))
	stack.push(new(uint256.Int))
	opMstore(&pc, evmInterpreter, &ScopeContext{mem, stack, nil})
	if common.Bytes2Hex(mem.GetCopy(0, 32)) != "0000000000000000000000000000000000000000000000000000000000000001" {
		t.Fatalf("Mstore failed to overwrite previous value")
	}
}

func BenchmarkOpMstore(bench *testing.B) {
	var (
		env            = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		stack          = newstack()
		mem            = NewMemory()
		evmInterpreter = NewEVMInterpreter(env, env.Config)
	)

	env.interpreter = evmInterpreter
	mem.Resize(64)
	pc := uint64(0)
	memStart := new(uint256.Int)
	value := new(uint256.Int).SetUint64(0x1337)

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		stack.push(value)
		stack.push(memStart)
		opMstore(&pc, evmInterpreter, &ScopeContext{mem, stack, nil})
	}
}

func BenchmarkOpKeccak256(bench *testing.B) {
	var (
		env            = NewEVM(BlockContext{}, TxContext{}, nil, params.TestChainConfig, Config{})
		stack          = newstack()
		mem            = NewMemory()
		evmInterpreter = NewEVMInterpreter(env, env.Config)
	)
	env.interpreter = evmInterpreter
	mem.Resize(32)
	pc := uint64(0)
	start := new(uint256.Int)

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		stack.push(uint256.NewInt(32))
		stack.push(start)
		opKeccak256(&pc, evmInterpreter, &ScopeContext{mem, stack, nil})
	}
}

func TestCreate2Addreses(t *testing.T) {
	type testcase struct {
		origin   string
		salt     string
		code     string
		expected string
	}

	for i, tt := range []testcase{
		{
			origin:   "0x0000000000000000000000000000000000000000",
			salt:     "0x0000000000000000000000000000000000000000",
			code:     "0x00",
			expected: "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38",
		},
		{
			origin:   "0xdeadbeef00000000000000000000000000000000",
			salt:     "0x0000000000000000000000000000000000000000",
			code:     "0x00",
			expected: "0xB928f69Bb1D91Cd65274e3c79d8986362984fDA3",
		},
		{
			origin:   "0xdeadbeef00000000000000000000000000000000",
			salt:     "0xfeed000000000000000000000000000000000000",
			code:     "0x00",
			expected: "0xD04116cDd17beBE565EB2422F2497E06cC1C9833",
		},
		{
			origin:   "0x0000000000000000000000000000000000000000",
			salt:     "0x0000000000000000000000000000000000000000",
			code:     "0xdeadbeef",
			expected: "0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e",
		},
		{
			origin:   "0x00000000000000000000000000000000deadbeef",
			salt:     "0xcafebabe",
			code:     "0xdeadbeef",
			expected: "0x60f3f640a8508fC6a86d45DF051962668E1e8AC7",
		},
		{
			origin:   "0x00000000000000000000000000000000deadbeef",
			salt:     "0xcafebabe",
			code:     "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			expected: "0x1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C",
		},
		{
			origin:   "0x0000000000000000000000000000000000000000",
			salt:     "0x0000000000000000000000000000000000000000",
			code:     "0x",
			expected: "0xE33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0",
		},
	} {

		origin := common.BytesToAddress(common.FromHex(tt.origin))
		salt := common.BytesToHash(common.FromHex(tt.salt))
		code := common.FromHex(tt.code)
		codeHash := crypto.Keccak256(code)
		address := crypto.CreateAddress2(origin, salt, codeHash)
		/*
			stack          := newstack()
			// salt, but we don't need that for this test
			stack.push(big.NewInt(int64(len(code)))) //size
			stack.push(big.NewInt(0)) // memstart
			stack.push(big.NewInt(0)) // value
			gas, _ := gasCreate2(params.GasTable{}, nil, nil, stack, nil, 0)
			fmt.Printf("Example %d\n* address `0x%x`\n* salt `0x%x`\n* init_code `0x%x`\n* gas (assuming no mem expansion): `%v`\n* result: `%s`\n\n", i,origin, salt, code, gas, address.String())
		*/
		expected := common.BytesToAddress(common.FromHex(tt.expected))
		if !bytes.Equal(expected.Bytes(), address.Bytes()) {
			t.Errorf("test %d: expected %s, got %s", i, expected.String(), address.String())
		}
	}
}

func TestRandom(t *testing.T) {
	type testcase struct {
		name   string
		random common.Hash
	}

	for _, tt := range []testcase{
		{name: "empty hash", random: common.Hash{}},
		{name: "1", random: common.Hash{0}},
		{name: "emptyCodeHash", random: emptyCodeHash},
		{name: "hash(0x010203)", random: crypto.Keccak256Hash([]byte{0x01, 0x02, 0x03})},
	} {
		var (
			env            = NewEVM(BlockContext{Random: &tt.random}, TxContext{}, nil, params.TestChainConfig, Config{})
			stack          = newstack()
			pc             = uint64(0)
			evmInterpreter = env.interpreter
		)
		opRandom(&pc, evmInterpreter, &ScopeContext{nil, stack, nil})
		if len(stack.data) != 1 {
			t.Errorf("Expected one item on stack after %v, got %d: ", tt.name, len(stack.data))
		}
		actual := stack.pop()
		expected, overflow := uint256.FromBig(new(big.Int).SetBytes(tt.random.Bytes()))
		if overflow {
			t.Errorf("Testcase %v: invalid overflow", tt.name)
		}
		if actual.Cmp(expected) != 0 {
			t.Errorf("Testcase %v: expected  %x, got %x", tt.name, expected, actual)
		}
	}
}

type testContractAddress struct{}

func (c testContractAddress) Address() common.Address {
	return common.Address{}
}

type testCallerAddress struct{}

func (c testCallerAddress) Address() common.Address {
	addr := common.Address{}
	addr[0]++
	return addr
}

func newTestScopeConext() *ScopeContext {
	c := new(ScopeContext)
	c.Memory = NewMemory()
	c.Memory.Resize(uint64(expandedFheCiphertextSize[FheUint8]) * 3)
	c.Stack = newstack()
	c.Contract = NewContract(testCallerAddress{}, testContractAddress{}, big.NewInt(10), 100000)
	return c
}

func uint256FromBig(b *big.Int) *uint256.Int {
	value, overflow := uint256.FromBig(b)
	if overflow {
		panic("overflow")
	}
	return value
}

func TestProtectedStorageSstoreSload(t *testing.T) {
	pc := uint64(0)
	depth := 1
	interpreter := newTestInterpreter()
	interpreter.evm.depth = depth
	ct := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint32)
	ctHash := ct.getHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256FromBig(ctHash.Big())

	// Setup and call SSTORE - it requires a location and a value to set there.
	scope.Stack.push(value)
	scope.Stack.push(loc)
	_, err := opSstore(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Clear the verified ciphertexts.
	interpreter.verifiedCiphertexts = make(map[common.Hash]*verifiedCiphertext)

	// Setup and call SLOAD - it requires a location to load.
	scope.Stack.push(loc)
	_, err = opSload(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Expect the ciphertext is verified after SLOAD.
	ctAfterSload := getVerifiedCiphertextFromEVM(interpreter, ctHash)
	if ctAfterSload == nil {
		t.Fatalf("expected ciphertext is verified after sload")
	}
	if !bytes.Equal(ct.serialize(), ctAfterSload.ciphertext.serialize()) {
		t.Fatalf("expected ciphertext after sload is the same as original")
	}
}

func TestProtectedStorageGarbageCollectionNoFlaggedLocation(t *testing.T) {
	pc := uint64(0)
	depth := 1
	interpreter := newTestInterpreter()
	interpreter.evm.depth = depth
	ctHash := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	locHash := common.BytesToHash(loc.Bytes())
	value := uint256FromBig(ctHash.Big())
	protectedStorage := crypto.CreateProtectedStorageContractAddress(scope.Contract.Address())

	// Persist the ciphertext in protected storage.
	scope.Stack.push(value)
	scope.Stack.push(loc)
	_, err := opSstore(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Set location flag to zero, such that garbage collection doesn't happen.
	flagHandleLocation := crypto.Keccak256Hash(crypto.Keccak256Hash(locHash.Bytes()).Bytes())
	interpreter.evm.StateDB.SetState(protectedStorage, flagHandleLocation, zero)

	// Overwrite the ciphertext handle with 0.
	scope.Stack.push(uint256.NewInt(0))
	scope.Stack.push(loc)
	_, err = opSstore(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Verify that garbage collection hasn't happened.
	metadata := ciphertextMetadata{}
	metadataKey := crypto.Keccak256Hash(ctHash.Bytes())
	metadata.deserialize(interpreter.evm.StateDB.GetState(protectedStorage, metadataKey))
	slot := uint256FromBig(metadataKey.Big())
	slot = slot.AddUint64(slot, 1)
	foundNonZero := false
	for i := uint64(0); i < metadata.length; i++ {
		res := interpreter.evm.StateDB.GetState(protectedStorage, common.BytesToHash(slot.Bytes()))
		if !bytes.Equal(res.Bytes(), zero.Bytes()) {
			foundNonZero = true
			break
		}
		slot = slot.AddUint64(slot, i)
	}
	if !foundNonZero {
		t.Fatalf("garbage collection must not have happened")
	}
}

func TestProtectedStorageGarbageCollection(t *testing.T) {
	pc := uint64(0)
	depth := 1
	interpreter := newTestInterpreter()
	interpreter.evm.depth = depth
	ctHash := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	locHash := common.BytesToHash(loc.Bytes())
	value := uint256FromBig(ctHash.Big())

	// Persist the ciphertext in protected storage.
	scope.Stack.push(value)
	scope.Stack.push(loc)
	_, err := opSstore(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Make sure ciphertext is persisted to protected storage.
	protectedStorage := crypto.CreateProtectedStorageContractAddress(scope.Contract.Address())
	metadata := ciphertextMetadata{}
	metadataKey := crypto.Keccak256Hash(ctHash.Bytes())
	metadata.deserialize(interpreter.evm.StateDB.GetState(protectedStorage, metadataKey))
	if metadata.refCount != 1 {
		t.Fatalf("metadata.refcount of ciphertext is not 1")
	}
	if metadata.length != uint64(expandedFheCiphertextSize[FheUint8]) {
		t.Fatalf("metadata.length (%v) != ciphertext len (%v)", metadata.length, uint64(expandedFheCiphertextSize[FheUint8]))
	}
	ciphertextLocationsToCheck := (metadata.length + 32 - 1) / 32
	startOfCiphertext := newInt(metadataKey.Bytes())
	startOfCiphertext.AddUint64(startOfCiphertext, 1)
	ctIdx := startOfCiphertext
	foundNonZero := false
	for i := uint64(0); i < ciphertextLocationsToCheck; i++ {
		c := interpreter.evm.StateDB.GetState(protectedStorage, common.BytesToHash(ctIdx.Bytes()))
		u := uint256FromBig(c.Big())
		if !u.IsZero() {
			foundNonZero = true
			break
		}
		ctIdx.AddUint64(startOfCiphertext, 1)
	}
	if !foundNonZero {
		t.Fatalf("ciphertext is not persisted to protected storage")
	}

	// Check if the handle location is flagged in protected storage.
	flagHandleLocation := crypto.Keccak256Hash(crypto.Keccak256Hash(locHash.Bytes()).Bytes())
	foundFlag := interpreter.evm.StateDB.GetState(protectedStorage, flagHandleLocation)
	if !bytes.Equal(foundFlag.Bytes(), flag.Bytes()) {
		t.Fatalf("location flag not persisted to protected storage")
	}

	// Overwrite the ciphertext handle with 0.
	scope.Stack.push(uint256.NewInt(0))
	scope.Stack.push(loc)
	_, err = opSstore(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Make sure the metadata and the ciphertext are garbage collected from protected storage.
	protectedStorageIdx := newInt(metadataKey.Bytes())
	foundNonZero = false
	for i := uint64(0); i < ciphertextLocationsToCheck; i++ {
		c := interpreter.evm.StateDB.GetState(protectedStorage, common.BytesToHash(protectedStorageIdx.Bytes()))
		u := uint256FromBig(c.Big())
		if !u.IsZero() {
			foundNonZero = true
			break
		}
		ctIdx.AddUint64(startOfCiphertext, 1)
	}
	if foundNonZero {
		t.Fatalf("ciphertext is not garbage collected from protected storage")
	}

	// Make sure the flag location is zero.
	foundFlag = interpreter.evm.StateDB.GetState(protectedStorage, flagHandleLocation)
	if !bytes.Equal(foundFlag.Bytes(), zero.Bytes()) {
		t.Fatalf("location flag is not set to zero on garbage collection")
	}
}

func TestProtectedStorageSloadDoesNotVerifyNonHandle(t *testing.T) {
	pc := uint64(0)
	interpreter := newTestInterpreter()
	scope := newTestScopeConext()
	loc := uint256.NewInt(10)
	value := uint256.NewInt(42)

	scope.Stack.push(value)
	scope.Stack.push(loc)
	_, err := opSstore(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	scope.Stack.push(loc)
	_, err = opSload(&pc, interpreter, scope)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Expect no verified ciphertexts.
	if len(interpreter.verifiedCiphertexts) != 0 {
		t.Fatalf("expected no verified ciphetexts")
	}
}

func TestOpReturnDelegation(t *testing.T) {
	pc := uint64(0)
	depth := 2
	interpreter := newTestInterpreter()
	scope := newTestScopeConext()
	ct := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8)
	ctHash := ct.getHash()

	offset := uint256.NewInt(0)
	length := uint256.NewInt(32)
	scope.Stack.push(length)
	scope.Stack.push(offset)
	scope.Memory.Set(offset.Uint64(), length.Uint64(), ctHash[:])
	interpreter.evm.depth = depth
	opReturn(&pc, interpreter, scope)
	interpreter.evm.depth--
	ctAfterOp := getVerifiedCiphertextFromEVM(interpreter, ctHash)
	if ctAfterOp == nil {
		t.Fatalf("expected ciphertext is still verified after the return op")
	}
	if !bytes.Equal(ct.serialize(), ctAfterOp.ciphertext.serialize()) {
		t.Fatalf("expected ciphertext after the return op is the same as original")
	}
}

func TestOpReturnUnverifyIfNotReturned(t *testing.T) {
	pc := uint64(0)
	depth := 2
	interpreter := newTestInterpreter()
	scope := newTestScopeConext()
	ctHash := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()

	offset := uint256.NewInt(0)
	len := uint256.NewInt(32)
	scope.Stack.push(len)
	scope.Stack.push(offset)
	// Set 0s as return.
	scope.Memory.Set(offset.Uint64(), len.Uint64(), make([]byte, len.Uint64()))
	interpreter.evm.depth = depth
	opReturn(&pc, interpreter, scope)
	interpreter.evm.depth = depth - 1
	ct := getVerifiedCiphertextFromEVM(interpreter, ctHash)
	if ct != nil {
		t.Fatalf("expected ciphertext is not verified after the return op")
	}
}

func TestOpReturnDoesNotUnverifyIfNotVerified(t *testing.T) {
	pc := uint64(0)
	interpreter := newTestInterpreter()
	scope := newTestScopeConext()
	ct := verifyCiphertextInTestMemory(interpreter, 2, 4, FheUint8)
	ctHash := ct.getHash()

	// Return from depth 3 to depth 2. However, ct is not verified at 3 and, hence, cannot
	// be passed from 3 to 2. However, we expect that ct remains verified at 4.
	offset := uint256.NewInt(0)
	len := uint256.NewInt(32)
	scope.Stack.push(len)
	scope.Stack.push(offset)
	scope.Memory.Set(offset.Uint64(), len.Uint64(), ctHash[:])
	interpreter.evm.depth = 3
	opReturn(&pc, interpreter, scope)
	interpreter.evm.depth--

	ctAt2 := getVerifiedCiphertextFromEVM(interpreter, ctHash)
	if ctAt2 != nil {
		t.Fatalf("expected ciphertext is not verified at 2")
	}
	interpreter.evm.depth = 3
	ctAt3 := getVerifiedCiphertextFromEVM(interpreter, ctHash)
	if ctAt3 != nil {
		t.Fatalf("expected ciphertext is not verified at 3")
	}
	interpreter.evm.depth = 4
	ctAt4 := getVerifiedCiphertextFromEVM(interpreter, ctHash)
	if ctAt4 == nil {
		t.Fatalf("expected ciphertext is still verified at 4")
	}
	if !bytes.Equal(ct.serialize(), ctAt4.ciphertext.serialize()) {
		t.Fatalf("expected ciphertext after the return op is the same as original")
	}
	if ctAt4.verifiedDepths.count() != 1 || !ctAt4.verifiedDepths.has(interpreter.evm.depth) {
		t.Fatalf("expected ciphertext to be verified at depth 4")
	}
}

// Use variables to get addresses of functions.
var vOpCall = opCall
var vOpCallCode = opCallCode
var vOpDelegateCall = opDelegateCall
var vOpStaticCall = opStaticCall

type OpCodeFun *func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error)

var callsToTest = []OpCodeFun{
	&vOpCall,
	&vOpCallCode,
	&vOpDelegateCall,
	&vOpStaticCall,
}

var testPrecompileAddress common.Address = common.BytesToAddress([]byte{255})
var testPrecompileNumber *uint256.Int = uint256.NewInt(255)

type testPrecompile struct {
	depths map[common.Hash]*depthSet
}

func newTestPrecompile(ctHashes []common.Hash) *testPrecompile {
	p := &testPrecompile{}
	p.depths = make(map[common.Hash]*depthSet)
	for _, ctHash := range ctHashes {
		p.depths[ctHash] = newDepthSet()
	}
	return p
}

func (e *testPrecompile) RequiredGas(accessibleState PrecompileAccessibleState, input []byte) uint64 {
	return 0
}

func (e *testPrecompile) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
	for ctHash, depthSet := range e.depths {
		ct, found := accessibleState.Interpreter().verifiedCiphertexts[ctHash]
		if found {
			for d := range ct.verifiedDepths.m {
				depthSet.add(d)
			}
		}
	}
	return nil, nil
}

func setupOpCall(call OpCodeFun, interpreter *EVMInterpreter, callArgs []byte, addr *uint256.Int) (pc uint64, scope *ScopeContext) {
	pc = uint64(0)
	scope = newTestScopeConext()

	retSize := uint256.NewInt(32)
	retOffset := uint256.NewInt(32)
	inSize := uint256.NewInt(uint64(len(callArgs)))
	inOffset := uint256.NewInt(0)
	scope.Memory.Set(inOffset.Uint64(), inSize.Uint64(), callArgs)
	value := uint256.NewInt(0)
	gas := uint256.NewInt(99999999999)
	interpreter.evm.callGasTemp = gas.Uint64()

	scope.Stack.push(retSize)
	scope.Stack.push(retOffset)
	scope.Stack.push(inSize)
	scope.Stack.push(inOffset)
	if call == &vOpCall || call == &vOpCallCode {
		scope.Stack.push(value)
	}
	scope.Stack.push(addr)
	scope.Stack.push(gas)

	return
}

func setupTestPrecompile(ctHashes []common.Hash) (precompile *testPrecompile) {
	precompile = newTestPrecompile(ctHashes)
	PrecompiledContractsHomestead[testPrecompileAddress] = precompile
	PrecompiledContractsByzantium[testPrecompileAddress] = precompile
	PrecompiledContractsIstanbul[testPrecompileAddress] = precompile
	PrecompiledContractsBerlin[testPrecompileAddress] = precompile
	return
}

func TestOpCallNonPrecompileWithHandleInArgs(t *testing.T) {
	for _, call := range callsToTest {
		depth := 2
		interpreter := newTestInterpreter()
		interpreter.evm.depth = depth
		ctHash := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()
		// Call a non-precompile contract at address 9999999.
		pc, scope := setupOpCall(call, interpreter, ctHash.Bytes(), uint256.NewInt(9999999))
		_, err := (*call)(&pc, interpreter, scope)
		if err != nil {
			t.Fatalf(err.Error())
		}

		ct := getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct == nil {
			t.Fatalf("expected ciphertext is verified at depth (%d) after opcall", depth)
		}

		interpreter.evm.depth++
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct != nil {
			t.Fatalf("expected ciphertext is not verified at depth + 1 (%d) after opcall", depth+1)
		}
	}
}

func TestOpCallPrecompileWithHandleInArgs(t *testing.T) {
	for _, call := range callsToTest {
		depth := 2
		interpreter := newTestInterpreter()
		interpreter.evm.depth = depth
		ctHash := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()
		pc, scope := setupOpCall(call, interpreter, ctHash.Bytes(), testPrecompileNumber)
		testPrecompile := setupTestPrecompile([]common.Hash{ctHash})
		_, err := (*call)(&pc, interpreter, scope)
		if err != nil {
			t.Fatalf(err.Error())
		}

		ct := getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct == nil {
			t.Fatalf("expected ciphertext is verified at depth (%d) after opcall", depth)
		}

		interpreter.evm.depth++
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct != nil {
			t.Fatalf("expected ciphertext is not verified at depth +1 (%d) after opcall", depth+1)
		}

		// Make sure the cipherext was verified at depth + 1 during the call.
		// TODO: Add the same test, but for a non-precompiled contract.
		if testPrecompile.depths[ctHash].count() != 2 || !testPrecompile.depths[ctHash].has(depth+1) {
			t.Fatalf("expected ciphertext was verified at depth + 1 (%d) during call", depth+1)
		}
	}
}

func TestOpCallPrecompileWithTwoHandlesInArgs(t *testing.T) {
	for _, call := range callsToTest {
		depth := 2
		interpreter := newTestInterpreter()
		interpreter.evm.depth = depth
		ctHash1 := verifyCiphertextInTestMemory(interpreter, 1, depth, FheUint8).getHash()
		ctHash2 := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()
		pc, scope := setupOpCall(call, interpreter, append(ctHash1.Bytes(), ctHash2.Bytes()...), testPrecompileNumber)
		testPrecompile := setupTestPrecompile([]common.Hash{ctHash1, ctHash2})
		_, err := (*call)(&pc, interpreter, scope)
		if err != nil {
			t.Fatalf(err.Error())
		}

		ct := getVerifiedCiphertextFromEVM(interpreter, ctHash1)
		if ct == nil {
			t.Fatalf("expected ciphertext1 is verified at depth (%d) after opcall", depth)
		}
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash2)
		if ct == nil {
			t.Fatalf("expected ciphertext2 is verified at depth (%d) after opcall", depth)
		}

		interpreter.evm.depth++
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash1)
		if ct != nil {
			t.Fatalf("expected ciphertext1 is not verified at depth +1 (%d) after opcall", depth+1)
		}
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash2)
		if ct != nil {
			t.Fatalf("expected ciphertext2 is not verified at depth +1 (%d) after opcall", depth+1)
		}

		// Make sure cipherext1 and ciphertext2 were both verified at depth + 1 during the call.
		// TODO: Add the same test, but for a non-precompiled contract.
		if testPrecompile.depths[ctHash1].count() != 2 || !testPrecompile.depths[ctHash1].has(depth+1) {
			t.Fatalf("expected ciphertext1 was verified at depth + 1 (%d) during call", depth+1)
		}
		if testPrecompile.depths[ctHash2].count() != 2 || !testPrecompile.depths[ctHash2].has(depth+1) {
			t.Fatalf("expected ciphertext2 was verified at depth + 1 (%d) during call", depth+1)
		}
	}
}

func TestOpCallPrecompileNoHandleInArgs(t *testing.T) {
	for _, call := range callsToTest {
		depth := 2
		interpreter := newTestInterpreter()
		interpreter.evm.depth = depth
		ctHash := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8).getHash()
		pc, scope := setupOpCall(call, interpreter, common.Hash{}.Bytes(), testPrecompileNumber)
		testPrecompile := setupTestPrecompile([]common.Hash{ctHash})
		_, err := (*call)(&pc, interpreter, scope)
		if err != nil {
			t.Fatalf(err.Error())
		}

		ct := getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct == nil {
			t.Fatalf("expected ciphertext is verified at depth (%d) after opcall", depth)
		}

		interpreter.evm.depth++
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct != nil {
			t.Fatalf("expected ciphertext is not verified at depth + 1 (%d) after opcall", depth+1)
		}

		if testPrecompile.depths[ctHash].count() != 1 || testPrecompile.depths[ctHash].has(depth+1) {
			t.Fatalf("expected test precompile was not verified at depth + 1 (%d)", depth+1)
		}
	}
}

func TestOpCallVerifySameCiphertextDeeperInStack(t *testing.T) {
	for _, call := range callsToTest {
		interpreter := newTestInterpreter()
		depth := 2
		interpreter.evm.depth = depth
		ct := verifyCiphertextInTestMemory(interpreter, 2, depth, FheUint8)

		// Call a non-precompile contract at address 9999999.
		pc, scope := setupOpCall(call, interpreter, common.Hash{}.Bytes(), uint256.NewInt(9999999))
		_, err := (*call)(&pc, interpreter, scope)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// Simulate a verification by the code running at depth + 1. It could, for example, be due to an SLOAD.
		interpreter.evm.depth = depth + 1
		ct = verifyTfheCiphertextInTestMemory(interpreter, ct, depth+1)

		// Make sure the ciphertext remains verified at depth 2, even though there is no return opcode
		// to make it available from depth 3 to depth 2.
		interpreter.evm.depth = depth
		verifiedCiphertext := getVerifiedCiphertextFromEVM(interpreter, ct.getHash())
		if verifiedCiphertext == nil {
			t.Fatalf("expected that the ciphertext is still verified at depth (%d)", depth)
		}
	}
}

func TestOpCallDoesNotDelegateIfNotVerified(t *testing.T) {
	for _, call := range callsToTest {
		verifiedDepth := 2
		interpreter := newTestInterpreter()
		interpreter.evm.depth = verifiedDepth + 1
		ctHash := verifyCiphertextInTestMemory(interpreter, 2, verifiedDepth, FheUint8).getHash()
		pc, scope := setupOpCall(call, interpreter, ctHash.Bytes(), testPrecompileNumber)
		testPrecompile := setupTestPrecompile([]common.Hash{ctHash})
		// Call at verifiedDepth + 1.
		_, err := (*call)(&pc, interpreter, scope)
		if err != nil {
			t.Fatalf(err.Error())
		}

		// Ciphertext must not be verified at verifiedDepth + 2.
		interpreter.evm.depth++
		ct := getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct != nil {
			t.Fatalf("expected ciphertext is not verified after opcall at verifiedDepth + 2 (%d)", verifiedDepth+2)
		}

		// Ciphertext must not be verified at verifiedDepth + 1.
		interpreter.evm.depth--
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct != nil {
			t.Fatalf("expected ciphertext is not verified after opcall at verifiedDepth + 1 (%d)", verifiedDepth+1)
		}

		// Ciphertext must be verified at verifiedDepth.
		interpreter.evm.depth--
		ct = getVerifiedCiphertextFromEVM(interpreter, ctHash)
		if ct == nil {
			t.Fatalf("expected ciphertext is verified after opcall at verifiedDepth (%d)", verifiedDepth)
		}
		if ct.verifiedDepths.count() != 1 || !ct.verifiedDepths.has(interpreter.evm.depth) {
			t.Fatalf("expected ciphertext to be verified at verifiedAtDepth (%d)", verifiedDepth)
		}

		// Ciphertext must have only been verified at verifiedDepth during the call.
		if !(testPrecompile.depths[ctHash].count() == 1 && testPrecompile.depths[ctHash].has(verifiedDepth)) {
			t.Fatalf("expected that testPrecompile was only verified at verifiedDepth (%d) during the call", verifiedDepth)
		}
	}
}
