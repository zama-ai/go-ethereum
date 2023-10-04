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
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
)

// precompiledTest defines the input/output pairs for precompiled contract tests.
type precompiledTest struct {
	Input, Expected string
	Gas             uint64
	Name            string
	NoBenchmark     bool // Benchmark primarily the worst-cases
}

// precompiledFailureTest defines the input/error pairs for precompiled
// contract failure tests.
type precompiledFailureTest struct {
	Input         string
	ExpectedError string
	Name          string
}

// allStatelessPrecompiles does not map to the actual set of precompiles, as it also contains
// repriced versions of precompiles at certain slots
var allStatelessPrecompiles = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):    &ecrecover{},
	common.BytesToAddress([]byte{2}):    &sha256hash{},
	common.BytesToAddress([]byte{3}):    &ripemd160hash{},
	common.BytesToAddress([]byte{4}):    &dataCopy{},
	common.BytesToAddress([]byte{5}):    &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{0xf5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):    &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):    &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):    &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):    &blake2F{},
	common.BytesToAddress([]byte{10}):   &bls12381G1Add{},
	common.BytesToAddress([]byte{11}):   &bls12381G1Mul{},
	common.BytesToAddress([]byte{12}):   &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{13}):   &bls12381G2Add{},
	common.BytesToAddress([]byte{14}):   &bls12381G2Mul{},
	common.BytesToAddress([]byte{15}):   &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{16}):   &bls12381Pairing{},
	common.BytesToAddress([]byte{17}):   &bls12381MapG1{},
	common.BytesToAddress([]byte{18}):   &bls12381MapG2{},
}

// EIP-152 test vectors
var blake2FMalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 0: empty input",
	},
	{
		Input:         "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 1: less than 213 bytes input",
	},
	{
		Input:         "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 2: more than 213 bytes input",
	},
	{
		Input:         "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002",
		ExpectedError: errBlake2FInvalidFinalFlag.Error(),
		Name:          "vector 3: malformed final block indicator flag",
	},
}

func testPrecompiled(addr string, test precompiledTest, t *testing.T) {
	a := common.HexToAddress(addr)
	p := allStatelessPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	state := newTestState()
	gas := p.RequiredGas(state, in)
	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		if res, _, err := RunPrecompiledContract(p, state, a, a, in, gas, false); err != nil {
			t.Error(err)
		} else if common.Bytes2Hex(res) != test.Expected {
			t.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
		}
		if expGas := test.Gas; expGas != gas {
			t.Errorf("%v: gas wrong, expected %d, got %d", test.Name, expGas, gas)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledOOG(addr string, test precompiledTest, t *testing.T) {
	p := allStatelessPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	state := newTestState()
	gas := p.RequiredGas(state, in) - 1

	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		a := common.HexToAddress(addr)
		_, _, err := RunPrecompiledContract(p, state, a, a, in, gas, false)
		if err.Error() != "out of gas" {
			t.Errorf("Expected error [out of gas], got [%v]", err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledFailure(addr string, test precompiledFailureTest, t *testing.T) {
	a := common.HexToAddress(addr)
	p := allStatelessPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	state := newTestState()
	gas := p.RequiredGas(state, in)
	t.Run(test.Name, func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, state, a, a, in, gas, false)
		if err.Error() != test.ExpectedError {
			t.Errorf("Expected error [%v], got [%v]", test.ExpectedError, err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func benchmarkPrecompiled(addr string, test precompiledTest, bench *testing.B) {
	if test.NoBenchmark {
		return
	}
	a := common.HexToAddress(addr)
	p := allStatelessPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	state := newTestState()
	reqGas := p.RequiredGas(state, in)

	var (
		res  []byte
		err  error
		data = make([]byte, len(in))
	)

	bench.Run(fmt.Sprintf("%s-Gas=%d", test.Name, reqGas), func(bench *testing.B) {
		bench.ReportAllocs()
		start := time.Now()
		bench.ResetTimer()
		for i := 0; i < bench.N; i++ {
			copy(data, in)
			res, _, err = RunPrecompiledContract(p, newTestState(), a, a, in, reqGas, false)
		}
		bench.StopTimer()
		elapsed := uint64(time.Since(start))
		if elapsed < 1 {
			elapsed = 1
		}
		gasUsed := reqGas * uint64(bench.N)
		bench.ReportMetric(float64(reqGas), "gas/op")
		// Keep it as uint64, multiply 100 to get two digit float later
		mgasps := (100 * 1000 * gasUsed) / elapsed
		bench.ReportMetric(float64(mgasps)/100, "mgas/s")
		//Check if it is correct
		if err != nil {
			bench.Error(err)
			return
		}
		if common.Bytes2Hex(res) != test.Expected {
			bench.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
			return
		}
	})
}

// Benchmarks the sample inputs from the ECRECOVER precompile.
func BenchmarkPrecompiledEcrecover(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "000000000000000000000000ceaccac640adf55b2028469bd36ba501f28b699d",
		Name:     "",
	}
	benchmarkPrecompiled("01", t, bench)
}

// Benchmarks the sample inputs from the SHA256 precompile.
func BenchmarkPrecompiledSha256(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "811c7003375852fabd0d362e40e68607a12bdabae61a7d068fe5fdd1dbbf2a5d",
		Name:     "128",
	}
	benchmarkPrecompiled("02", t, bench)
}

// Benchmarks the sample inputs from the RIPEMD precompile.
func BenchmarkPrecompiledRipeMD(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "0000000000000000000000009215b8d9882ff46f0dfde6684d78e831467f65e6",
		Name:     "128",
	}
	benchmarkPrecompiled("03", t, bench)
}

// Benchmarks the sample inputs from the identiy precompile.
func BenchmarkPrecompiledIdentity(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Name:     "128",
	}
	benchmarkPrecompiled("04", t, bench)
}

// Tests the sample inputs from the ModExp EIP 198.
func TestPrecompiledModExp(t *testing.T)      { testJson("modexp", "05", t) }
func BenchmarkPrecompiledModExp(b *testing.B) { benchJson("modexp", "05", b) }

func TestPrecompiledModExpEip2565(t *testing.T)      { testJson("modexp_eip2565", "f5", t) }
func BenchmarkPrecompiledModExpEip2565(b *testing.B) { benchJson("modexp_eip2565", "f5", b) }

// Tests the sample inputs from the elliptic curve addition EIP 213.
func TestPrecompiledBn256Add(t *testing.T)      { testJson("bn256Add", "06", t) }
func BenchmarkPrecompiledBn256Add(b *testing.B) { benchJson("bn256Add", "06", b) }

// Tests OOG
func TestPrecompiledModExpOOG(t *testing.T) {
	modexpTests, err := loadJson("modexp")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range modexpTests {
		testPrecompiledOOG("05", test, t)
	}
}

// Tests the sample inputs from the elliptic curve scalar multiplication EIP 213.
func TestPrecompiledBn256ScalarMul(t *testing.T)      { testJson("bn256ScalarMul", "07", t) }
func BenchmarkPrecompiledBn256ScalarMul(b *testing.B) { benchJson("bn256ScalarMul", "07", b) }

// Tests the sample inputs from the elliptic curve pairing check EIP 197.
func TestPrecompiledBn256Pairing(t *testing.T)      { testJson("bn256Pairing", "08", t) }
func BenchmarkPrecompiledBn256Pairing(b *testing.B) { benchJson("bn256Pairing", "08", b) }

func TestPrecompiledBlake2F(t *testing.T)      { testJson("blake2F", "09", t) }
func BenchmarkPrecompiledBlake2F(b *testing.B) { benchJson("blake2F", "09", b) }

func TestPrecompileBlake2FMalformedInput(t *testing.T) {
	for _, test := range blake2FMalformedInputTests {
		testPrecompiledFailure("09", test, t)
	}
}

func TestPrecompiledEcrecover(t *testing.T) { testJson("ecRecover", "01", t) }

func testJson(name, addr string, t *testing.T) {
	tests, err := loadJson(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiled(addr, test, t)
	}
}

func testJsonFail(name, addr string, t *testing.T) {
	tests, err := loadJsonFail(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiledFailure(addr, test, t)
	}
}

func benchJson(name, addr string, b *testing.B) {
	tests, err := loadJson(name)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range tests {
		benchmarkPrecompiled(addr, test, b)
	}
}

func TestPrecompiledBLS12381G1Add(t *testing.T)      { testJson("blsG1Add", "0a", t) }
func TestPrecompiledBLS12381G1Mul(t *testing.T)      { testJson("blsG1Mul", "0b", t) }
func TestPrecompiledBLS12381G1MultiExp(t *testing.T) { testJson("blsG1MultiExp", "0c", t) }
func TestPrecompiledBLS12381G2Add(t *testing.T)      { testJson("blsG2Add", "0d", t) }
func TestPrecompiledBLS12381G2Mul(t *testing.T)      { testJson("blsG2Mul", "0e", t) }
func TestPrecompiledBLS12381G2MultiExp(t *testing.T) { testJson("blsG2MultiExp", "0f", t) }
func TestPrecompiledBLS12381Pairing(t *testing.T)    { testJson("blsPairing", "10", t) }
func TestPrecompiledBLS12381MapG1(t *testing.T)      { testJson("blsMapG1", "11", t) }
func TestPrecompiledBLS12381MapG2(t *testing.T)      { testJson("blsMapG2", "12", t) }

func BenchmarkPrecompiledBLS12381G1Add(b *testing.B)      { benchJson("blsG1Add", "0a", b) }
func BenchmarkPrecompiledBLS12381G1Mul(b *testing.B)      { benchJson("blsG1Mul", "0b", b) }
func BenchmarkPrecompiledBLS12381G1MultiExp(b *testing.B) { benchJson("blsG1MultiExp", "0c", b) }
func BenchmarkPrecompiledBLS12381G2Add(b *testing.B)      { benchJson("blsG2Add", "0d", b) }
func BenchmarkPrecompiledBLS12381G2Mul(b *testing.B)      { benchJson("blsG2Mul", "0e", b) }
func BenchmarkPrecompiledBLS12381G2MultiExp(b *testing.B) { benchJson("blsG2MultiExp", "0f", b) }
func BenchmarkPrecompiledBLS12381Pairing(b *testing.B)    { benchJson("blsPairing", "10", b) }
func BenchmarkPrecompiledBLS12381MapG1(b *testing.B)      { benchJson("blsMapG1", "11", b) }
func BenchmarkPrecompiledBLS12381MapG2(b *testing.B)      { benchJson("blsMapG2", "12", b) }

// Failure tests
func TestPrecompiledBLS12381G1AddFail(t *testing.T)      { testJsonFail("blsG1Add", "0a", t) }
func TestPrecompiledBLS12381G1MulFail(t *testing.T)      { testJsonFail("blsG1Mul", "0b", t) }
func TestPrecompiledBLS12381G1MultiExpFail(t *testing.T) { testJsonFail("blsG1MultiExp", "0c", t) }
func TestPrecompiledBLS12381G2AddFail(t *testing.T)      { testJsonFail("blsG2Add", "0d", t) }
func TestPrecompiledBLS12381G2MulFail(t *testing.T)      { testJsonFail("blsG2Mul", "0e", t) }
func TestPrecompiledBLS12381G2MultiExpFail(t *testing.T) { testJsonFail("blsG2MultiExp", "0f", t) }
func TestPrecompiledBLS12381PairingFail(t *testing.T)    { testJsonFail("blsPairing", "10", t) }
func TestPrecompiledBLS12381MapG1Fail(t *testing.T)      { testJsonFail("blsMapG1", "11", t) }
func TestPrecompiledBLS12381MapG2Fail(t *testing.T)      { testJsonFail("blsMapG2", "12", t) }

func loadJson(name string) ([]precompiledTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

func loadJsonFail(name string) ([]precompiledFailureTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/fail-%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledFailureTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

// BenchmarkPrecompiledBLS12381G1MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G1MultiExpWorstCase(b *testing.B) {
	task := "0000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be1" +
		"0000000000000000000000000000000011bc8afe71676e6730702a46ef817060249cd06cd82e6981085012ff6d013aa4470ba3a2c71e13ef653e1e223d1ccfe9" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 4787; i++ {
		input = input + task
	}
	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000005a6310ea6f2a598023ae48819afc292b4dfcb40aabad24a0c2cb6c19769465691859eeb2a764342a810c5038d700f18000000000000000000000000000000001268ac944437d15923dc0aec00daa9250252e43e4b35ec7a19d01f0d6cd27f6e139d80dae16ba1c79cc7f57055a93ff5",
		Name:        "WorstCaseG1",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("0c", testcase, b)
}

// BenchmarkPrecompiledBLS12381G2MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G2MultiExpWorstCase(b *testing.B) {
	task := "000000000000000000000000000000000d4f09acd5f362e0a516d4c13c5e2f504d9bd49fdfb6d8b7a7ab35a02c391c8112b03270d5d9eefe9b659dd27601d18f" +
		"000000000000000000000000000000000fd489cb75945f3b5ebb1c0e326d59602934c8f78fe9294a8877e7aeb95de5addde0cb7ab53674df8b2cfbb036b30b99" +
		"00000000000000000000000000000000055dbc4eca768714e098bbe9c71cf54b40f51c26e95808ee79225a87fb6fa1415178db47f02d856fea56a752d185f86b" +
		"000000000000000000000000000000001239b7640f416eb6e921fe47f7501d504fadc190d9cf4e89ae2b717276739a2f4ee9f637c35e23c480df029fd8d247c7" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 1040; i++ {
		input = input + task
	}

	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000018f5ea0c8b086095cfe23f6bb1d90d45de929292006dba8cdedd6d3203af3c6bbfd592e93ecb2b2c81004961fdcbb46c00000000000000000000000000000000076873199175664f1b6493a43c02234f49dc66f077d3007823e0343ad92e30bd7dc209013435ca9f197aca44d88e9dac000000000000000000000000000000000e6f07f4b23b511eac1e2682a0fc224c15d80e122a3e222d00a41fab15eba645a700b9ae84f331ae4ed873678e2e6c9b000000000000000000000000000000000bcb4849e460612aaed79617255fd30c03f51cf03d2ed4163ca810c13e1954b1e8663157b957a601829bb272a4e6c7b8",
		Name:        "WorstCaseG2",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("0f", testcase, b)
}

// Zama-specific precompiled contracts

type statefulPrecompileAccessibleState struct {
	interpreter *EVMInterpreter
}

func (s *statefulPrecompileAccessibleState) Interpreter() *EVMInterpreter {
	return s.interpreter
}

func newTestInterpreter() *EVMInterpreter {
	cfg := Config{}
	evm := &EVM{}
	evm.Context = BlockContext{}
	evm.Context.Transfer = func(StateDB, common.Address, common.Address, *big.Int) {}
	evm.Context.CanTransfer = func(StateDB, common.Address, *big.Int) bool { return true }
	interpreter := NewEVMInterpreter(evm, cfg)
	evm.interpreter = interpreter
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	interpreter.evm.StateDB = state
	interpreter.evm.Commit = true
	interpreter.evm.Logger = &defaultLogger{}
	return interpreter
}

func newTestState() *statefulPrecompileAccessibleState {
	s := new(statefulPrecompileAccessibleState)
	interpreter := newTestInterpreter()
	s.interpreter = interpreter
	s.interpreter.testing = true
	return s
}

func verifyCiphertextInTestMemory(interpreter *EVMInterpreter, value uint64, depth int, t fheUintType) *tfheCiphertext {
	// Simulate as if the ciphertext is compact and comes externally.
	ser := encryptAndSerializeCompact(uint32(value), t)
	ct := new(tfheCiphertext)
	err := ct.deserializeCompact(ser, t)
	if err != nil {
		panic(err)
	}
	return verifyTfheCiphertextInTestMemory(interpreter, ct, depth)
}

func verifyTfheCiphertextInTestMemory(interpreter *EVMInterpreter, ct *tfheCiphertext, depth int) *tfheCiphertext {
	verifiedCiphertext := importCiphertextToEVMAtDepth(interpreter, ct, depth)
	return verifiedCiphertext.ciphertext
}

func toPrecompileInput(isScalar bool, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	var isScalarByte byte
	if isScalar {
		isScalarByte = 1
	} else {
		isScalarByte = 0
	}
	ret = append(ret, isScalarByte)
	return ret
}

var scalarBytePadding = make([]byte, 31)

func toLibPrecompileInput(method string, isScalar bool, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	hashRes := crypto.Keccak256([]byte(method))
	signature := hashRes[0:4]
	ret = append(ret, signature...)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	var isScalarByte byte
	if isScalar {
		isScalarByte = 1
	} else {
		isScalarByte = 0
	}
	ret = append(ret, isScalarByte)
	ret = append(ret, scalarBytePadding...)
	return ret
}

func toLibPrecompileInputNoScalar(method string, hashes ...common.Hash) []byte {
	ret := make([]byte, 0)
	hashRes := crypto.Keccak256([]byte(method))
	signature := hashRes[0:4]
	ret = append(ret, signature...)
	for _, hash := range hashes {
		ret = append(ret, hash.Bytes()...)
	}
	return ret
}

func VerifyCiphertext(t *testing.T, fheUintType fheUintType) {
	var value uint32
	switch fheUintType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	c := &verifyCiphertext{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	compact := encryptAndSerializeCompact(value, fheUintType)
	input := append(compact, byte(fheUintType))
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(tfheCiphertext)
	if err = ct.deserializeCompact(compact, fheUintType); err != nil {
		t.Fatalf(err.Error())
	}
	if common.BytesToHash(out) != ct.getHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, ct.getHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func VerifyCiphertextBadType(t *testing.T, actualType fheUintType, metadataType fheUintType) {
	var value uint32
	switch actualType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	c := &verifyCiphertext{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	compact := encryptAndSerializeCompact(value, actualType)
	input := append(compact, byte(metadataType))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on type mismatch")
	}
	if len(state.interpreter.verifiedCiphertexts) != 0 {
		t.Fatalf("verifyCiphertext mustn't have verified given ciphertext")
	}
}

func TrivialEncrypt(t *testing.T, fheUintType fheUintType) {
	var value big.Int
	switch fheUintType {
	case FheUint8:
		value = *big.NewInt(2)
	case FheUint16:
		value = *big.NewInt(4283)
	case FheUint32:
		value = *big.NewInt(1333337)
	}
	c := &trivialEncrypt{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	valueBytes := make([]byte, 32)
	input := append(value.FillBytes(valueBytes), byte(fheUintType))
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(tfheCiphertext).trivialEncrypt(value, fheUintType)
	if common.BytesToHash(out) != ct.getHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, ct.getHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func FheLibAdd(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs + rhs
	c := &fheLib{}
	signature := "fheAdd(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibSub(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs - rhs
	c := &fheLib{}
	signature := "fheSub(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibMul(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 3
		rhs = 2
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs * rhs
	c := &fheLib{}
	signature := "fheMul(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibLe(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheLib{}
	signature := "fheLe(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	// lhs <= rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs <= lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLibLt(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheLib{}
	signature := "fheLt(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	// lhs < rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs < lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLibEq(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheLib{}
	signature := "fheLt(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func FheLibGe(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheLib{}
	signature := "fheGe(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs >= rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs >= lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLibGt(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheLib{}
	signature := "fheGt(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs > rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs > lhs
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLibShl(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs << rhs
	c := &fheLib{}
	signature := "fheShl(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibShr(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs >> rhs
	c := &fheLib{}
	signature := "fheShr(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibNe(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheLib{}
	signature := "fheNe(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func FheLibMin(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheLib{}
	signature := "fheMin(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != rhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != rhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
		}
	}
}

func FheLibMax(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheLib{}
	signature := "fheMax(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != lhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toLibPrecompileInput(signature, false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != lhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
		}
	}
}

func FheLibNeg(t *testing.T, fheUintType fheUintType) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(-uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(-uint32(pt))
	}

	c := &fheLib{}
	signature := "fheNeg(uint256)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(state.interpreter, pt, depth, fheUintType).getHash()

	input := toLibPrecompileInputNoScalar(signature, ptHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibNot(t *testing.T, fheUintType fheUintType) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(^uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(^uint32(pt))
	}

	c := &fheLib{}
	signature := "fheNot(uint256)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(state.interpreter, pt, depth, fheUintType).getHash()

	input := toLibPrecompileInputNoScalar(signature, ptHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheLibDiv(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 4
		rhs = 2
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 137
		rhs = 17
	}
	expected := lhs / rhs
	c := &fheLib{}
	signature := "fheDiv(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar multiplication should fail")
		}
	}
}

func FheLibRem(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 7
		rhs = 3
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 1337
		rhs = 73
	}
	expected := lhs % rhs
	c := &fheLib{}
	signature := "fheRem(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar remainder should fail")
		}
	}
}

func FheLibBitAnd(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs & rhs
	c := &fheLib{}
	signature := "fheBitAnd(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit and should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibBitOr(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs | rhs
	c := &fheLib{}
	signature := "fheBitOr(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit or should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibBitXor(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs ^ rhs
	c := &fheLib{}
	signature := "fheBitXor(uint256,uint256,bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toLibPrecompileInput(signature, scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit xor should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheLibRand(t *testing.T, fheUintType fheUintType) {
	c := &fheLib{}
	signature := "fheRand(bytes1)"
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, byte(fheUintType))
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("fheRand expected output len of 32, got %v", len(out))
	}
	if len(state.interpreter.verifiedCiphertexts) != 1 {
		t.Fatalf("fheRand expected 1 verified ciphertext")
	}

	hash := common.BytesToHash(out)
	_, err = state.interpreter.verifiedCiphertexts[hash].ciphertext.decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func LibTrivialEncrypt(t *testing.T, fheUintType fheUintType) {
	var value big.Int
	switch fheUintType {
	case FheUint8:
		value = *big.NewInt(2)
	case FheUint16:
		value = *big.NewInt(4283)
	case FheUint32:
		value = *big.NewInt(1333337)
	}
	c := &fheLib{}
	signature := "trivialEncrypt(uint256,bytes1)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	valueBytes := make([]byte, 32)
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, value.FillBytes(valueBytes)...)
	input = append(input, byte(fheUintType))
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ct := new(tfheCiphertext).trivialEncrypt(value, fheUintType)
	if common.BytesToHash(out) != ct.getHash() {
		t.Fatalf("output hash in verifyCipertext is incorrect")
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, ct.getHash())
	if res == nil {
		t.Fatalf("verifyCiphertext must have verified given ciphertext")
	}
}

func LibDecrypt(t *testing.T, fheUintType fheUintType) {
	var value uint64
	switch fheUintType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	c := &fheLib{}
	signature := "decrypt(uint256)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	hash := verifyCiphertextInTestMemory(state.interpreter, value, depth, fheUintType).getHash()
	input = append(input, signatureBytes...)
	input = append(input, hash.Bytes()...)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("decrypt expected output len of 32, got %v", len(out))
	}
	result := big.Int{}
	result.SetBytes(out)
	if result.Uint64() != value {
		t.Fatalf("decrypt result not equal to value, result %v != value %v", result.Uint64(), value)
	}
}

func TestLibVerifyCiphertextInvalidType(t *testing.T) {
	c := &fheLib{}
	signature := "verifyCiphertext(bytes)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := fheUintType(255)
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	compact := encryptAndSerializeCompact(0, FheUint32)
	input = append(input, compact...)
	input = append(input, byte(invalidType))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext type")
	}

	if !strings.Contains(err.Error(), "ciphertext type is invalid") {
		t.Fatalf("Unexpected test error: %s", err.Error())
	}
}

func TestLibReencrypt(t *testing.T) {
	c := &fheLib{}
	signature := "reencrypt(uint256,uint256)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	state.interpreter.evm.EthCall = true
	toEncrypt := 7
	fheUintType := FheUint8
	encCiphertext := verifyCiphertextInTestMemory(state.interpreter, uint64(toEncrypt), depth, fheUintType).getHash()
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, encCiphertext.Bytes()...)
	// just append twice not to generate public key
	input = append(input, encCiphertext.Bytes()...)
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf("Reencrypt error: %s", err.Error())
	}
}
func TestLibOneTrueOptimisticRequire(t *testing.T) {
	var value uint64 = 1
	c := &fheLib{}
	signature := "optimisticRequire(uint256)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	hash := verifyCiphertextInTestMemory(state.interpreter, value, depth, FheUint8).getHash()
	input = append(input, signatureBytes...)
	input = append(input, hash.Bytes()...)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = state.interpreter.Run(newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestLibCast(t *testing.T) {
	c := &fheLib{}
	signature := "cast(uint256,bytes1)"
	hashRes := crypto.Keccak256([]byte(signature))
	signatureBytes := hashRes[0:4]
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	state.interpreter.evm.EthCall = true
	toEncrypt := 7
	fheUintType := FheUint8
	encCiphertext := verifyCiphertextInTestMemory(state.interpreter, uint64(toEncrypt), depth, fheUintType).getHash()
	addr := common.Address{}
	readOnly := false
	input := make([]byte, 0)
	input = append(input, signatureBytes...)
	input = append(input, encCiphertext.Bytes()...)
	input = append(input, byte(FheUint32))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf("Reencrypt error: %s", err.Error())
	}
}

func FheAdd(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs + rhs
	c := &fheAdd{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheSub(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs - rhs
	c := &fheSub{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheMul(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 169
		rhs = 5
	case FheUint32:
		lhs = 137
		rhs = 17
	}
	expected := lhs * rhs
	c := &fheMul{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheDiv(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 4
		rhs = 2
	case FheUint16:
		lhs = 721
		rhs = 1000
	case FheUint32:
		lhs = 137
		rhs = 17
	}
	expected := lhs / rhs
	c := &fheDiv{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar multiplication should fail")
		}
	}
}

func FheRem(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 9
		rhs = 5
	case FheUint16:
		lhs = 1773
		rhs = 523
	case FheUint32:
		lhs = 123765
		rhs = 2179
	}
	expected := lhs % rhs
	c := &fheRem{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	} else {
		if err == nil {
			t.Fatal("Non scalar remainder should fail")
		}
	}
}

func FheBitAnd(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs & rhs
	c := &fheBitAnd{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit and should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheBitOr(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs | rhs
	c := &fheBitOr{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit or should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheBitXor(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	expected := lhs ^ rhs
	c := &fheBitXor{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if scalar {
		if err == nil {
			t.Fatalf("scalar bit xor should have failed")
		}
	} else {
		if err != nil {
			t.Fatalf(err.Error())
		}
		res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err := res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != expected {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
		}
	}
}

func FheShl(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs << rhs
	c := &fheShl{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheShr(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 2
	case FheUint32:
		lhs = 1333337
		rhs = 3
	}
	expected := lhs >> rhs
	c := &fheShr{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheEq(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheEq{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}
}

func FheNe(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheNe{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs == rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
}

func FheGe(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheGe{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs >= rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}
	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs >= lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheGt(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheGt{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}
	// lhs > rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 1 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs > lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 0 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
		}
	}
}

func FheLe(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}
	c := &fheLe{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	// lhs <= rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs <= lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheLt(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheLt{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	// lhs < rhs
	input1 := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input1, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != 0 {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 0)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		// rhs < lhs
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != 1 {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), 1)
		}
	}
}

func FheMin(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheMin{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != rhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != rhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), rhs)
		}
	}
}

func FheMax(t *testing.T, fheUintType fheUintType, scalar bool) {
	var lhs, rhs uint64
	switch fheUintType {
	case FheUint8:
		lhs = 2
		rhs = 1
	case FheUint16:
		lhs = 4283
		rhs = 1337
	case FheUint32:
		lhs = 1333337
		rhs = 133337
	}

	c := &fheMax{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsHash := verifyCiphertextInTestMemory(state.interpreter, lhs, depth, fheUintType).getHash()
	var rhsHash common.Hash
	if scalar {
		rhsHash = common.BytesToHash(big.NewInt(int64(rhs)).Bytes())
	} else {
		rhsHash = verifyCiphertextInTestMemory(state.interpreter, rhs, depth, fheUintType).getHash()
	}

	input := toPrecompileInput(scalar, lhsHash, rhsHash)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != lhs {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
	}

	// Inverting operands is only possible in the non scalar case as scalar
	// operators expect the scalar to be on the rhs.
	if !scalar {
		input2 := toPrecompileInput(false, rhsHash, lhsHash)
		out, err = c.Run(state, addr, addr, input2, readOnly)
		if err != nil {
			t.Fatalf(err.Error())
		}
		res = getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
		if res == nil {
			t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
		}
		decrypted, err = res.ciphertext.decrypt()
		if err != nil || decrypted.Uint64() != lhs {
			t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), lhs)
		}
	}
}

func FheNeg(t *testing.T, fheUintType fheUintType, scalar bool) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(-uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(-uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(-uint32(pt))
	}

	c := &fheNeg{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(state.interpreter, pt, depth, fheUintType).getHash()

	input := make([]byte, 0)
	input = append(input, ptHash.Bytes()...)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func FheNot(t *testing.T, fheUintType fheUintType, scalar bool) {
	var pt, expected uint64
	switch fheUintType {
	case FheUint8:
		pt = 2
		expected = uint64(^uint8(pt))
	case FheUint16:
		pt = 4283
		expected = uint64(^uint16(pt))
	case FheUint32:
		pt = 1333337
		expected = uint64(^uint32(pt))
	}

	c := &fheNot{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	ptHash := verifyCiphertextInTestMemory(state.interpreter, pt, depth, fheUintType).getHash()

	input := make([]byte, 0)
	input = append(input, ptHash.Bytes()...)
	out, err := c.Run(state, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(state.interpreter, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decrypted, err := res.ciphertext.decrypt()
	if err != nil || decrypted.Uint64() != expected {
		t.Fatalf("invalid decrypted result, decrypted %v != expected %v", decrypted.Uint64(), expected)
	}
}

func Decrypt(t *testing.T, fheUintType fheUintType) {
	var value uint64
	switch fheUintType {
	case FheUint8:
		value = 2
	case FheUint16:
		value = 4283
	case FheUint32:
		value = 1333337
	}
	c := &decrypt{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(state.interpreter, value, depth, fheUintType).getHash()
	out, err := c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("decrypt expected output len of 32, got %v", len(out))
	}
	result := big.Int{}
	result.SetBytes(out)
	if result.Uint64() != value {
		t.Fatalf("decrypt result not equal to value, result %v != value %v", result.Uint64(), value)
	}
}

func FheRand(t *testing.T, fheUintType fheUintType) {
	c := &fheRand{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	out, err := c.Run(state, addr, addr, []byte{byte(fheUintType)}, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("fheRand expected output len of 32, got %v", len(out))
	}
	if len(state.interpreter.verifiedCiphertexts) != 1 {
		t.Fatalf("fheRand expected 1 verified ciphertext")
	}

	hash := common.BytesToHash(out)
	_, err = state.interpreter.verifiedCiphertexts[hash].ciphertext.decrypt()
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func newStopOpcodeContract() *Contract {
	addr := AccountRef{}
	c := NewContract(addr, addr, big.NewInt(0), 100000)
	c.Code = make([]byte, 1)
	c.Code[0] = byte(STOP)
	return c
}

func TestOneTrueOptimisticRequire(t *testing.T) {
	var value uint64 = 1
	c := &optimisticRequire{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(state.interpreter, value, depth, FheUint8).getHash()
	out, err := c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = state.interpreter.Run(newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestTwoTrueOptimisticRequires(t *testing.T) {
	var value uint64 = 1
	c := &optimisticRequire{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(state.interpreter, value, depth, FheUint8).getHash()
	out, err := c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	hash = verifyCiphertextInTestMemory(state.interpreter, value, depth, FheUint8).getHash()
	out, err = c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = state.interpreter.Run(newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestOptimisticRequireTwiceOnSameCiphertext(t *testing.T) {
	var value uint64 = 1
	c := &optimisticRequire{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	ct := verifyCiphertextInTestMemory(state.interpreter, value, depth, FheUint8)
	hash := ct.getHash()
	out, err := c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	out, err = c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call the interpreter with a single STOP opcode and expect that the optimistic require doesn't revert.
	out, err = state.interpreter.Run(newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestOneFalseOptimisticRequire(t *testing.T) {
	var value uint64 = 0
	c := &optimisticRequire{}
	depth := 0
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(state.interpreter, value, depth, FheUint8).getHash()
	out, err := c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call the interpreter with a single STOP opcode and expect that the optimistic require reverts.
	out, err = state.interpreter.Run(newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err == nil || err != ErrExecutionReverted {
		t.Fatalf("require expected reversal on value 0")
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestOneFalseAndOneTrueOptimisticRequire(t *testing.T) {
	c := &optimisticRequire{}
	depth := 0
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	hash := verifyCiphertextInTestMemory(state.interpreter, 0, depth, FheUint8).getHash()
	out, err := c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	hash = verifyCiphertextInTestMemory(state.interpreter, 1, depth, FheUint8).getHash()
	out, err = c.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call the interpreter with a single STOP opcode and expect that the optimistic require reverts.
	out, err = state.interpreter.Run(newStopOpcodeContract(), make([]byte, 0), readOnly)
	if err == nil || err != ErrExecutionReverted {
		t.Fatalf("require expected reversal on value 0")
	} else if out != nil {
		t.Fatalf("expected empty response")
	}
}

func TestDecryptWithFalseOptimisticRequire(t *testing.T) {
	opt := &optimisticRequire{}
	dec := &decrypt{}
	depth := 0
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	// Call optimistic require with a false value and expect it succeeds.
	hash := verifyCiphertextInTestMemory(state.interpreter, 0, depth, FheUint8).getHash()
	out, err := opt.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call decrypt and expect it to fail due to the optimistic require being false.
	_, err = dec.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err == nil {
		t.Fatalf("expected decrypt fails due to false optimistic require")
	}
	// Make sure there are no more optimistic requires after the decrypt call.
	if len(state.interpreter.optimisticRequires) != 0 {
		t.Fatalf("expected that there are no optimistic requires after decrypt")
	}
}

func TestDecryptWithTrueOptimisticRequire(t *testing.T) {
	opt := &optimisticRequire{}
	dec := &decrypt{}
	depth := 0
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	// Call optimistic require with a false value and expect it succeeds.
	hash := verifyCiphertextInTestMemory(state.interpreter, 1, depth, FheUint8).getHash()
	out, err := opt.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 0 {
		t.Fatalf("require expected output len of 0, got %v", len(out))
	}
	// Call decrypt and expect it to succeed due to the optimistic require being true.
	out, err = dec.Run(state, addr, addr, hash.Bytes(), readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	} else if len(out) != 32 {
		t.Fatalf("decrypt expected output len of 32, got %v", len(out))
	}
	// Make sure there are no more optimistic requires after the decrypt call.
	if len(state.interpreter.optimisticRequires) != 0 {
		t.Fatalf("expected that there are no optimistic requires after decrypt")
	}
}

func TestVerifyCiphertextInvalidType(t *testing.T) {
	c := &verifyCiphertext{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := fheUintType(255)
	compact := encryptAndSerializeCompact(0, FheUint32)
	input := append(compact, byte(invalidType))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext type")
	}
}

func TestTrivialEncryptInvalidType(t *testing.T) {
	c := &trivialEncrypt{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := fheUintType(255)
	input := make([]byte, 32)
	input = append(input, byte(invalidType))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("trivialEncrypt must have failed on invalid ciphertext type")
	}
}

func TestCastInvalidType(t *testing.T) {
	c := &cast{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	invalidType := fheUintType(255)
	hash := verifyCiphertextInTestMemory(state.interpreter, 1, depth, FheUint8).getHash()
	input := make([]byte, 0)
	input = append(input, hash.Bytes()...)
	input = append(input, byte(invalidType))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("cast must have failed on invalid ciphertext type")
	}
}

func TestVerifyCiphertextInvalidSize(t *testing.T) {
	c := &verifyCiphertext{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	ctType := FheUint32
	compact := encryptAndSerializeCompact(0, ctType)
	input := append(compact[:len(compact)-1], byte(ctType))
	_, err := c.Run(state, addr, addr, input, readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must have failed on invalid ciphertext size")
	}
}

func TestVerifyCiphertext8(t *testing.T) {
	VerifyCiphertext(t, FheUint8)
}

func TestVerifyCiphertext16(t *testing.T) {
	VerifyCiphertext(t, FheUint16)
}

func TestVerifyCiphertext32(t *testing.T) {
	VerifyCiphertext(t, FheUint32)
}

func TestTrivialEncrypt8(t *testing.T) {
	TrivialEncrypt(t, FheUint8)
}

func TestTrivialEncrypt16(t *testing.T) {
	TrivialEncrypt(t, FheUint16)
}

func TestTrivialEncrypt32(t *testing.T) {
	TrivialEncrypt(t, FheUint32)
}

func TestVerifyCiphertext8BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint8, FheUint16)
	VerifyCiphertextBadType(t, FheUint8, FheUint32)
}

func TestVerifyCiphertext16BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint16, FheUint8)
	VerifyCiphertextBadType(t, FheUint16, FheUint32)
}

func TestVerifyCiphertext32BadType(t *testing.T) {
	VerifyCiphertextBadType(t, FheUint32, FheUint8)
	VerifyCiphertextBadType(t, FheUint32, FheUint16)
}

func TestVerifyCiphertextBadCiphertext(t *testing.T) {
	c := &verifyCiphertext{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	_, err := c.Run(state, addr, addr, make([]byte, 10), readOnly)
	if err == nil {
		t.Fatalf("verifyCiphertext must fail on bad ciphertext input")
	}
	if len(state.interpreter.verifiedCiphertexts) != 0 {
		t.Fatalf("verifyCiphertext mustn't have verified given ciphertext")
	}
}

func TestFheLibAdd8(t *testing.T) {
	FheLibAdd(t, FheUint8, false)
}

func TestFheLibSub8(t *testing.T) {
	FheLibSub(t, FheUint8, false)
}

func TestFheLibMul8(t *testing.T) {
	FheLibMul(t, FheUint8, false)
}

func TestFheLibLe8(t *testing.T) {
	FheLibLe(t, FheUint8, false)
}

func TestFheLibLt8(t *testing.T) {
	FheLibLt(t, FheUint8, false)
}

func TestFheLibEq8(t *testing.T) {
	FheLibEq(t, FheUint8, false)
}

func TestFheLibGe8(t *testing.T) {
	FheLibGe(t, FheUint8, false)
}

func TestFheLibGt8(t *testing.T) {
	FheLibGt(t, FheUint8, false)
}

func TestFheLibShl8(t *testing.T) {
	FheLibShl(t, FheUint8, false)
}

func TestFheLibShr8(t *testing.T) {
	FheLibShr(t, FheUint8, false)
}

func TestFheLibNe8(t *testing.T) {
	FheLibNe(t, FheUint8, false)
}

func TestFheLibMin8(t *testing.T) {
	FheLibMin(t, FheUint8, false)
}

func TestFheLibMax8(t *testing.T) {
	FheLibMax(t, FheUint8, false)
}

func TestFheLibNeg8(t *testing.T) {
	FheLibNeg(t, FheUint8)
}

func TestFheLibNot8(t *testing.T) {
	FheLibNot(t, FheUint8)
}

func TestFheLibDiv8(t *testing.T) {
	FheLibDiv(t, FheUint8, true)
}

func TestFheLibRem8(t *testing.T) {
	FheLibRem(t, FheUint8, true)
}

func TestFheLibBitAnd8(t *testing.T) {
	FheLibBitAnd(t, FheUint8, false)
}

func TestFheLibBitOr8(t *testing.T) {
	FheLibBitOr(t, FheUint8, false)
}

func TestFheLibBitXor8(t *testing.T) {
	FheLibBitXor(t, FheUint8, false)
}

func TestFheLibRand8(t *testing.T) {
	FheLibRand(t, FheUint8)
}

func TestFheLibTrivialEncrypt8(t *testing.T) {
	LibTrivialEncrypt(t, FheUint8)
}

func TestLibDecrypt8(t *testing.T) {
	LibDecrypt(t, FheUint8)
}

func TestFheAdd8(t *testing.T) {
	FheAdd(t, FheUint8, false)
}

func TestFheAdd16(t *testing.T) {
	FheAdd(t, FheUint16, false)
}

func TestFheAdd32(t *testing.T) {
	FheAdd(t, FheUint32, false)
}

func TestFheScalarAdd8(t *testing.T) {
	FheAdd(t, FheUint8, true)
}

func TestFheScalarAdd16(t *testing.T) {
	FheAdd(t, FheUint16, true)
}

func TestFheScalarAdd32(t *testing.T) {
	FheAdd(t, FheUint32, true)
}

func TestFheSub8(t *testing.T) {
	FheSub(t, FheUint8, false)
}

func TestFheSub16(t *testing.T) {
	FheSub(t, FheUint16, false)
}

func TestFheSub32(t *testing.T) {
	FheSub(t, FheUint32, false)
}

func TestFheScalarSub8(t *testing.T) {
	FheSub(t, FheUint8, true)
}

func TestFheScalarSub16(t *testing.T) {
	FheSub(t, FheUint16, true)
}

func TestFheScalarSub32(t *testing.T) {
	FheSub(t, FheUint32, true)
}

func TestFheMul8(t *testing.T) {
	FheMul(t, FheUint8, false)
}

func TestFheMul16(t *testing.T) {
	FheMul(t, FheUint16, false)
}

func TestFheMul32(t *testing.T) {
	FheMul(t, FheUint32, false)
}

func TestFheScalarMul8(t *testing.T) {
	FheMul(t, FheUint8, true)
}

func TestFheScalarMul16(t *testing.T) {
	FheMul(t, FheUint16, true)
}

func TestFheScalarMul32(t *testing.T) {
	FheMul(t, FheUint32, true)
}

func TestFheDiv8(t *testing.T) {
	FheDiv(t, FheUint8, false)
}

func TestFheDiv16(t *testing.T) {
	FheDiv(t, FheUint16, false)
}

func TestFheDiv32(t *testing.T) {
	FheDiv(t, FheUint32, false)
}

func TestFheScalarDiv8(t *testing.T) {
	FheDiv(t, FheUint8, true)
}

func TestFheScalarDiv16(t *testing.T) {
	FheDiv(t, FheUint16, true)
}

func TestFheScalarDiv32(t *testing.T) {
	FheDiv(t, FheUint32, true)
}

func TestFheRem8(t *testing.T) {
	FheRem(t, FheUint8, false)
}

func TestFheRem16(t *testing.T) {
	FheRem(t, FheUint16, false)
}

func TestFheRem32(t *testing.T) {
	FheRem(t, FheUint32, false)
}

func TestFheScalarRem8(t *testing.T) {
	FheRem(t, FheUint8, true)
}

func TestFheScalarRem16(t *testing.T) {
	FheRem(t, FheUint16, true)
}

func TestFheScalarRem32(t *testing.T) {
	FheRem(t, FheUint32, true)
}

func TestFheBitAnd8(t *testing.T) {
	FheBitAnd(t, FheUint8, false)
}

func TestFheBitAnd16(t *testing.T) {
	FheBitAnd(t, FheUint16, false)
}

func TestFheBitAnd32(t *testing.T) {
	FheBitAnd(t, FheUint32, false)
}

func TestFheScalarBitAnd8(t *testing.T) {
	FheBitAnd(t, FheUint8, true)
}

func TestFheScalarBitAnd16(t *testing.T) {
	FheBitAnd(t, FheUint16, true)
}

func TestFheScalarBitAnd32(t *testing.T) {
	FheBitAnd(t, FheUint32, true)
}

func TestFheBitOr8(t *testing.T) {
	FheBitOr(t, FheUint8, false)
}

func TestFheBitOr16(t *testing.T) {
	FheBitOr(t, FheUint16, false)
}

func TestFheBitOr32(t *testing.T) {
	FheBitOr(t, FheUint32, false)
}

func TestFheScalarBitOr8(t *testing.T) {
	FheBitOr(t, FheUint8, true)
}

func TestFheScalarBitOr16(t *testing.T) {
	FheBitOr(t, FheUint16, true)
}

func TestFheScalarBitOr32(t *testing.T) {
	FheBitOr(t, FheUint32, true)
}

func TestFheBitXor8(t *testing.T) {
	FheBitXor(t, FheUint8, false)
}

func TestFheBitXor16(t *testing.T) {
	FheBitXor(t, FheUint16, false)
}

func TestFheBitXor32(t *testing.T) {
	FheBitXor(t, FheUint32, false)
}

func TestFheScalarBitXor8(t *testing.T) {
	FheBitXor(t, FheUint8, true)
}

func TestFheScalarBitXor16(t *testing.T) {
	FheBitXor(t, FheUint16, true)
}

func TestFheScalarBitXor32(t *testing.T) {
	FheBitXor(t, FheUint32, true)
}

func TestFheShl8(t *testing.T) {
	FheShl(t, FheUint8, false)
}

func TestFheShl16(t *testing.T) {
	FheShl(t, FheUint16, false)
}

func TestFheShl32(t *testing.T) {
	FheShl(t, FheUint32, false)
}

func TestFheScalarShl8(t *testing.T) {
	FheShl(t, FheUint8, true)
}

func TestFheScalarShl16(t *testing.T) {
	FheShl(t, FheUint16, true)
}

func TestFheScalarShl32(t *testing.T) {
	FheShl(t, FheUint32, true)
}

func TestFheShr8(t *testing.T) {
	FheShr(t, FheUint8, false)
}

func TestFheShr16(t *testing.T) {
	FheShr(t, FheUint16, false)
}

func TestFheShr32(t *testing.T) {
	FheShr(t, FheUint32, false)
}

func TestFheScalarShr8(t *testing.T) {
	FheShr(t, FheUint8, true)
}

func TestFheScalarShr16(t *testing.T) {
	FheShr(t, FheUint16, true)
}

func TestFheScalarShr32(t *testing.T) {
	FheShr(t, FheUint32, true)
}

func TestFheEq8(t *testing.T) {
	FheEq(t, FheUint8, false)
}

func TestFheEq16(t *testing.T) {
	FheEq(t, FheUint16, false)
}

func TestFheEq32(t *testing.T) {
	FheEq(t, FheUint32, false)
}

func TestFheScalarEq8(t *testing.T) {
	FheEq(t, FheUint8, true)
}

func TestFheScalarEq16(t *testing.T) {
	FheEq(t, FheUint16, true)
}

func TestFheScalarEq32(t *testing.T) {
	FheEq(t, FheUint32, true)
}

func TestFheNe8(t *testing.T) {
	FheNe(t, FheUint8, false)
}

func TestFheNe16(t *testing.T) {
	FheNe(t, FheUint16, false)
}

func TestFheNe32(t *testing.T) {
	FheNe(t, FheUint32, false)
}

func TestFheScalarNe8(t *testing.T) {
	FheNe(t, FheUint8, true)
}

func TestFheScalarNe16(t *testing.T) {
	FheNe(t, FheUint16, true)
}

func TestFheScalarNe32(t *testing.T) {
	FheNe(t, FheUint32, true)
}

func TestFheGe8(t *testing.T) {
	FheGe(t, FheUint8, false)
}

func TestFheGe16(t *testing.T) {
	FheGe(t, FheUint16, false)
}

func TestFheGe32(t *testing.T) {
	FheGe(t, FheUint32, false)
}

func TestFheScalarGe8(t *testing.T) {
	FheGe(t, FheUint8, true)
}

func TestFheScalarGe16(t *testing.T) {
	FheGe(t, FheUint16, true)
}

func TestFheScalarGe32(t *testing.T) {
	FheGe(t, FheUint32, true)
}

func TestFheGt8(t *testing.T) {
	FheGt(t, FheUint8, false)
}

func TestFheGt16(t *testing.T) {
	FheGt(t, FheUint16, false)
}

func TestFheGt32(t *testing.T) {
	FheGt(t, FheUint32, false)
}

func TestFheScalarGt8(t *testing.T) {
	FheGt(t, FheUint8, true)
}

func TestFheScalarGt16(t *testing.T) {
	FheGt(t, FheUint16, true)
}

func TestFheScalarGt32(t *testing.T) {
	FheGt(t, FheUint32, true)
}

func TestFheLe8(t *testing.T) {
	FheLe(t, FheUint8, false)
}

func TestFheLe16(t *testing.T) {
	FheLe(t, FheUint16, false)
}

func TestFheLe32(t *testing.T) {
	FheLe(t, FheUint32, false)
}

func TestFheScalarLe8(t *testing.T) {
	FheLe(t, FheUint8, true)
}

func TestFheScalarLe16(t *testing.T) {
	FheLe(t, FheUint16, true)
}

func TestFheScalarLe32(t *testing.T) {
	FheLe(t, FheUint32, true)
}

func TestFheLt8(t *testing.T) {
	FheLt(t, FheUint8, false)
}

func TestFheLt16(t *testing.T) {
	FheLt(t, FheUint16, false)
}

func TestFheLt32(t *testing.T) {
	FheLt(t, FheUint32, false)
}

func TestFheScalarLt8(t *testing.T) {
	FheLt(t, FheUint8, true)
}

func TestFheScalarLt16(t *testing.T) {
	FheLt(t, FheUint16, true)
}

func TestFheScalarLt32(t *testing.T) {
	FheLt(t, FheUint32, true)
}

func TestFheMin8(t *testing.T) {
	FheMin(t, FheUint8, false)
}

func TestFheMin16(t *testing.T) {
	FheMin(t, FheUint16, false)
}

func TestFheMin32(t *testing.T) {
	FheMin(t, FheUint32, false)
}

func TestFheScalarMin8(t *testing.T) {
	FheMin(t, FheUint8, true)
}

func TestFheScalarMin16(t *testing.T) {
	FheMin(t, FheUint16, true)
}

func TestFheScalarMin32(t *testing.T) {
	FheMin(t, FheUint32, true)
}

func TestFheMax8(t *testing.T) {
	FheMax(t, FheUint8, false)
}

func TestFheMax16(t *testing.T) {
	FheMax(t, FheUint16, false)
}

func TestFheMax32(t *testing.T) {
	FheMax(t, FheUint32, false)
}

func TestFheNeg8(t *testing.T) {
	FheNeg(t, FheUint8, false)
}

func TestFheNeg16(t *testing.T) {
	FheNeg(t, FheUint16, false)
}

func TestFheNeg32(t *testing.T) {
	FheNeg(t, FheUint32, false)
}

func TestFheNot8(t *testing.T) {
	FheNot(t, FheUint8, false)
}

func TestFheNot16(t *testing.T) {
	FheNot(t, FheUint16, false)
}

func TestFheNot32(t *testing.T) {
	FheNot(t, FheUint32, false)
}

func TestFheScalarMax8(t *testing.T) {
	FheMax(t, FheUint8, true)
}

func TestFheScalarMax16(t *testing.T) {
	FheMax(t, FheUint16, true)
}

func TestFheScalarMax32(t *testing.T) {
	FheMax(t, FheUint32, true)
}

func TestDecrypt8(t *testing.T) {
	Decrypt(t, FheUint8)
}

func TestDecrypt16(t *testing.T) {
	Decrypt(t, FheUint16)
}

func TestDecrypt32(t *testing.T) {
	Decrypt(t, FheUint32)
}

func TestFheRand8(t *testing.T) {
	FheRand(t, FheUint8)
}

func TestFheRand16(t *testing.T) {
	FheRand(t, FheUint16)
}

func TestFheRand32(t *testing.T) {
	FheRand(t, FheUint32)
}

func TestUnknownCiphertextHandle(t *testing.T) {
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	hash := verifyCiphertextInTestMemory(state.interpreter, 2, depth, FheUint8).getHash()

	ct := getVerifiedCiphertext(state, hash)
	if ct == nil {
		t.Fatalf("expected that ciphertext is verified")
	}

	// change the hash
	hash[0]++
	ct = getVerifiedCiphertext(state, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified")
	}
}

func TestCiphertextNotVerifiedWithoutReturn(t *testing.T) {
	state := newTestState()
	state.interpreter.evm.depth = 1
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(state.interpreter, 1, verifiedDepth, FheUint8).getHash()

	ct := getVerifiedCiphertext(state, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified")
	}
}

func TestCiphertextNotAutomaticallyDelegated(t *testing.T) {
	state := newTestState()
	state.interpreter.evm.depth = 3
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(state.interpreter, 1, verifiedDepth, FheUint8).getHash()

	ct := getVerifiedCiphertext(state, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at depth (%d)", state.interpreter.evm.depth)
	}
}

func TestCiphertextVerificationConditions(t *testing.T) {
	state := newTestState()
	verifiedDepth := 2
	hash := verifyCiphertextInTestMemory(state.interpreter, 1, verifiedDepth, FheUint8).getHash()

	state.interpreter.evm.depth = verifiedDepth
	ctPtr := getVerifiedCiphertext(state, hash)
	if ctPtr == nil {
		t.Fatalf("expected that ciphertext is verified at verifiedDepth (%d)", verifiedDepth)
	}

	state.interpreter.evm.depth = verifiedDepth + 1
	ct := getVerifiedCiphertext(state, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at verifiedDepth + 1 (%d)", verifiedDepth+1)
	}

	state.interpreter.evm.depth = verifiedDepth - 1
	ct = getVerifiedCiphertext(state, hash)
	if ct != nil {
		t.Fatalf("expected that ciphertext is not verified at verifiedDepth - 1 (%d)", verifiedDepth-1)
	}
}

func TestFheRandInvalidInput(t *testing.T) {
	c := &fheRand{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	_, err := c.Run(state, addr, addr, []byte{}, readOnly)
	if err == nil {
		t.Fatalf("fheRand expected failure on invalid type")
	}
	if len(state.interpreter.verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on invalid input")
	}
}

func TestFheRandInvalidType(t *testing.T) {
	c := &fheRand{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	addr := common.Address{}
	readOnly := false
	_, err := c.Run(state, addr, addr, []byte{byte(254)}, readOnly)
	if err == nil {
		t.Fatalf("fheRand expected failure on invalid type")
	}
	if len(state.interpreter.verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on invalid type")
	}
}

func TestFheRandEthCall(t *testing.T) {
	c := &fheRand{}
	depth := 1
	state := newTestState()
	state.interpreter.evm.depth = depth
	state.interpreter.evm.EthCall = true
	addr := common.Address{}
	readOnly := true
	_, err := c.Run(state, addr, addr, []byte{byte(FheUint8)}, readOnly)
	if err == nil {
		t.Fatalf("fheRand expected failure on EthCall")
	}
	if len(state.interpreter.verifiedCiphertexts) != 0 {
		t.Fatalf("fheRand expected 0 verified ciphertexts on EthCall")
	}
}
