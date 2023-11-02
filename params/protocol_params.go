// Copyright 2015 The go-ethereum Authors
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

package params

import "math/big"

const (
	GasLimitBoundDivisor uint64 = 1024               // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit          uint64 = 5000               // Minimum the gas limit may ever be.
	MaxGasLimit          uint64 = 0x7fffffffffffffff // Maximum the gas limit (2^63-1).
	GenesisGasLimit      uint64 = 4712388            // Gas limit of the Genesis block.

	MaximumExtraDataSize  uint64 = 32    // Maximum size extra data may be after Genesis.
	ExpByteGas            uint64 = 10    // Times ceil(log256(exponent)) for the EXP instruction.
	SloadGas              uint64 = 50    // Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added.
	CallValueTransferGas  uint64 = 9000  // Paid for CALL when the value transfer is non-zero.
	CallNewAccountGas     uint64 = 25000 // Paid for CALL when the destination address didn't exist prior.
	TxGas                 uint64 = 21000 // Per transaction not creating a contract. NOTE: Not payable on data of calls between transactions.
	TxGasContractCreation uint64 = 53000 // Per transaction that creates a contract. NOTE: Not payable on data of calls between transactions.
	TxDataZeroGas         uint64 = 4     // Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions.
	QuadCoeffDiv          uint64 = 512   // Divisor for the quadratic particle of the memory cost equation.
	LogDataGas            uint64 = 8     // Per byte in a LOG* operation's data.
	CallStipend           uint64 = 2300  // Free gas given at beginning of call.

	Keccak256Gas     uint64 = 30 // Once per KECCAK256 operation.
	Keccak256WordGas uint64 = 6  // Once per word of the KECCAK256 operation's data.

	SstoreSetGas    uint64 = 20000 // Once per SSTORE operation.
	SstoreResetGas  uint64 = 5000  // Once per SSTORE operation if the zeroness changes from zero.
	SstoreClearGas  uint64 = 5000  // Once per SSTORE operation if the zeroness doesn't change.
	SstoreRefundGas uint64 = 15000 // Once per SSTORE operation if the zeroness changes to zero.

	NetSstoreNoopGas  uint64 = 200   // Once per SSTORE operation if the value doesn't change.
	NetSstoreInitGas  uint64 = 20000 // Once per SSTORE operation from clean zero.
	NetSstoreCleanGas uint64 = 5000  // Once per SSTORE operation from clean non-zero.
	NetSstoreDirtyGas uint64 = 200   // Once per SSTORE operation from dirty.

	NetSstoreClearRefund      uint64 = 15000 // Once per SSTORE operation for clearing an originally existing storage slot
	NetSstoreResetRefund      uint64 = 4800  // Once per SSTORE operation for resetting to the original non-zero value
	NetSstoreResetClearRefund uint64 = 19800 // Once per SSTORE operation for resetting to the original zero value

	SstoreSentryGasEIP2200            uint64 = 2300  // Minimum gas required to be present for an SSTORE call, not consumed
	SstoreSetGasEIP2200               uint64 = 20000 // Once per SSTORE operation from clean zero to non-zero
	SstoreResetGasEIP2200             uint64 = 5000  // Once per SSTORE operation from clean non-zero to something else
	SstoreClearsScheduleRefundEIP2200 uint64 = 15000 // Once per SSTORE operation for clearing an originally existing storage slot

	ColdAccountAccessCostEIP2929 = uint64(2600) // COLD_ACCOUNT_ACCESS_COST
	ColdSloadCostEIP2929         = uint64(2100) // COLD_SLOAD_COST
	WarmStorageReadCostEIP2929   = uint64(100)  // WARM_STORAGE_READ_COST

	// In EIP-2200: SstoreResetGas was 5000.
	// In EIP-2929: SstoreResetGas was changed to '5000 - COLD_SLOAD_COST'.
	// In EIP-3529: SSTORE_CLEARS_SCHEDULE is defined as SSTORE_RESET_GAS + ACCESS_LIST_STORAGE_KEY_COST
	// Which becomes: 5000 - 2100 + 1900 = 4800
	SstoreClearsScheduleRefundEIP3529 uint64 = SstoreResetGasEIP2200 - ColdSloadCostEIP2929 + TxAccessListStorageKeyGas

	JumpdestGas   uint64 = 1     // Once per JUMPDEST operation.
	EpochDuration uint64 = 30000 // Duration between proof-of-work epochs.

	CreateDataGas         uint64 = 200   //
	CallCreateDepth       uint64 = 1024  // Maximum depth of call/create stack.
	ExpGas                uint64 = 10    // Once per EXP instruction
	LogGas                uint64 = 375   // Per LOG* operation.
	CopyGas               uint64 = 3     //
	StackLimit            uint64 = 1024  // Maximum size of VM stack allowed.
	TierStepGas           uint64 = 0     // Once per operation, for a selection of them.
	LogTopicGas           uint64 = 375   // Multiplied by the * of the LOG*, per LOG transaction. e.g. LOG0 incurs 0 * c_txLogTopicGas, LOG4 incurs 4 * c_txLogTopicGas.
	CreateGas             uint64 = 32000 // Once per CREATE operation & contract-creation transaction.
	Create2Gas            uint64 = 32000 // Once per CREATE2 operation
	SelfdestructRefundGas uint64 = 24000 // Refunded following a selfdestruct operation.
	MemoryGas             uint64 = 3     // Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL.

	TxDataNonZeroGasFrontier  uint64 = 68   // Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions.
	TxDataNonZeroGasEIP2028   uint64 = 16   // Per byte of non zero data attached to a transaction after EIP 2028 (part in Istanbul)
	TxFheDataFractionalGas    uint64 = 4    // A byte of data attached to a transaction has fractional cost: 1 / TxFheDataFractionGas (part of an FHE-based chain)
	TxAccessListAddressGas    uint64 = 2400 // Per address specified in EIP 2930 access list
	TxAccessListStorageKeyGas uint64 = 1900 // Per storage key specified in EIP 2930 access list

	// These have been changed during the course of the chain
	CallGasFrontier              uint64 = 40  // Once per CALL operation & message call transaction.
	CallGasEIP150                uint64 = 700 // Static portion of gas for CALL-derivates after EIP 150 (Tangerine)
	BalanceGasFrontier           uint64 = 20  // The cost of a BALANCE operation
	BalanceGasEIP150             uint64 = 400 // The cost of a BALANCE operation after Tangerine
	BalanceGasEIP1884            uint64 = 700 // The cost of a BALANCE operation after EIP 1884 (part of Istanbul)
	ExtcodeSizeGasFrontier       uint64 = 20  // Cost of EXTCODESIZE before EIP 150 (Tangerine)
	ExtcodeSizeGasEIP150         uint64 = 700 // Cost of EXTCODESIZE after EIP 150 (Tangerine)
	SloadGasFrontier             uint64 = 50
	SloadGasEIP150               uint64 = 200
	SloadGasEIP1884              uint64 = 800  // Cost of SLOAD after EIP 1884 (part of Istanbul)
	SloadGasEIP2200              uint64 = 800  // Cost of SLOAD after EIP 2200 (part of Istanbul)
	ExtcodeHashGasConstantinople uint64 = 400  // Cost of EXTCODEHASH (introduced in Constantinople)
	ExtcodeHashGasEIP1884        uint64 = 700  // Cost of EXTCODEHASH after EIP 1884 (part in Istanbul)
	SelfdestructGasEIP150        uint64 = 5000 // Cost of SELFDESTRUCT post EIP 150 (Tangerine)

	// EXP has a dynamic portion depending on the size of the exponent
	ExpByteFrontier uint64 = 10 // was set to 10 in Frontier
	ExpByteEIP158   uint64 = 50 // was raised to 50 during Eip158 (Spurious Dragon)

	// Extcodecopy has a dynamic AND a static cost. This represents only the
	// static portion of the gas. It was changed during EIP 150 (Tangerine)
	ExtcodeCopyBaseFrontier uint64 = 20
	ExtcodeCopyBaseEIP150   uint64 = 700

	// CreateBySelfdestructGas is used when the refunded account is one that does
	// not exist. This logic is similar to call.
	// Introduced in Tangerine Whistle (Eip 150)
	CreateBySelfdestructGas uint64 = 25000

	BaseFeeChangeDenominator = 8          // Bounds the amount the base fee can change between blocks.
	ElasticityMultiplier     = 2          // Bounds the maximum gas limit an EIP-1559 block may have.
	InitialBaseFee           = 1000000000 // Initial base fee for EIP-1559 blocks.

	MaxCodeSize = 24576 // Maximum bytecode to permit for a contract

	// Precompiled contract gas prices

	EcrecoverGas        uint64 = 3000 // Elliptic curve sender recovery gas price
	Sha256BaseGas       uint64 = 60   // Base price for a SHA256 operation
	Sha256PerWordGas    uint64 = 12   // Per-word price for a SHA256 operation
	Ripemd160BaseGas    uint64 = 600  // Base price for a RIPEMD160 operation
	Ripemd160PerWordGas uint64 = 120  // Per-word price for a RIPEMD160 operation
	IdentityBaseGas     uint64 = 15   // Base price for a data copy operation
	IdentityPerWordGas  uint64 = 3    // Per-work price for a data copy operation

	Bn256AddGasByzantium             uint64 = 500    // Byzantium gas needed for an elliptic curve addition
	Bn256AddGasIstanbul              uint64 = 150    // Gas needed for an elliptic curve addition
	Bn256ScalarMulGasByzantium       uint64 = 40000  // Byzantium gas needed for an elliptic curve scalar multiplication
	Bn256ScalarMulGasIstanbul        uint64 = 6000   // Gas needed for an elliptic curve scalar multiplication
	Bn256PairingBaseGasByzantium     uint64 = 100000 // Byzantium base price for an elliptic curve pairing check
	Bn256PairingBaseGasIstanbul      uint64 = 45000  // Base price for an elliptic curve pairing check
	Bn256PairingPerPointGasByzantium uint64 = 80000  // Byzantium per-point price for an elliptic curve pairing check
	Bn256PairingPerPointGasIstanbul  uint64 = 34000  // Per-point price for an elliptic curve pairing check

	Bls12381G1AddGas          uint64 = 600    // Price for BLS12-381 elliptic curve G1 point addition
	Bls12381G1MulGas          uint64 = 12000  // Price for BLS12-381 elliptic curve G1 point scalar multiplication
	Bls12381G2AddGas          uint64 = 4500   // Price for BLS12-381 elliptic curve G2 point addition
	Bls12381G2MulGas          uint64 = 55000  // Price for BLS12-381 elliptic curve G2 point scalar multiplication
	Bls12381PairingBaseGas    uint64 = 115000 // Base gas price for BLS12-381 elliptic curve pairing check
	Bls12381PairingPerPairGas uint64 = 23000  // Per-point pair gas price for BLS12-381 elliptic curve pairing check
	Bls12381MapG1Gas          uint64 = 5500   // Gas price for BLS12-381 mapping field element to G1 operation
	Bls12381MapG2Gas          uint64 = 110000 // Gas price for BLS12-381 mapping field element to G2 operation

	// The Refund Quotient is the cap on how much of the used gas can be refunded. Before EIP-3529,
	// up to half the consumed gas could be refunded. Redefined as 1/5th in EIP-3529
	RefundQuotient        uint64 = 2
	RefundQuotientEIP3529 uint64 = 5

	// FHE operation costs depend on tfhe-rs performance and hardware acceleration. These values will most certainly change.
	FheUint8AddSubGas  uint64 = 83000
	FheUint16AddSubGas uint64 = 108000
	FheUint32AddSubGas uint64 = 130000
	FheUint8MulGas     uint64 = 150000
	FheUint16MulGas    uint64 = 200000
	FheUint32MulGas    uint64 = 270000
	// Div and Rem currently only support a plaintext divisor and below gas costs reflect that case only.
	FheUint8DivGas      uint64 = 200000
	FheUint16DivGas     uint64 = 250000
	FheUint32DivGas     uint64 = 350000
	FheUint8RemGas      uint64 = 200000
	FheUint16RemGas     uint64 = 250000
	FheUint32RemGas     uint64 = 350000
	FheUint8BitwiseGas  uint64 = 20000
	FheUint16BitwiseGas uint64 = 21000
	FheUint32BitwiseGas uint64 = 22000
	FheUint8ShiftGas    uint64 = 105000
	FheUint16ShiftGas   uint64 = 128000
	FheUint32ShiftGas   uint64 = 160000
	FheUint8LeGas       uint64 = 61000
	FheUint16LeGas      uint64 = 83000
	FheUint32LeGas      uint64 = 109000
	FheUint8MinMaxGas   uint64 = 108000
	FheUint16MinMaxGas  uint64 = 134000
	FheUint32MinMaxGas  uint64 = 150000
	FheUint8NegNotGas   uint64 = 83000
	FheUint16NegNotGas  uint64 = 108000
	FheUint32NegNotGas  uint64 = 130000

	// TODO: Costs will depend on the complexity of doing reencryption/decryption by the oracle.
	FheUint8ReencryptGas  uint64 = 320000
	FheUint16ReencryptGas uint64 = 320400
	FheUint32ReencryptGas uint64 = 320800
	FheUint8DecryptGas    uint64 = 320000
	FheUint16DecryptGas   uint64 = 320400
	FheUint32DecryptGas   uint64 = 320800

	// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
	FheUint8VerifyGas  uint64 = 200
	FheUint16VerifyGas uint64 = 300
	FheUint32VerifyGas uint64 = 400

	// TODO: Cost will depend on the complexity of doing decryption by the oracle.
	FheUint8RequireGas  uint64 = 320000
	FheUint16RequireGas uint64 = 320400
	FheUint32RequireGas uint64 = 320800

	// TODO: As of now, only support FheUint8. All optimistic require predicates are
	// downcast to FheUint8 at the solidity level. Eventually move to ebool.
	// If there is at least one optimistic require, we need to decrypt it as it was a normal FHE require.
	// For every subsequent optimistic require, we need to bitand it with the current require value - that
	// works, because we assume requires have a value of 0 or 1.
	FheUint8OptimisticRequireGas       uint64 = FheUint8RequireGas
	FheUint8OptimisticRequireBitandGas uint64 = FheUint8BitwiseGas

	// TODO: These will change once we have an FHE-based random generaration.
	FheUint8RandGas  uint64 = NetSstoreInitGas + 1000
	FheUint16RandGas uint64 = FheUint8RandGas + 1000
	FheUint32RandGas uint64 = FheUint16RandGas + 1000

	// TODO: The values here are chosen somewhat arbitrarily (at least the 8 bit ones). Also, we don't
	// take into account whether a ciphertext existed (either "current" or "original") for the given handle.
	// Finally, costs are likely to change in the future.
	FheUint8ProtectedStorageSstoreGas  uint64 = NetSstoreInitGas + 2000
	FheUint16ProtectedStorageSstoreGas uint64 = FheUint8ProtectedStorageSstoreGas * 2
	FheUint32ProtectedStorageSstoreGas uint64 = FheUint16ProtectedStorageSstoreGas * 2

	// TODO: We don't take whether the slot is cold or warm into consideration.
	FheUint8ProtectedStorageSloadGas  uint64 = ColdSloadCostEIP2929 + 200
	FheUint16ProtectedStorageSloadGas uint64 = FheUint8ProtectedStorageSloadGas * 2
	FheUint32ProtectedStorageSloadGas uint64 = FheUint16ProtectedStorageSloadGas * 2

	FheCastGas uint64 = 100

	FhePubKeyGas uint64 = 2

	FheUint8TrivialEncryptGas  uint64 = 100
	FheUint16TrivialEncryptGas uint64 = 200
	FheUint32TrivialEncryptGas uint64 = 400
)

// Gas discount table for BLS12-381 G1 and G2 multi exponentiation operations
var Bls12381MultiExpDiscountTable = [128]uint64{1200, 888, 764, 641, 594, 547, 500, 453, 438, 423, 408, 394, 379, 364, 349, 334, 330, 326, 322, 318, 314, 310, 306, 302, 298, 294, 289, 285, 281, 277, 273, 269, 268, 266, 265, 263, 262, 260, 259, 257, 256, 254, 253, 251, 250, 248, 247, 245, 244, 242, 241, 239, 238, 236, 235, 233, 232, 231, 229, 228, 226, 225, 223, 222, 221, 220, 219, 219, 218, 217, 216, 216, 215, 214, 213, 213, 212, 211, 211, 210, 209, 208, 208, 207, 206, 205, 205, 204, 203, 202, 202, 201, 200, 199, 199, 198, 197, 196, 196, 195, 194, 193, 193, 192, 191, 191, 190, 189, 188, 188, 187, 186, 185, 185, 184, 183, 182, 182, 181, 180, 179, 179, 178, 177, 176, 176, 175, 174}

var (
	DifficultyBoundDivisor = big.NewInt(2048)   // The bound divisor of the difficulty, used in the update calculations.
	GenesisDifficulty      = big.NewInt(131072) // Difficulty of the Genesis block.
	MinimumDifficulty      = big.NewInt(131072) // The minimum that the difficulty may ever be.
	DurationLimit          = big.NewInt(13)     // The decision boundary on the blocktime duration used to determine whether difficulty should go up or not.
)
