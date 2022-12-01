// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

// Ciphertext: 0x0102abcdef0102abcdef0102abcdef0102abcdef0102abcdef0102abcdefabab

contract Handles {
    bytes32 public handle;
    bytes32 public bogus_handle = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbb;

    function store(bytes32 ciphertext) public payable {
        handle = verify(ciphertext);
    }

    // If called before `ovewrite_handle()`, `reencrypt()` must suceed.
    function reencrypt() public view returns (bytes32) {
        return reencrypt(handle);
    }

    // `reencrypt()` must fail or return zeroes.
    function reencrypt_bogus() public view returns (bytes32) {
        return reencrypt(bogus_handle);
    }

    // Makes the handle invalid. `reencrypt()` must fail or return zeroes.
    function overwrite_handle() public payable {
        handle = bogus_handle;
    }

    // The `reencrypt()` precompiled contract.
    function reencrypt(bytes32 _handle) private view returns (bytes32 out) {
        bytes32[1] memory input_array;
        input_array[0] = _handle;
        bytes32[1] memory out_array;
        assembly {
            if iszero(staticcall(gas(), 67, input_array, 32, out_array, 32)) {
                revert(0, 0)
            }
        }
        out = out_array[0];
    }

    // The `verify()` precompiled contract.
    function verify(bytes32 ciphertext) private returns (bytes32 out) {
        bytes32[1] memory input_array;
        input_array[0] = ciphertext;
        uint256 value = 0;
        bytes32[1] memory out_array;
        assembly {
            if iszero(call(gas(), 66, value, input_array, 32, out_array, 32)) {
                revert(0, 0)
            }
        }
        out = out_array[0];
    }
}
