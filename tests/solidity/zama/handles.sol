// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract Precompiles {
    function precompile_reencrypt(bytes32 handle) internal view returns (bytes32 out) {
        bytes32[1] memory input_array;
        input_array[0] = handle;
        bytes32[1] memory out_array;
        assembly {
            if iszero(staticcall(gas(), 67, input_array, 32, out_array, 32)) {
                revert(0, 0)
            }
        }
        out = out_array[0];
    }

    function precompile_verify(bytes memory ciphertext) internal view returns (bytes32 out) {
        bytes32[1] memory out_array;
        uint256 len = ciphertext.length;
        assembly {
            if iszero(staticcall(gas(), 66, add(ciphertext, 32), len, out_array, 32)) {
                revert(0, 0)
            }
        }
        out = out_array[0];
    }

    function precompile_delegate(bytes32 _handle) internal view {
        bytes32[1] memory input_array;
        input_array[0] = _handle;
        assembly {
            if iszero(staticcall(gas(), 68, input_array, 32, 0, 0)) {
                revert(0, 0)
            }
        }
    }
}

// Ciphertext: 0x0102abcdef

contract HandleOwner is Precompiles {
    bytes32 public handle;
    bytes32 public bogus_handle = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbb;
    Callee callee;

    constructor(address callee_addr) {
        callee = Callee(callee_addr);
    }

    function store(bytes memory ciphertext) public {
        handle = precompile_verify(ciphertext);
    }

    // If called before `ovewrite_handle()`, `reencrypt()` must suceed.
    function reencrypt() public view returns (bytes32) {
        return precompile_reencrypt(handle);
    }

    // `reencrypt()` must fail or return zeroes.
    function reencrypt_bogus() public view returns (bytes32) {
        return precompile_reencrypt(bogus_handle);
    }

    // Makes the handle invalid. Subsequent `reencrypt()`s must fail or return zeroes.
    function overwrite_handle() public payable {
        handle = bogus_handle;
    }

    // Returns the handle without delegation. Callers using it must fail.
    function get_handle_without_delegate() public view returns (bytes32) {
        return handle;
    }

    // Returns the handle with delegation. Callers using it must succeed.
    function get_handle_with_delegate() public view returns (bytes32) {
        precompile_delegate(handle);
        return handle;
    }

    // Should work as we (as owners) are calling it.
    function callee_reencrypt() public view returns (bytes32) {
        return callee.reencrypt(handle);
    }
}

contract Callee is Precompiles {
    function reencrypt(bytes32 handle) public view returns (bytes32) {
        return precompile_reencrypt(handle);
    } 
}

contract Caller is Precompiles {
    HandleOwner owner;

    constructor(address owner_addr) {
        owner = HandleOwner(owner_addr);
    }

    // Fails, because the owner hasn't delegated.
    function reencrypt_without_delegate() public view returns (bytes32) {
        return precompile_reencrypt(owner.get_handle_without_delegate());
    }

    // Succeeds, because the owner has delegated.
    function reencrypt_with_delegate() public view returns (bytes32) {
        return precompile_reencrypt(owner.get_handle_with_delegate());
    }
}
