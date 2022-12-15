// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.7.0 <0.9.0;

contract Precompiles {

    function precompile_add(uint256 handle1, uint256 handle2) internal view returns (uint256 out_handle) {
        bytes32[2] memory input;
        input[0] = bytes32(handle1);
        input[1] = bytes32(handle2);
        bytes32[1] memory output;
        assembly {
            if iszero(staticcall(gas(), 65, input, 64, output, 32)) {
                revert(0, 0)
            }
        }
        out_handle = uint256(output[0]);
    }

    function precompile_decrypt(uint256 handle1) internal view returns (uint256 out_handle) {
        bytes32[1] memory input;
        input[0] = bytes32(handle1);
        bytes32[1] memory output;
        assembly {
            if iszero(staticcall(gas(), 69, input, 32, output, 32)) {
                revert(0, 0)
            }
        }
        out_handle = uint256(output[0]);

    }

    function precompile_encrypt(uint256  to_be_encrypted) internal view returns (uint256 out_handle) {
        bytes32[1] memory input;
        input[0] = bytes32(to_be_encrypted);
        bytes32[1] memory output;
        assembly {
            if iszero(staticcall(gas(), 70, input, 32, output, 32)) {
                revert(0, 0)
            }
        }
         out_handle = uint256(output[0]);
    }

    function precompile_reencrypt(uint256 in_handle) internal view returns (uint256 out_handle) {
        bytes32[1] memory input;
        input[0] = bytes32(in_handle);
        bytes32[1] memory output;
        assembly {
            if iszero(staticcall(gas(), 67, input, 32, output, 32)) {
                revert(0, 0)
            }
        }
        out_handle = uint256(output[0]);
    }

    function precompile_verify(bytes memory ciphertext) internal view returns (uint256 out_handle) {
        bytes32[1] memory output;
        uint256 len = ciphertext.length;
        assembly {
            if iszero(staticcall(gas(), 66, add(ciphertext, 32), len, output, 32)) {
                revert(0, 0)
            }
        }
        out_handle = uint256(output[0]);
    }

    function precompile_delegate(uint256 in_handle) internal view {
        bytes32[1] memory input;
        input[0] = bytes32(in_handle);
        assembly {
            if iszero(staticcall(gas(), 68, input, 32, 0, 0)) {
                revert(0, 0)
            }
        }
    }
}

// Ciphertext: 0x0102abcdef

contract HandleOwner is Precompiles {
    uint256 public handle;
    uint256 public handle2;
    uint256 public bogus_handle = 42;
    Callee callee;
    address payable owner;

    constructor(address callee_addr) {
        callee = Callee(callee_addr);
        owner = payable(msg.sender);
    }

    function store(bytes memory ciphertext) public {
        handle = precompile_verify(ciphertext);
    }

     function store2(bytes memory ciphertext) public {
        handle2 = precompile_verify(ciphertext);
    }

    function add() public view returns (uint256) {
        return precompile_add(handle, handle2);
    }

    function decrypt() public view returns (uint256) {
        return precompile_decrypt(handle);
    }

    function encrypt(uint256  input) public view returns (uint256) {
        return precompile_encrypt(input);
    }

    // If called before `ovewrite_handle()`, `reencrypt()` must suceed.
    function reencrypt() public view returns (uint256) {
        return precompile_reencrypt(handle);
    }

    // `reencrypt()` must fail or return zeroes.
    function reencrypt_bogus() public view returns (uint256) {
        return precompile_reencrypt(bogus_handle);
    }

    // Makes the handle invalid. Subsequent `reencrypt()`s must fail or return zeroes.
    function overwrite_handle() public payable {
        handle = bogus_handle;
    }

    // Returns the handle without delegation. Callers using it must succeed
    // due to automatic delegation.
    function get_handle_without_delegate() public view returns (uint256) {
        uint256 h = handle;
        return h;
    }

    // Returns the handle with delegation. Callers using it must succeed.
    function get_handle_with_delegate() public view returns (uint256) {
        precompile_delegate(handle);
        return handle;
    }

    // Should work as we (as owners) are calling it.
    function callee_reencrypt() public view returns (uint256) {
        return callee.reencrypt(handle);
    }

    function load_handle_without_returning_it() public view returns(uint256) {
        uint256 h = handle + 1;
        return h;
    }

    function destruct() public {
        require(msg.sender == owner);
        selfdestruct(owner);
    }
}

contract Callee is Precompiles {
    function reencrypt(uint256 handle) public view returns (uint256) {
        return precompile_reencrypt(handle);
    } 
}

contract Caller is Precompiles {
    HandleOwner owner;

    constructor(address owner_addr) {
        owner = HandleOwner(owner_addr);
    }

    // Succeeds, because we do automatic delegation on return.
    function reencrypt_without_delegate() public view returns (uint256) {
        return precompile_reencrypt(owner.get_handle_without_delegate());
    }

    // Succeeds, because there is an explicit delegate by the caller.
    function reencrypt_with_delegate() public view returns (uint256) {
        return precompile_reencrypt(owner.get_handle_with_delegate());
    }

    // Fails, because the owner hasn't delegated, even though the handle is valid.
    function reencrypt_with_a_valid_handle(uint256 handle) public view returns (uint256) {
        owner.load_handle_without_returning_it();
        return precompile_reencrypt(handle);
    }
}