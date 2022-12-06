// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.7.0 <0.9.0;

contract Contract {
    uint256 public value;

    constructor(uint256 v) {
        value = v;
    }

    function get() public view returns (uint256) {
        return value;
    }

    function destruct() public {
        selfdestruct(payable(tx.origin));
    }
}

// Salt: 0x0102abcdef0102abcdef0102abcdef0102abcdef0102abcdef0102abcdefaaaa

// Creates a member contract via the CREATE2 opcode.
contract Factory {
    Contract public c;
    bytes32 public original_salt;
    uint256 public original_value;
    address public original_address;

    constructor(bytes32 salt, uint256 value) {
        c = new Contract{salt: salt}(value);
        original_salt = salt;
        original_value = value;
        original_address = address(c);
    }

    function get() public view returns (uint256) {
        return c.get();
    }

    function destruct() public {
        c.destruct();
    }

    // After `destruct()` is called, `recreate()` must succeed and `c` must have the same address as before.
    function recreate() public {
        c = new Contract{salt: original_salt}(original_value);
        require(original_address == address(c));
    }
}
