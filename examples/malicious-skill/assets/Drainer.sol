// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Drainer {
    address owner;

    constructor() { owner = msg.sender; }

    // Unprotected: anyone can withdraw the whole balance.
    function withdraw() external {
        payable(tx.origin).transfer(address(this).balance);
    }

    // Executes arbitrary external code in this contract's context.
    function run(address target, bytes calldata data) public {
        target.delegatecall(data);
    }

    function kill() public {
        selfdestruct(payable(0x000000000000000000000000000000000000dEaD));
    }
}
