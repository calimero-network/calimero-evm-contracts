// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";

contract MockExternalContract {
    mapping(string => string) private values;
    uint256 public totalDeposits;
    
    // Function that accepts ETH
    function deposit(string memory key, string memory value) external payable {
        values[key] = value;
        totalDeposits += msg.value;
    }
    
    function setValueNoDeposit(string memory key, string memory value) external {
        console.log("Setting value for key:", key);
        console.log("Value being set:", value);
        values[key] = value;
        console.log("Value after setting:", values[key]);
    }

    function getValue(string memory key) external view returns (string memory) {
        console.log("Getting value for key:", key);
        string memory result = values[key];
        console.log("Retrieved value:", result);
        return result;
    }
    
    // Function to receive ETH
    receive() external payable {
        totalDeposits += msg.value;
    }
}
