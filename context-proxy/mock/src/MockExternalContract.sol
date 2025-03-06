// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract MockExternalContract {
    mapping(string => string) private values;
    uint256 public totalDeposits;
    
    // Function that accepts ETH
    function deposit(string memory key, string memory value) external payable {
        values[key] = value;
        totalDeposits += msg.value;
    }
    
    // Function that doesn't accept ETH
    function setValueNoDeposit(string memory key, string memory value) external {
        values[key] = value;
    }
    
    // Getter function
    function getValue(string memory key) external view returns (string memory) {
        return values[key];
    }
    
    // Function to receive ETH
    receive() external payable {
        totalDeposits += msg.value;
    }
}
