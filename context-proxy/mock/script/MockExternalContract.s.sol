// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {MockExternalContract} from "../src/MockExternalContract.sol";

contract MockExternalContractScript is Script {
    MockExternalContract public config;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        config = new MockExternalContract();
        
        console.log("MockExternalContract deployed at:", address(config));

        vm.stopBroadcast();
    }
}
