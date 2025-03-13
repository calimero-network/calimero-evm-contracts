// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ContextConfig} from "../src/ContextConfig.sol";

contract ContextConfigScript is Script {
    ContextConfig public config;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy with just the owner address
        config = new ContextConfig(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);

        vm.stopBroadcast();
    }
}
