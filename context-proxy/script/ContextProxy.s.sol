// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ContextProxy} from "../src/ContextProxy.sol";

contract ContextProxyScript is Script {
    ContextProxy public config;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy with owner and ledgerId (using msg.sender for both in this example)
        config = new ContextProxy(bytes32(0), msg.sender);
        
        console.log("ContextProxy deployed at:", address(config));
        console.log("Owner:", msg.sender);

        vm.stopBroadcast();
    }
}
