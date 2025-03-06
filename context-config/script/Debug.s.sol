// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/ContextConfig.sol";

contract DebugScript is Script {
    function run() public {
        // Get the deployed contract
        ContextConfig config = ContextConfig(0x5FbDB2315678afecb367f032d93F642f64180aa3);
        
        // Create a simple SignedRequest
        ContextConfig.Request memory payload = ContextConfig.Request({
            signerId: bytes32(uint256(uint160(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266))),
            userId: bytes32(uint256(1)),
            nonce: 1,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(
                ContextConfig.ContextRequest({
                    contextId: bytes32(uint256(2)),
                    kind: ContextConfig.ContextRequestKind.Add,
                    data: abi.encode(
                        bytes32(uint256(3)),  // authorId
                        ContextConfig.Application({
                            id: bytes32(uint256(4)),
                            blob: bytes32(uint256(5)),
                            size: 100,
                            source: "test",
                            metadata: bytes("test")
                        })
                    )
                })
            )
        });
        
        ContextConfig.SignedRequest memory signedRequest = ContextConfig.SignedRequest({
            payload: payload,
            r: bytes32(0),
            s: bytes32(0),
            v: 0
        });
        
        // Call the function
        vm.startBroadcast();
        bool result = config.mutate(signedRequest);
        vm.stopBroadcast();
    }
}