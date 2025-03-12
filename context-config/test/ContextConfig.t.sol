// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/ContextConfig.sol";
import "forge-std/console.sol";
import "context-proxy/src/ContextProxy.sol";

contract ContextConfigTest is Test {
    ContextConfig public config;
    address public owner; // Add this to track the owner
    
    // The original Ed25519 private key
    bytes32 private ed25519PrivateKey;
    
    // Derived keys
    bytes32 public ed25519PublicKey;    // user_id
    uint256 private ecdsaPrivateKey;    // For signing
    bytes32 public ecdsaPublicKey;      // signer_id

    function setUp() public {
        // Store the owner address (the test contract itself)
        owner = address(this);
        // Pass the owner address when creating the contract
        config = new ContextConfig(owner);

        // Set proxy code first
        bytes memory proxyBytecode = type(ContextProxy).creationCode;
        vm.prank(owner);
        bool success = config.setProxyCode(proxyBytecode);
        assertTrue(success, "Setting proxy code should succeed");
        
        // Simulate the original Ed25519 private key
        ed25519PrivateKey = bytes32(uint256(0xaaaa));
        
        // Derive Ed25519 public key (in real implementation this would use proper Ed25519 derivation)
        ed25519PublicKey = bytes32(uint256(0x8d1603b1b6976d3f181e1ee816c20e831237c89f6336f331c9e04d32ff714e60));
        
        // Derive ECDSA private key from Ed25519 private key
        ecdsaPrivateKey = uint256(keccak256(abi.encodePacked(
            "ECDSA_DERIVE",
            ed25519PrivateKey
        )));
        
        // Get ECDSA public key (address)
        address ecdsaAddress = vm.addr(ecdsaPrivateKey);
        // Store the full bytes32 format
        ecdsaPublicKey = bytes32(uint256(uint160(ecdsaAddress)));
    }

    function testContextCreation() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create application
        ContextConfig.Application memory app = ContextConfig.Application({
            id: bytes32(0),
            blob: bytes32(0),
            size: 0,
            source: "test",
            metadata: bytes("")
        });

        // Create context request
        ContextConfig.ContextRequest memory contextRequest = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: ContextConfig.ContextRequestKind.Add,
            data: abi.encode(ed25519PublicKey, app)  // Use ed25519PublicKey for authorization
        });

        // Create main request
        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: ecdsaPublicKey,    // ECDSA public key for signature verification
            userId: ed25519PublicKey,    // Ed25519 public key for authorization
            nonce: 1,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(contextRequest)
        });

        // Get message hash and sign it
        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        
        // Sign with the ECDSA private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaPrivateKey, ethSignedMessageHash);

        // Create signed request
        ContextConfig.SignedRequest memory signedRequest = ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });

        // Submit request
        bool success = config.mutate(signedRequest);
        assertTrue(success, "Context creation failed");

        // Verify application
        ContextConfig.Application memory response = config.application(contextId);
        assertEq(response.source, "test", "Application source mismatch");
        assertEq(response.id, bytes32(0), "Application id mismatch");
        assertEq(response.blob, bytes32(0), "Application blob mismatch");
        assertEq(response.size, 0, "Application size mismatch");
        assertEq(response.metadata.length, 0, "Application metadata mismatch");
    }

    // Helper function to create and sign a request
    function createSignedRequest (
        bytes32 contextId,
        bytes32 authorId,
        ContextConfig.Application memory app
    ) internal view returns (ContextConfig.SignedRequest memory) {


        uint64 nonce;
        try config.fetchNonce(contextId, authorId) returns (uint64 currentNonce) {
            nonce = currentNonce;
        } catch {
            nonce = 1;
        }

        ContextConfig.ContextRequest memory contextRequest = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: ContextConfig.ContextRequestKind.Add,
            data: abi.encode(authorId, app)
        });

        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: ecdsaPublicKey,
            userId: ed25519PublicKey,
            nonce: nonce,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(contextRequest)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaPrivateKey, ethSignedMessageHash);

        return ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });
    }

    function testMemberManagement() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create context first
        ContextConfig.Application memory app = createTestApplication();
        ContextConfig.SignedRequest memory createRequest = createSignedRequest(
            contextId,
            ed25519PublicKey,
            app
        );

        bool success = config.mutate(createRequest);
        assertTrue(success, "Context creation failed");

        // Add new members
        bytes32[] memory newMembers = new bytes32[](2);
        newMembers[0] = bytes32(uint256(0xbbbb));
        newMembers[1] = bytes32(uint256(0xcccc));

        ContextConfig.SignedRequest memory addRequest = createAddMembersRequest(
            contextId,
            newMembers
        );

        success = config.mutate(addRequest);
        assertTrue(success, "Member addition failed");

        // Verify members after addition
        bytes32[] memory membersList = config.members(contextId, 0, 10);
        assertEq(membersList.length, 3, "Should have three members");

        // Remove one member
        bytes32[] memory membersToRemove = new bytes32[](1);
        membersToRemove[0] = bytes32(uint256(0xbbbb));

        ContextConfig.SignedRequest memory removeRequest = createRemoveMembersRequest(
            contextId,
            membersToRemove
        );

        success = config.mutate(removeRequest);
        assertTrue(success, "Member removal failed");

        // Verify members after removal
        membersList = config.members(contextId, 0, 10);
        assertEq(membersList.length, 2, "Should have two members");

        // Verify remaining members
        bool foundOriginal = false;
        bool foundSecond = false;
        bool foundRemoved = false;
        
        for (uint i = 0; i < membersList.length; i++) {
            if (membersList[i] == ed25519PublicKey) foundOriginal = true;
            if (membersList[i] == bytes32(uint256(0xcccc))) foundSecond = true;
            if (membersList[i] == bytes32(uint256(0xbbbb))) foundRemoved = true;
        }
        
        assertTrue(foundOriginal, "Original member should still exist");
        assertTrue(foundSecond, "Second member should still exist");
        assertFalse(foundRemoved, "Removed member should not exist");
    }

    // Helper function to create a test application
    function createTestApplication() internal pure returns (ContextConfig.Application memory) {
        return ContextConfig.Application({
            id: bytes32(0),
            blob: bytes32(0),
            size: 0,
            source: "test",
            metadata: bytes("")
        });
    }

    // Helper function for creating add members request
    function createAddMembersRequest(
        bytes32 contextId,
        bytes32[] memory newMembers
    ) internal view returns (ContextConfig.SignedRequest memory) {

        uint64 nonce;
        try config.fetchNonce(contextId, ed25519PublicKey) returns (uint64 currentNonce) {
            nonce = currentNonce;
        } catch {
            nonce = 1;
        }

        ContextConfig.ContextRequest memory addMembersRequest = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: ContextConfig.ContextRequestKind.AddMembers,
            data: abi.encode(newMembers)
        });

        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: ecdsaPublicKey,
            userId: ed25519PublicKey,
            nonce: nonce,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(addMembersRequest)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaPrivateKey, ethSignedMessageHash);

        return ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });
    }

    // Helper function for creating remove members request
    function createRemoveMembersRequest(
        bytes32 contextId,
        bytes32[] memory membersToRemove
    ) internal view returns (ContextConfig.SignedRequest memory) {

        uint64 nonce;
        try config.fetchNonce(contextId, ed25519PublicKey) returns (uint64 currentNonce) {
            nonce = currentNonce;
        } catch {
            nonce = 1;
        }

        ContextConfig.ContextRequest memory removeMembersRequest = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: ContextConfig.ContextRequestKind.RemoveMembers,
            data: abi.encode(membersToRemove)
        });

        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: ecdsaPublicKey,
            userId: ed25519PublicKey,
            nonce: nonce,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(removeMembersRequest)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaPrivateKey, ethSignedMessageHash);

        return ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });
    }

    // Helper function for creating signed context request
    function createSignedContextRequest(
        bytes32 contextId,
        ContextConfig.ContextRequestKind kind,
        bytes memory data,
        bytes32 userId,
        bytes32 signerId,
        uint256 signerPrivateKey
    ) internal view returns (ContextConfig.SignedRequest memory) {

        uint64 nonce;
        try config.fetchNonce(contextId, userId) returns (uint64 currentNonce) {
            nonce = currentNonce;
        } catch {
            nonce = 1;
        }
        ContextConfig.ContextRequest memory contextReq = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: kind,
            data: data
        });

        ContextConfig.Request memory request = ContextConfig.Request({
            userId: userId,
            signerId: signerId,
            nonce: nonce,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(contextReq)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedMessageHash);

        return ContextConfig.SignedRequest({
            payload: request,
            v: v,
            r: r,
            s: s
        });
    }

    function testCapabilityManagement() public {
        bytes32 contextId = bytes32(uint256(1));
        ContextConfig.Application memory app = ContextConfig.Application({
            id: bytes32(0),
            blob: bytes32(0),
            size: 0,
            source: "test",
            metadata: bytes("")
        });
        
        // Member1 creates context
        config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.Add,
            abi.encode(ed25519PublicKey, app),
            ed25519PublicKey,
            ecdsaPublicKey,
            ecdsaPrivateKey
        ));

        // Check Member1's capabilities
        checkCapabilities(contextId, "Member1 initial capabilities", ed25519PublicKey, true, true, true);

        // Set up Member2
        uint256 member2EcdsaPrivateKey = uint256(keccak256(abi.encodePacked("NEW_MEMBER")));
        address member2EcdsaAddress = vm.addr(member2EcdsaPrivateKey);
        bytes32 member2EcdsaPublicKey = bytes32(uint256(uint160(member2EcdsaAddress)));
        bytes32 member2Ed25519PublicKey = bytes32(uint256(0x2222));

        // Member1 adds Member2
        bytes32[] memory newMembers = new bytes32[](1);
        newMembers[0] = member2Ed25519PublicKey;
        config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.AddMembers,
            abi.encode(newMembers),
            ed25519PublicKey,
            ecdsaPublicKey,
            ecdsaPrivateKey
        ));

        // Check Member2's capabilities before grant
        checkCapabilities(contextId, "Member2 before grant", member2Ed25519PublicKey, false, false, false);

        // Member1 grants ManageMembers to Member2
        config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.AddCapability,
            abi.encode(member2Ed25519PublicKey, ContextConfig.Capability.ManageMembers),
            ed25519PublicKey,
            ecdsaPublicKey,
            ecdsaPrivateKey
        ));

        // Check Member2's capabilities after grant
        checkCapabilities(contextId, "Member2 after grant", member2Ed25519PublicKey, false, true, false);

        // Member2 adds Member3
        bytes32 member3Ed25519PublicKey = bytes32(uint256(0x3333));
        bytes32[] memory member3Array = new bytes32[](1);
        member3Array[0] = member3Ed25519PublicKey;
        config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.AddMembers,
            abi.encode(member3Array),
            member2Ed25519PublicKey,
            member2EcdsaPublicKey,
            member2EcdsaPrivateKey
        ));

        // Verify Member3 was added
        bool member3Found = false;
        bytes32[] memory membersList = config.members(contextId, 0, 10);
        for (uint i = 0; i < membersList.length; i++) {
            if (membersList[i] == member3Ed25519PublicKey) {
                member3Found = true;
                break;
            }
        }
        assertTrue(member3Found, "Member3 should have been added");

        // Member1 revokes ManageMembers from Member2
        config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.RevokeCapability,
            abi.encode(member2Ed25519PublicKey, ContextConfig.Capability.ManageMembers),
            ed25519PublicKey,
            ecdsaPublicKey,
            ecdsaPrivateKey
        ));

        // Check Member2's capabilities after revoke
        checkCapabilities(contextId, "Member2 after revoke", member2Ed25519PublicKey, false, false, false);

        // Member2 attempts to remove Member3 (should fail)
        // Use try/catch instead of vm.expectRevert since we're having issues with it
        bool success = false;
        try config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.RemoveMembers,
            abi.encode(member3Array),
            member2Ed25519PublicKey,
            member2EcdsaPublicKey,
            member2EcdsaPrivateKey
        )) {
            success = true;
        } catch {
            success = false;
        }
        
        assertFalse(success, "Member2 should not be able to remove Member3 after capability revocation");
    }

    function checkCapabilities(
        bytes32 contextId,
        string memory label,
        bytes32 userKey,
        bool expectManageApp,
        bool expectManageMembers,
        bool expectProxy
    ) internal view {
        bytes32[] memory userArray = new bytes32[](1);
        userArray[0] = userKey;

        // Get capabilities for the user
        ContextConfig.UserCapabilities[] memory caps = config.privileges(contextId, userArray);

        console.log("--- ", label, " ---");
        console.log("User ID:", uint256(userKey));
        
        // If no capabilities found
        if (caps.length == 0 || caps[0].capabilities.length == 0) {
            console.log("No capabilities found");
            assertFalse(expectManageApp, "Expected ManageApplication capability");
            assertFalse(expectManageMembers, "Expected ManageMembers capability");
            assertFalse(expectProxy, "Expected Proxy capability");
            console.log("---");
            return;
        }

        // Check capabilities
        bool hasManageApp = false;
        bool hasManageMembers = false;
        bool hasProxy = false;

        console.log("Number of capabilities:", caps[0].capabilities.length);
        for (uint j = 0; j < caps[0].capabilities.length; j++) {
            uint capValue = uint(caps[0].capabilities[j]);
            console.log("Capability:", capValue);
            
            if (capValue == uint(ContextConfig.Capability.ManageApplication)) {
                hasManageApp = true;
            } else if (capValue == uint(ContextConfig.Capability.ManageMembers)) {
                hasManageMembers = true;
            } else if (capValue == uint(ContextConfig.Capability.Proxy)) {
                hasProxy = true;
            }
        }
        
        // Assert expected capabilities
        if (expectManageApp) {
            assertTrue(hasManageApp, "Expected ManageApplication capability");
        } else {
            assertFalse(hasManageApp, "Did not expect ManageApplication capability");
        }
        
        if (expectManageMembers) {
            assertTrue(hasManageMembers, "Expected ManageMembers capability");
        } else {
            assertFalse(hasManageMembers, "Did not expect ManageMembers capability");
        }
        
        if (expectProxy) {
            assertTrue(hasProxy, "Expected Proxy capability");
        } else {
            assertFalse(hasProxy, "Did not expect Proxy capability");
        }
        
        console.log("---");
    }

    function testFetchNonce() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create context first
        ContextConfig.Application memory app = createTestApplication();
        config.mutate(createSignedRequest(
            contextId,
            ed25519PublicKey,
            app
        ));

        // Check initial nonce - should be 1 after the first operation
        uint64 nonce = config.fetchNonce(contextId, ed25519PublicKey);
        console.log("nonce: %d", nonce);
        assertEq(nonce, 1, "Initial nonce should be 1 after context creation");

        // Perform an operation and check nonce again
        config.mutate(createAddMembersRequest(
            contextId,
            new bytes32[](1)
        ));

        uint64 newNonce = config.fetchNonce(contextId, ed25519PublicKey);
        assertEq(newNonce, 2, "Nonce should be updated to 2");
    }

    function testNonceChecking() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create context first
        ContextConfig.Application memory app = createTestApplication();
        ContextConfig.SignedRequest memory createRequest = createSignedRequest(
            contextId,
            ed25519PublicKey,
            app
        );

        bool success = config.mutate(createRequest);
        assertTrue(success, "Context creation failed");

        // Try to create the same context again (should fail with ContextAlreadyExists)
        try config.mutate(createRequest) {
            fail();
        } catch Error(string memory reason) {
            // This is for require statements with a reason string
            console.log("Caught error:", reason);
        } catch (bytes memory lowLevelData) {
            // This is for custom errors
            bytes4 selector = bytes4(lowLevelData);
            console.log("Caught custom error selector:");
            console.logBytes4(selector);
            
            // Check if it's the ContextAlreadyExists error
            bytes4 expectedSelector = bytes4(keccak256("ContextAlreadyExists()"));
            assertEq(selector, expectedSelector, "Expected ContextAlreadyExists error");
        }

        // Now test nonce checking with a different operation
        
        // First, let's add a member with nonce 2 (should succeed)
        bytes32[] memory newMembers = new bytes32[](1);
        newMembers[0] = bytes32(uint256(0xbbbb));
        ContextConfig.SignedRequest memory addRequest = createAddMembersRequest(
            contextId,
            newMembers
        );
        
        success = config.mutate(addRequest);
        assertTrue(success, "Adding member with higher nonce should succeed");
        
        // Now try with the same nonce again (should fail with InvalidNonce)
        try config.mutate(addRequest) {
            fail();
        } catch Error(string memory reason) {
            console.log("Caught error:", reason);
        } catch (bytes memory lowLevelData) {
            bytes4 selector = bytes4(lowLevelData);
            console.log("Caught custom error selector:");
            console.logBytes4(selector);
            
            // Check if it's the InvalidNonce error
            bytes4 expectedSelector = bytes4(keccak256("InvalidNonce()"));
            assertEq(selector, expectedSelector, "Expected InvalidNonce error");
        }

        // Try with a lower nonce (should fail with InvalidNonce)
        ContextConfig.ContextRequest memory addMembersRequest = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: ContextConfig.ContextRequestKind.AddMembers,
            data: abi.encode(newMembers)
        });

        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: ecdsaPublicKey,
            userId: ed25519PublicKey,
            nonce: 0,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(addMembersRequest)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaPrivateKey, ethSignedMessageHash);

        ContextConfig.SignedRequest memory lowerNonceRequest = ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });
        
        try config.mutate(lowerNonceRequest) {
            fail();
        } catch Error(string memory reason) {
            console.log("Caught error:", reason);
        } catch (bytes memory lowLevelData) {
            bytes4 selector = bytes4(lowLevelData);
            console.log("Caught custom error selector:");
            console.logBytes4(selector);
            
            // Check if it's the InvalidNonce error
            bytes4 expectedSelector = bytes4(keccak256("InvalidNonce()"));
            assertEq(selector, expectedSelector, "Expected InvalidNonce error");
        }
        
        // Try with a higher nonce (should succeed)
        ContextConfig.SignedRequest memory higherNonceRequest = createAddMembersRequest(
            contextId,
            newMembers
        );
        success = config.mutate(higherNonceRequest);
        assertTrue(success, "Higher nonce request should succeed");
    }

    function testRevisionTracking() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create context first
        ContextConfig.Application memory app = createTestApplication();
        config.mutate(createSignedRequest(
            contextId,
            ed25519PublicKey,
            app
        ));

        // Check initial revisions
        uint32 appRevision = config.applicationRevision(contextId);
        uint32 membersRevision = config.membersRevision(contextId);
        assertEq(appRevision, 1, "Initial application revision should be 1");
        assertEq(membersRevision, 1, "Initial members revision should be 1");

        // Add members and check revision
        bytes32[] memory newMembers = new bytes32[](1);
        newMembers[0] = bytes32(uint256(0xbbbb));
        config.mutate(createAddMembersRequest(
            contextId,
            newMembers
        ));

        uint32 newMembersRevision = config.membersRevision(contextId);
        assertEq(newMembersRevision, 2, "Members revision should be incremented");
        assertEq(config.applicationRevision(contextId), 1, "Application revision should not change");

        // Add capability and check revision
        config.mutate(createSignedContextRequest(
            contextId,
            ContextConfig.ContextRequestKind.AddCapability,
            abi.encode(bytes32(uint256(0xbbbb)), ContextConfig.Capability.ManageApplication),
            ed25519PublicKey,
            ecdsaPublicKey,
            ecdsaPrivateKey
        ));

        uint32 newAppRevision = config.applicationRevision(contextId);
        assertEq(newAppRevision, 2, "Application revision should be incremented");
        assertEq(config.membersRevision(contextId), 2, "Members revision should not change");
    }

    function testHasMember() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create context first
        ContextConfig.Application memory app = createTestApplication();
        config.mutate(createSignedRequest(
            contextId,
            ed25519PublicKey,
            app
        ));

        // Check if creator is a member
        bool isMember = config.hasMember(contextId, ed25519PublicKey);
        assertTrue(isMember, "Creator should be a member");

        // Check if non-member is not a member
        bytes32 nonMember = bytes32(uint256(0xdead));
        bool isNonMember = config.hasMember(contextId, nonMember);
        assertFalse(isNonMember, "Non-member should not be a member");

        // Add a new member
        bytes32[] memory newMembers = new bytes32[](1);
        newMembers[0] = nonMember;
        config.mutate(createAddMembersRequest(
            contextId,
            newMembers
        ));

        // Check if new member is now a member
        isNonMember = config.hasMember(contextId, nonMember);
        assertTrue(isNonMember, "New member should now be a member");
    }

    function testProxyDeploymentOnContextCreation() public {
        bytes32 contextId = bytes32(uint256(1));
        
        // Create context
        ContextConfig.Application memory app = createTestApplication();
        ContextConfig.SignedRequest memory createRequest = createSignedRequest(
            contextId,
            ed25519PublicKey,
            app
        );

        bool success = config.mutate(createRequest);
        assertTrue(success, "Context creation failed");
        
        // Check if proxy was automatically deployed
        address payable proxyAddress = payable(config.proxyContract(contextId));
        console.log("Proxy address:", proxyAddress);
        assertTrue(proxyAddress != address(0), "Proxy should be deployed during context creation");
    }
} 