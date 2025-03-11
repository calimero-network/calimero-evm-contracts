// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "context-config/src/ContextConfig.sol";
import "../src/ContextProxy.sol";
import "mock/src/MockExternalContract.sol";

contract ContextProxyTest is Test {
    // Contracts
    ContextConfig public contextConfig;
    ContextProxy public proxy;
    MockExternalContract public mockExternal;
    
    // Test accounts
    address public owner;
    address public ledgerId;
    
    // Context and members
    bytes32 public contextId;
    
    // Test signers
    uint256 public contextAuthorPrivateKey;
    uint256 public member1PrivateKey;
    uint256 public member2PrivateKey;
    uint256 public member3PrivateKey;
    
    address public contextAuthorAddress;
    address public member1Address;
    address public member2Address;
    address public member3Address;
    
    bytes32 public contextAuthorId;
    bytes32 public member1Id;
    bytes32 public member2Id;
    bytes32 public member3Id;
    
    // Setup function runs before each test
    function setUp() public {
        // Generate test accounts
        owner = address(this);
        
        // Initialize context ID
        contextId = bytes32(uint256(1));
        
        // Set up context author
        bytes32 authorEd25519PrivateKey = bytes32(uint256(0xaaaa));
        contextAuthorId = bytes32(uint256(0x8d1603b1b6976d3f181e1ee816c20e831237c89f6336f331c9e04d32ff714e60));
        contextAuthorPrivateKey = uint256(keccak256(abi.encodePacked(
            "ECDSA_DERIVE",
            authorEd25519PrivateKey
        )));
        contextAuthorAddress = vm.addr(contextAuthorPrivateKey);

        // Set up member 1
        bytes32 member1Ed25519PrivateKey = bytes32(uint256(0xbbbb));
        member1Id = bytes32(uint256(0x8d1603b1b6976d3f181e1ee816c20e831237c89f6336f331c9e04d32ff714e61));
        member1PrivateKey = uint256(keccak256(abi.encodePacked(
            "ECDSA_DERIVE",
            member1Ed25519PrivateKey
        )));
        member1Address = vm.addr(member1PrivateKey);
        // Set up member 2
        bytes32 member2Ed25519PrivateKey = bytes32(uint256(0xcccc));
        member2Id = bytes32(uint256(0x8d1603b1b6976d3f181e1ee816c20e831237c89f6336f331c9e04d32ff714e62));
        member2PrivateKey = uint256(keccak256(abi.encodePacked(
            "ECDSA_DERIVE",
            member2Ed25519PrivateKey
        )));
        member2Address = vm.addr(member2PrivateKey);

        // Set up member 3
        bytes32 member3Ed25519PrivateKey = bytes32(uint256(0xdddd));
        member3Id = bytes32(uint256(0x8d1603b1b6976d3f181e1ee816c20e831237c89f6336f331c9e04d32ff714e63));
        member3PrivateKey = uint256(keccak256(abi.encodePacked(
            "ECDSA_DERIVE",
            member3Ed25519PrivateKey
        )));
        member3Address = vm.addr(member3PrivateKey);

        // Deploy context config contract
        contextConfig = new ContextConfig(owner);
        
        // Set proxy code first
        bytes memory proxyBytecode = type(ContextProxy).creationCode;
        vm.prank(owner);
        bool success = contextConfig.setProxyCode(proxyBytecode);
        require(success, "Setting proxy code failed");
       

        // Create context using the context author's keys
        createContext(contextId, contextAuthorId, authorEd25519PrivateKey);
        
        // Get proxy address
        address proxyAddress = contextConfig.proxyContract(contextId);
        require(proxyAddress != address(0), "Proxy address is zero");
        proxy = ContextProxy(payable(proxyAddress));

        // Add member1 to context
        bytes32[] memory newMembers = new bytes32[](3);
        newMembers[0] = member1Id;
        newMembers[1] = member2Id;
        newMembers[2] = member3Id;
        
        addMembersToContext(contextId, contextAuthorId, contextAuthorPrivateKey, newMembers);

        // Deploy mock external contract
        mockExternal = new MockExternalContract();
    }
    
    // Helper function to create a context
    function createContext(
        bytes32 _contextId,
        bytes32 _memberId,
        bytes32 _ed25519PrivateKey
    ) internal {

        // Derive ECDSA private key from Ed25519 private key
        uint256 ecdsaPrivateKey = uint256(keccak256(abi.encodePacked(
            "ECDSA_DERIVE",
            _ed25519PrivateKey
        )));
        
        // Get ECDSA public key (address)
        address ecdsaAddress = vm.addr(ecdsaPrivateKey);
        bytes32 ecdsaPublicKey = bytes32(uint256(uint160(ecdsaAddress)));
        
        ContextConfig.Application memory app = ContextConfig.Application({
            id: bytes32(0),
            blob: bytes32(0),
            size: 0,
            source: "test",
            metadata: bytes("")
        });

        ContextConfig.ContextRequest memory contextRequest = ContextConfig.ContextRequest({
            contextId: _contextId,
            kind: ContextConfig.ContextRequestKind.Add,
            data: abi.encode(_memberId, app)
        });

        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: ecdsaPublicKey,
            userId: _memberId,
            nonce: 1,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(contextRequest)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaPrivateKey, ethSignedMessageHash);

        ContextConfig.SignedRequest memory signedRequest = ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });

        bool success = contextConfig.mutate(signedRequest);
        require(success, "Context creation failed");
    }
    
    // Helper function to add members to a context
    function addMembersToContext(
        bytes32 _contextId,
        bytes32 _authorId,
        uint256 _authorPrivateKey,
        bytes32[] memory _members
    ) internal {
        bytes memory membersData = abi.encode(_members);
        
        ContextConfig.ContextRequest memory contextRequest = ContextConfig.ContextRequest({
            contextId: _contextId,
            kind: ContextConfig.ContextRequestKind.AddMembers,
            data: membersData
        });
        
        // Get ECDSA public key from private key
        address authorAddress = vm.addr(_authorPrivateKey);
        bytes32 authorEcdsaPublicKey = bytes32(uint256(uint160(authorAddress)));
        
        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: authorEcdsaPublicKey,
            userId: _authorId,
            nonce: 1,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(contextRequest)
        });
        
        // Create signed request
        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_authorPrivateKey, ethSignedMessageHash);
        
        ContextConfig.SignedRequest memory signedRequest = ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });
        
        // Submit the request
        bool success = contextConfig.mutate(signedRequest);
        require(success, "Failed to add members");
    }
    
    // Helper function to create a signed request for proxy contract
    function createProxySignedRequest(
        uint256 privateKey,
        bytes32 userId,  // This will be Ed25519 ID
        bytes memory requestData,
        ContextProxy.RequestKind kind
    ) internal pure returns (ContextProxy.SignedRequest memory) {
        // Get ECDSA public key from private key
        address signerAddress = vm.addr(privateKey);
        bytes32 signerId = bytes32(uint256(uint160(signerAddress)));

        ContextProxy.Request memory request = ContextProxy.Request({
            signerId: signerId,    // ECDSA public key
            userId: userId,        // Ed25519 ID
            kind: kind,
            data: requestData
        });
        
        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        
        return ContextProxy.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });
    }
    
    // Helper function to create a proposal
    function createProposal(
        bytes32 proposalId,
        bytes32 authorId,
        ContextProxy.ProposalAction[] memory actions
    ) internal pure returns (ContextProxy.Proposal memory) {
        return ContextProxy.Proposal({
            id: proposalId,
            authorId: authorId,
            actions: actions
        });
    }
    
    // Helper function to submit a proposal
    function submitProposal(
        bytes32 proposalId,
        bytes32 authorId,          // Ed25519 ID
        uint256 authorPrivateKey,  // ECDSA private key
        ContextProxy.ProposalAction[] memory actions
    ) internal returns (ContextProxy.ProposalWithApprovals memory) {
        ContextProxy.Proposal memory proposal = createProposal(proposalId, authorId, actions);
        
        bytes memory requestData = abi.encode(proposal);
        
        ContextProxy.SignedRequest memory signedRequest = createProxySignedRequest(
            authorPrivateKey,
            authorId,
            requestData,
            ContextProxy.RequestKind.Propose
        );
        
        return proxy.mutate(signedRequest);
    }
    
    // Helper function to approve a proposal
    function approveProposal(
        bytes32 proposalId,
        bytes32 userId,          // Ed25519 ID
        uint256 signerPrivateKey   // ECDSA private key
    ) internal returns (ContextProxy.ProposalWithApprovals memory) {
        ContextProxy.ProposalApprovalWithSigner memory approval = ContextProxy.ProposalApprovalWithSigner({
            proposalId: proposalId,
            userId: userId
        });
        
        bytes memory requestData = abi.encode(approval);
        
        // Get current nonce for this user
        // uint64 nonce = proxy.fetchNonce(signerId);
        
        ContextProxy.SignedRequest memory signedRequest = createProxySignedRequest(
            signerPrivateKey,
            userId,
            requestData,
            ContextProxy.RequestKind.Approve
        );
        
        return proxy.mutate(signedRequest);
    }
    
    // Test token transfer proposal
    function testExecuteProposalTransfer() public {
        // Fund the proxy contract first
        vm.deal(address(proxy), 10 ether);
        
        bytes32 proposalId = keccak256("transfer-proposal");
        address recipient = address(0x123);
        uint256 transferAmount = 1 ether;
        
        // Record initial balances
        uint256 initialProxyBalance = address(proxy).balance;
        uint256 initialRecipientBalance = recipient.balance;
        
        // Create a Transfer action
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.Transfer,
            data: abi.encode(recipient, transferAmount)
        });
        
        // Submit proposal as member1
        ContextProxy.ProposalWithApprovals memory result = submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Verify initial state
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 1);
        
        // Member2 approves the proposal
        result = approveProposal(proposalId, member2Id, member2PrivateKey);
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 2);
        
        // Member3 approves the proposal - should execute
        result = approveProposal(proposalId, member3Id, member3PrivateKey);
        // After execution, proposal should be cleared (id = 0) and approvals reset
        assertEq(result.proposalId, bytes32(0));
        assertEq(result.numApprovals, 0);
        
        // Verify balances after execution
        assertEq(address(proxy).balance, initialProxyBalance - transferAmount);
        assertEq(recipient.balance, initialRecipientBalance + transferAmount);
    }
    
    function testExecuteProposalExternalCallWithDeposit() public {
        // Fund the proxy contract first
        vm.deal(address(proxy), 10 ether);
        
        bytes32 proposalId = keccak256("external-call-value-proposal");
        uint256 depositAmount = 0.5 ether;
        string memory key = "test_key";
        string memory value = "test_value";
        
        // Record initial balances
        uint256 initialProxyBalance = address(proxy).balance;
        uint256 initialExternalBalance = address(mockExternal).balance;
        
        // Create calldata for the external function
        bytes memory callData = abi.encodeWithSignature(
            "deposit(string,string)",
            key,
            value
        );
        
        // Create an ExternalFunctionCall action
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.ExternalFunctionCall,
            data: abi.encode(address(mockExternal), callData, depositAmount)
        });
        
        // Submit proposal as member1
        ContextProxy.ProposalWithApprovals memory result = submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Verify initial state
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 1);
        
        // Member2 approves
        result = approveProposal(proposalId, member2Id, member2PrivateKey);
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 2);
        
        // Member3 approves - should execute
        result = approveProposal(proposalId, member3Id, member3PrivateKey);
        assertEq(result.proposalId, bytes32(0));
        assertEq(result.numApprovals, 0);
        
        // Verify the external call was executed
        assertEq(mockExternal.getValue(key), value);
        assertEq(mockExternal.totalDeposits(), depositAmount);
        
        // Verify balances
        assertEq(address(proxy).balance, initialProxyBalance - depositAmount);
        assertEq(address(mockExternal).balance, initialExternalBalance + depositAmount);
    }
    
    function testExecuteProposalExternalCallNoDeposit() public {
        bytes32 proposalId = keccak256("external-call-no-value-proposal");
        string memory key = "test_key";
        string memory value = "test_value";
        
        // Create calldata for the external function
        bytes memory callData = abi.encodeWithSignature(
            "setValueNoDeposit(string,string)",
            key,
            value
        );
        
        // Create an ExternalFunctionCall action
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.ExternalFunctionCall,
            data: abi.encode(address(mockExternal), callData, 0)
        });
        
        // Submit proposal as member1
        ContextProxy.ProposalWithApprovals memory result = submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Verify initial state
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 1);
        
        // Member2 approves
        result = approveProposal(proposalId, member2Id, member2PrivateKey);
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 2);
        
        // Member3 approves - should execute
        result = approveProposal(proposalId, member3Id, member3PrivateKey);
        assertEq(result.proposalId, bytes32(0));
        assertEq(result.numApprovals, 0);
        
        // Verify the external call was executed
        assertEq(mockExternal.getValue(key), value);
        assertEq(mockExternal.totalDeposits(), 0);
    }
    
    // Test changing num approvals
    function testExecuteProposalSetNumApprovals() public {
        // Verify initial state is 3 approvals
        assertEq(proxy.numApprovals(), 3);
        
        bytes32 proposalId = keccak256("set-approvals-proposal");
        uint32 newApprovals = 2;
        
        // Create a SetNumApprovals action
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetNumApprovals,
            data: abi.encode(newApprovals)
        });
        
        // Member1 submits proposal
        submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Member2 approves the proposal
        approveProposal(
            proposalId,
            member2Id,
            member2PrivateKey
        );
        
        // Member3 approves the proposal
        approveProposal(
            proposalId,
            member3Id,
            member3PrivateKey
        );
        
        // Verify numApprovals was updated
        assertEq(proxy.numApprovals(), newApprovals, "numApprovals should be updated to 2");
    }

    function testExecuteProposalSetContextValue() public {
        bytes32 proposalId = keccak256("set-context-value-proposal");
        
        // Create test key-value pair
        bytes memory key = "test_key";
        bytes memory value = "test_value";
        
        // Create a SetContextValue action
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetContextValue,
            data: abi.encode(key, value)
        });
        
        // Submit proposal as member1
        ContextProxy.ProposalWithApprovals memory result = submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Verify initial state
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 1);
        
        // Member2 approves the proposal
        result = approveProposal(proposalId, member2Id, member2PrivateKey);
        assertEq(result.proposalId, proposalId);
        assertEq(result.numApprovals, 2);
        
        // Member3 approves the proposal - should execute
        result = approveProposal(proposalId, member3Id, member3PrivateKey);
        // After execution, proposal should be cleared (id = 0) and approvals reset
        assertEq(result.proposalId, bytes32(0));
        assertEq(result.numApprovals, 0);
        
        // Verify the context value was set correctly
        bytes memory storedValue = proxy.getContextValue(key);
        assertEq(keccak256(storedValue), keccak256(value), "Context value not set correctly");
        
        // Test retrieving multiple values
        (bytes[] memory keys, bytes[] memory values) = proxy.contextStorageEntries(0, 10);
        assertEq(keys.length, 1, "Should have one stored key");
        assertEq(values.length, 1, "Should have one stored value");
        assertEq(keccak256(keys[0]), keccak256(key), "Stored key doesn't match");
        assertEq(keccak256(values[0]), keccak256(value), "Stored value doesn't match");
    }

    function testExecuteProposalMultipleContextValues() public {
        // Set up test data
        bytes[3] memory keys = [
            bytes("key1"),
            bytes("key2"),
            bytes("key3")
        ];
        bytes[3] memory values = [
            bytes("value1"),
            bytes("value2"),
            bytes("value3")
        ];
        
        // Create and execute proposals for each key-value pair
        for (uint i = 0; i < 3; i++) {
            bytes32 proposalId = keccak256(abi.encodePacked("set-context-value-proposal", i));
            
            ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
            actions[0] = ContextProxy.ProposalAction({
                kind: ContextProxy.ProposalActionKind.SetContextValue,
                data: abi.encode(keys[i], values[i])
            });
            
            // Submit and approve proposal
            submitProposal(proposalId, member1Id, member1PrivateKey, actions);
            approveProposal(proposalId, member2Id, member2PrivateKey);
            approveProposal(proposalId, member3Id, member3PrivateKey);
            
            // Verify value was set
            bytes memory storedValue = proxy.getContextValue(keys[i]);
            assertEq(keccak256(storedValue), keccak256(values[i]));
        }
        
        // Test pagination
        // Get first 2 entries
        (bytes[] memory paginatedKeys1,) = proxy.contextStorageEntries(0, 2);
        assertEq(paginatedKeys1.length, 2, "Should return 2 entries");
        
        // Get remaining entry
        (bytes[] memory paginatedKeys2,) = proxy.contextStorageEntries(2, 1);
        assertEq(paginatedKeys2.length, 1, "Should return 1 entry");
        
        // Try to get entries beyond the end
        (bytes[] memory paginatedKeys3,) = proxy.contextStorageEntries(3, 1);
        assertEq(paginatedKeys3.length, 0, "Should return empty array");
    }

    function testProposalLimitAndDeletion() public {
        // First, let's decrease the active proposals limit to 2 (default is 10)
        bytes32 proposalId = keccak256("set-limit-proposal");
        uint32 newLimit = 2;
        
        // Create a SetActiveProposalsLimit action
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetActiveProposalsLimit,
            data: abi.encode(newLimit)
        });
        
        // Submit and approve the limit change proposal
        ContextProxy.ProposalWithApprovals memory result = submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        approveProposal(proposalId, member2Id, member2PrivateKey);
        approveProposal(proposalId, member3Id, member3PrivateKey);
        
        // Verify the limit was updated
        uint32 currentLimit = proxy.getActiveProposalsLimit();
        assertEq(currentLimit, newLimit, "Limit should be updated to 2");
        
        // Now create first proposal (transfer proposal)
        bytes32 proposal1Id = keccak256("proposal1");
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.Transfer,
            data: abi.encode(address(0x123), 1 ether)
        });
        
        result = submitProposal(
            proposal1Id,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Create second proposal (context value proposal)
        bytes32 proposal2Id = keccak256("proposal2");
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetContextValue,
            data: abi.encode("key", "value")
        });
        
        result = submitProposal(
            proposal2Id,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Try to create third proposal - should fail
        bytes32 proposal3Id = keccak256("proposal3");
        bool success = false;
        try proxy.mutate(createProxySignedRequest(
            member1PrivateKey,
            member1Id,
            abi.encode(ContextProxy.Proposal({
                id: proposal3Id,
                authorId: member1Id,
                actions: actions
            })),
            ContextProxy.RequestKind.Propose
        )) returns (ContextProxy.ProposalWithApprovals memory) {
            success = true;
        } catch {
            success = false;
        }
        
        assertFalse(success, "Third proposal should have failed");
        
        // Delete proposal1 directly
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.DeleteProposal,
            data: abi.encode(proposal1Id)
        });
        
        result = submitProposal(
            keccak256("delete-proposal"),
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Now we should be able to create a new proposal
        bytes32 newProposalId = keccak256("new-proposal");
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetContextValue,
            data: abi.encode("new_key", "new_value")
        });
        
        result = submitProposal(
            newProposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        assertEq(result.proposalId, newProposalId, "New proposal should be created after deletion");
        
        // Try to create one more proposal - should fail again
        bytes32 oneMoreProposalId = keccak256("one-more-proposal");
        success = false;
        try proxy.mutate(createProxySignedRequest(
            member1PrivateKey,
            member1Id,
            abi.encode(ContextProxy.Proposal({
                id: oneMoreProposalId,
                authorId: member1Id,
                actions: actions
            })),
            ContextProxy.RequestKind.Propose
        )) returns (ContextProxy.ProposalWithApprovals memory) {
            success = true;
        } catch {
            success = false;
        }
        
        assertFalse(success, "Creating proposal after limit should fail");
    }

    function testProxyUpgrade() public {
        // Deploy new implementation
        ContextProxy newImplementation = new ContextProxy(
            contextId,
            address(contextConfig)
        );
        
        // Store some data in the proxy before upgrade
        bytes32 proposalId = keccak256("test-proposal");
        ContextProxy.ProposalAction[] memory actions = new ContextProxy.ProposalAction[](1);
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetContextValue,
            data: abi.encode("test_key", "test_value")
        });
        
        ContextProxy.ProposalWithApprovals memory result = submitProposal(
            proposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        // Store initial state
        address initialProxyAddress = address(proxy);
        
        // Create UpdateProxy request through context contract using context author
        ContextConfig.ContextRequest memory contextRequest = ContextConfig.ContextRequest({
            contextId: contextId,
            kind: ContextConfig.ContextRequestKind.UpdateProxy,
            data: abi.encode(address(newImplementation))
        });

        // Create signed request using context author's credentials
        ContextConfig.Request memory request = ContextConfig.Request({
            signerId: bytes32(uint256(uint160(contextAuthorAddress))),
            userId: contextAuthorId,
            nonce: 2,
            kind: ContextConfig.RequestKind.Context,
            data: abi.encode(contextRequest)
        });

        bytes32 messageHash = keccak256(abi.encode(request));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(contextAuthorPrivateKey, ethSignedMessageHash);

        ContextConfig.SignedRequest memory signedRequest = ContextConfig.SignedRequest({
            payload: request,
            r: r,
            s: s,
            v: v
        });

        // Submit upgrade request to context contract
        bool success = contextConfig.mutate(signedRequest);
        assertTrue(success, "Proxy upgrade should succeed");
        
        // Verify proxy address hasn't changed
        assertEq(address(proxy), initialProxyAddress, "Proxy address should remain the same");
        
        // Verify state is preserved
        ContextProxy.Proposal memory storedProposal = proxy.getProposal(proposalId);
        assertEq(storedProposal.id, proposalId, "Proposal should still exist after upgrade");
        
        // Test functionality with new implementation
        bytes32 newProposalId = keccak256("post-upgrade-proposal");
        actions[0] = ContextProxy.ProposalAction({
            kind: ContextProxy.ProposalActionKind.SetContextValue,
            data: abi.encode("new_key", "new_value")
        });
        
        result = submitProposal(
            newProposalId,
            member1Id,
            member1PrivateKey,
            actions
        );
        
        assertEq(result.proposalId, newProposalId, "Should be able to create new proposals after upgrade");
    }
}