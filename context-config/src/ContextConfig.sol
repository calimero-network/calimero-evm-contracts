// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";

/**
 * @title ContextConfig
 * @dev Contract for managing context configurations, members, and capabilities
 */
contract ContextConfig {

    struct Guard {
        bytes32[] privileged;
        uint32 revision;
    }

    struct Context {
        Guard applicationGuard;
        Application application;
        
        Guard membersGuard;
        bytes32[] members;
        
        Guard proxyGuard;
        address proxyAddress;
        
        mapping(bytes32 => uint64) memberNonces;
    }

    // State variables
    mapping(bytes32 => Context) public contexts;
    bytes32 public proxyCodeHash;
    address public immutable owner;
    bytes public proxyBytecode;

    // Events
    event ContextCreated(bytes32 indexed contextId, bytes32 authorId);
    event MembersAdded(bytes32 indexed contextId, bytes32[] members);
    event MembersRemoved(bytes32 indexed contextId, bytes32[] members);
    event ApplicationUpdated(bytes32 indexed contextId);
    event ProxyUpdated(bytes32 indexed contextId, address proxyAddress);
    event CapabilityAdded(bytes32 indexed contextId, bytes32 memberId, Capability capability);
    event CapabilityRevoked(bytes32 indexed contextId, bytes32 memberId, Capability capability);
    event ProxyDeployed(bytes32 indexed contextId, address proxyAddress);
    event ProxyCodeUpdated(bytes32 newCodeHash);

    // Errors
    error Unauthorized();
    error ContextAlreadyExists();
    error ContextNotFound();
    error NotAMember();
    error InvalidNonce();
    error InvalidSignature();
    error InvalidRequest();
    error ProxyDeploymentFailed();
    error ProxyBytecodeNotSet();

    // Data structures
    struct Application {
        bytes32 id;
        bytes32 blob;
        uint64 size;
        string source;
        bytes metadata;
    }

    enum RequestKind {
        Context  // Wraps ContextRequest
    }

    enum Capability {
        ManageMembers,
        ManageApplication,
        Proxy
    }

    enum ContextRequestKind {
        Add,               // (bytes32 authorId, Application application)
        AddMembers,        // (bytes32[] newMembers)
        RemoveMembers,     // (bytes32[] membersToRemove)
        AddCapability,     // (bytes32 memberId, Capability capability)
        RevokeCapability,  // (bytes32 memberId, Capability capability)
        UpdateProxy,       // (no data needed, deploys proxy if not already deployed)
        UpdateApplication  // (Application newApplication)
    }

    struct ContextRequest {
        bytes32 contextId;
        ContextRequestKind kind;
        bytes data;
    }

    struct Request {
        bytes32 signerId;    // ECDSA public key
        bytes32 userId;      // Ed25519 public key
        uint64 nonce;
        RequestKind kind;
        bytes data;
    }

    struct SignedRequest {
        Request payload;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct UserCapabilities {
        bytes32 userId;
        Capability[] capabilities;
    }

    /**
     * @dev Constructor
     * @param _owner Owner address
     */
    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * @dev Modifier to check if context exists
     * @param contextId The context ID
     */
    modifier contextExists(bytes32 contextId) {
        console.log("contexts[contextId].applicationGuard.revision: %d", contexts[contextId].applicationGuard.revision);
        if (contexts[contextId].applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        _;
    }

    /**
     * @dev Verify and authorize a request
     * @param request The request to verify
     * @param r The r value of the signature
     * @param s The s value of the signature
     * @param v The v value of the signature
     * @return Whether the request is authorized
     */
    function verifyAndAuthorize(
        Request calldata request,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) internal returns (bool) {
        // Verify signature
        bytes32 messageHash = keccak256(abi.encode(request));
        
        // Get the Ethereum signed message hash
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));

        // Verify the signature using ECDSA key with ethSignedMessageHash
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        // Convert signer address to bytes32 for comparison
        bytes32 signerAsBytes32 = bytes32(uint256(uint160(signer)));

        if (signer == address(0) || signerAsBytes32 != request.signerId) {
            revert InvalidSignature();
        }
        
        // Decode context request once to avoid multiple decoding operations
        ContextRequest memory contextRequest = abi.decode(request.data, (ContextRequest));
        console.log("contextRequest.kind: %d", uint8(contextRequest.kind));
        
        // For initial context creation, we don't need to check authorization
        if (contextRequest.kind == ContextRequestKind.Add) {
            return true;
        }

        console.log("contextRequest.contextId:");
        console.logBytes32(contextRequest.contextId);
        // Get context and check if it exists
        Context storage context = contexts[contextRequest.contextId];
        console.log("context.applicationGuard.revision: %d", context.applicationGuard.revision);
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        console.log("passed context.applicationGuard.revision == 0");
        // Check if nonce is valid
        uint64 currentNonce = context.memberNonces[request.userId];
        console.log("currentNonce: %d", currentNonce);
        console.log("request.nonce: %d", request.nonce);
        if (currentNonce != request.nonce) {
            revert InvalidNonce();
        }
        console.log("passed currentNonce >= request.nonce");
        // Update nonce
        context.memberNonces[request.userId] = request.nonce;

        // Handle different request types
        ContextRequestKind kind = contextRequest.kind;
        
        // For capability management, check if user is authorized
        if (kind == ContextRequestKind.AddCapability || kind == ContextRequestKind.RevokeCapability) {
            return isAuthorized(request.userId, contextRequest.contextId);
        }

        // For member management operations, check ManageMembers capability
        if (kind == ContextRequestKind.AddMembers || kind == ContextRequestKind.RemoveMembers) {
            bool hasCap = hasCapability(request.userId, contextRequest.contextId, Capability.ManageMembers);

            if (!hasCap) {
                revert Unauthorized();
            }
            return true;
        }

        // For any other operations, require general authorization
        return isAuthorized(request.userId, contextRequest.contextId);
    }

    /**
     * @dev Check if a user is authorized for a context
     * @param userId The user ID
     * @param contextId The context ID
     * @return Whether the user is authorized
     */
    function isAuthorized(bytes32 userId, bytes32 contextId) internal view returns (bool) {
        bytes32[] storage privileged = contexts[contextId].membersGuard.privileged;
        uint256 length = privileged.length;
        
        for (uint i = 0; i < length; i++) {
            if (privileged[i] == userId) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Process a signed request
     * @param request The signed request
     * @return Whether the request was successful
     */
    function mutate(SignedRequest calldata request) external returns (bool) {
        
        if (!verifyAndAuthorize(
            request.payload,
            request.r,
            request.s,
            request.v
        )) {
            revert InvalidSignature();
        }

        console.log("passed verifyAndAuthorize");

        if (request.payload.kind == RequestKind.Context) {
            console.log("passed request.payload.kind == RequestKind.Context");
            ContextRequest memory contextRequest = abi.decode(request.payload.data, (ContextRequest));
            console.log("passed abi.decode(request.payload.data, (ContextRequest))");
            if (contextRequest.kind == ContextRequestKind.Add) {
                console.log("passed contextRequest.kind == ContextRequestKind.Add");
                
                // Get the data bytes
                bytes memory data = contextRequest.data;
                console.log("data length: %d", data.length);
                
                // Log the raw data bytes without using slices
                // We'll log individual bytes in chunks
                if (data.length >= 32) {
                    bytes32 chunk1;
                    assembly {
                        // Load 32 bytes from memory - need to add 32 to skip the length field
                        chunk1 := mload(add(data, 32))
                    }
                    console.log("First 32 bytes:");
                    console.logBytes32(chunk1);
                }
                
                if (data.length >= 64) {
                    bytes32 chunk2;
                    assembly {
                        // Load next 32 bytes
                        chunk2 := mload(add(data, 64))
                    }
                    console.log("Next 32 bytes:");
                    console.logBytes32(chunk2);
                }
                
                if (data.length >= 96) {
                    bytes32 chunk3;
                    assembly {
                        // Load next 32 bytes
                        chunk3 := mload(add(data, 96))
                    }
                    console.log("Next 32 bytes:");
                    console.logBytes32(chunk3);
                }
                
                console.log("About to decode (bytes32, Application)");
                
                // MODIFIED: Check if the first 32 bytes are a pointer (0x20)
                bytes32 firstWord;
                assembly {
                    firstWord := mload(add(data, 32))
                }
                
                bytes memory actualData;
                bytes32 decodedAuthorId;
                Application memory app;
                
                if (firstWord == 0x0000000000000000000000000000000000000000000000000000000000000020) {
                    console.log("Detected pointer at start of data, skipping first 32 bytes");
                    // Skip the first 32 bytes (the pointer) and use the rest
                    actualData = new bytes(data.length - 32);
                    for (uint i = 0; i < data.length - 32; i++) {
                        actualData[i] = data[i + 32];
                    }
                    
                    // Attempt the decode on the adjusted data
                    (decodedAuthorId, app) = abi.decode(
                        actualData,
                        (bytes32, Application)
                    );
                } else {
                    // Use the original data
                    (decodedAuthorId, app) = abi.decode(
                        data,
                        (bytes32, Application)
                    );
                }
                
                // If we get here, decoding was successful
                console.log("Decode successful");
                console.log("authorId:");
                console.logBytes32(decodedAuthorId);
                console.log("app.id:");
                console.logBytes32(app.id);
                console.log("app.blob:");
                console.logBytes32(app.blob);
                console.log("app.size:");
                console.log(app.size);
                console.log("app.source:");
                console.log(app.source);
                console.log("app.metadata:");
                console.logBytes(app.metadata);
                console.log("contextRequest.contextId:");
                console.logBytes32(contextRequest.contextId);
                
                // Log if any bytes in app.id are non-zero
                bool hasNonZeroId = false;
                for (uint i = 0; i < 32; i++) {
                    if (app.id[i] != 0) {
                        hasNonZeroId = true;
                        console.log("app.id has non-zero byte at position %d: %d", i, uint8(app.id[i]));
                    }
                }
                if (!hasNonZeroId) {
                    console.log("All bytes in app.id are zero");
                }
                
                // Log if any bytes in app.blob are non-zero
                bool hasNonZeroBlob = false;
                for (uint i = 0; i < 32; i++) {
                    if (app.blob[i] != 0) {
                        hasNonZeroBlob = true;
                        console.log("app.blob has non-zero byte at position %d: %d", i, uint8(app.blob[i]));
                    }
                }
                if (!hasNonZeroBlob) {
                    console.log("All bytes in app.blob are zero");
                }
                
                console.log("passed (bytes32 decodedAuthorId, Application memory app)");
                return addContext(decodedAuthorId, contextRequest.contextId, app);
            }
            else if (contextRequest.kind == ContextRequestKind.AddMembers) {
                console.log("passed contextRequest.kind == ContextRequestKind.AddMembers");
                bytes32[] memory newMembers = abi.decode(contextRequest.data, (bytes32[]));

                return addMembers(
                    contextRequest.contextId,
                    newMembers
                );
            }
            else if (contextRequest.kind == ContextRequestKind.RemoveMembers) {
                bytes32[] memory membersToRemove = abi.decode(contextRequest.data, (bytes32[]));
                return removeMembers(
                    contextRequest.contextId,
                    membersToRemove
                );
            }
            else if (contextRequest.kind == ContextRequestKind.AddCapability) {
                (bytes32 memberId, Capability capability) = abi.decode(
                    contextRequest.data,
                    (bytes32, Capability)
                );
                return addCapability(
                    contextRequest.contextId,
                    memberId,
                    capability
                );
            }
            else if (contextRequest.kind == ContextRequestKind.RevokeCapability) {
                (bytes32 memberId, Capability capability) = abi.decode(
                    contextRequest.data,
                    (bytes32, Capability)
                );
                return revokeCapability(
                    contextRequest.contextId,
                    memberId,
                    capability
                );
            }
            else if (contextRequest.kind == ContextRequestKind.UpdateProxy) {
                return updateProxy(
                    contextRequest.contextId
                );
            }
            else if (contextRequest.kind == ContextRequestKind.UpdateApplication) {
                Application memory newApp = abi.decode(contextRequest.data, (Application));
                return updateApplication(
                    contextRequest.contextId,
                    newApp
                );
            }
        }

        revert InvalidRequest();
    }

    /**
     * @dev Add a new context
     * @param authorId The context owner
     * @param contextId The context ID
     * @param app The application
     * @return Whether the context was added
     */
    function addContext(
        bytes32 authorId,
        bytes32 contextId,
        Application memory app
    ) internal returns (bool) {
        if (contexts[contextId].applicationGuard.revision != 0) {
            revert ContextAlreadyExists();
        }

        // Initialize guards with Ed25519 public key (authorId)
        bytes32[] memory privilegedMembers = new bytes32[](1);
        privilegedMembers[0] = authorId;

        Guard memory guard = Guard({
            privileged: privilegedMembers,
            revision: 1
        });

        // Initialize members with Ed25519 public key
        bytes32[] memory contextMembers = new bytes32[](1);
        contextMembers[0] = authorId;

        // Check if proxy bytecode is set
        if (proxyBytecode.length == 0) {
            revert ProxyBytecodeNotSet();
        }

        // Deploy proxy contract
        address proxyAddress = deployProxy(contextId);
        if (proxyAddress == address(0)) {
            revert ProxyDeploymentFailed();
        }

        // Assign fields individually
        Context storage newContext = contexts[contextId];
        newContext.applicationGuard = guard;
        newContext.application = app;
        newContext.membersGuard = guard;
        newContext.members = contextMembers;
        newContext.proxyGuard = guard;
        newContext.proxyAddress = proxyAddress;
        newContext.memberNonces[authorId] = 0;

        emit ContextCreated(contextId, authorId);
        return true;
    }

    /**
     * @dev Get context application
     * @param contextId The context ID
     * @return The application
     */
    function application(bytes32 contextId) external view returns (Application memory) {
        Context storage context = contexts[contextId];
        
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        
        return context.application;
    }

    /**
     * @dev Add members to a context
     * @param contextId The context ID
     * @param newMembers The new members
     * @return Whether the members were added
     */
    function addMembers(
        bytes32 contextId,
        bytes32[] memory newMembers
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        
        // Cache array length to save gas
        uint256 membersLength = context.members.length;
        
        // Add new members
        for (uint i = 0; i < newMembers.length; i++) {
            bytes32 newMember = newMembers[i];
            bool alreadyMember = false;
            
            // Check if already a member
            for (uint j = 0; j < membersLength; j++) {
                if (context.members[j] == newMember) {
                    alreadyMember = true;
                    break;
                }
            }
            
            if (!alreadyMember) {
                context.members.push(newMember);
                context.memberNonces[newMember] = 0;
            }
        }

        // Increment revision using unchecked to save gas
        unchecked {
            context.membersGuard.revision++;
        }
        
        emit MembersAdded(contextId, newMembers);
        return true;
    }

    /**
     * @dev Remove members from a context
     * @param contextId The context ID
     * @param membersToRemove The members to remove
     * @return Whether the members were removed
     */
    function removeMembers(
        bytes32 contextId,
        bytes32[] memory membersToRemove
    ) internal returns (bool) {
        Context storage context = contexts[contextId];

        // Remove members
        for (uint i = 0; i < membersToRemove.length; i++) {
            bytes32 memberToRemove = membersToRemove[i];
            
            // Find and remove member
            for (uint j = 0; j < context.members.length; j++) {
                if (context.members[j] == memberToRemove) {
                    // Move last element to removed position (if not last)
                    if (j != context.members.length - 1) {
                        context.members[j] = context.members[context.members.length - 1];
                    }
                    context.members.pop();
                    delete context.memberNonces[memberToRemove];
                    break;
                }
            }
        }

        // Increment revision using unchecked to save gas
        unchecked {
            context.membersGuard.revision++;
        }
        
        emit MembersRemoved(contextId, membersToRemove);
        return true;
    }

    /**
     * @dev Get members of a context
     * @param contextId The context ID
     * @param offset The offset
     * @param length The length
     * @return The members
     */
    function members(
        bytes32 contextId,
        uint256 offset,
        uint256 length
    ) external view returns (bytes32[] memory) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        // If there are no members or offset is beyond array length, return empty array
        if (context.members.length == 0 || offset >= context.members.length) {
            return new bytes32[](0);
        }

        uint256 available = context.members.length - offset;
        uint256 resultLength = available < length ? available : length;
        
        bytes32[] memory result = new bytes32[](resultLength);
        for (uint256 i = 0; i < resultLength; i++) {
            result[i] = context.members[offset + i];
        }
        
        return result;
    }

    /**
     * @dev Check if a user has a capability
     * @param userId The user ID
     * @param contextId The context ID
     * @param capability The capability
     * @return Whether the user has the capability
     */
    function hasCapability(
        bytes32 userId,
        bytes32 contextId,
        Capability capability
    ) internal view returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            return false;
        }

        // Check specific capability only
        bytes32[] storage privileged;
        if (capability == Capability.ManageApplication) {
            privileged = context.applicationGuard.privileged;
        } else if (capability == Capability.ManageMembers) {
            privileged = context.membersGuard.privileged;
        } else if (capability == Capability.Proxy) {
            privileged = context.proxyGuard.privileged;
        } else {
            return false;
        }

        for (uint i = 0; i < privileged.length; i++) {
            if (privileged[i] == userId) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Add a capability to a user
     * @param contextId The context ID
     * @param memberId The member ID
     * @param capability The capability
     * @return Whether the capability was added
     */
    function addCapability(
        bytes32 contextId,
        bytes32 memberId,
        Capability capability
    ) internal returns (bool) {
        Context storage context = contexts[contextId];

        // Add capability
        if (capability == Capability.ManageApplication) {
            context.applicationGuard.privileged.push(memberId);
            unchecked { context.applicationGuard.revision++; }
        } else if (capability == Capability.ManageMembers) {
            context.membersGuard.privileged.push(memberId);
            unchecked { context.membersGuard.revision++; }
        } else if (capability == Capability.Proxy) {
            context.proxyGuard.privileged.push(memberId);
            unchecked { context.proxyGuard.revision++; }
        }

        emit CapabilityAdded(contextId, memberId, capability);
        return true;
    }

    /**
     * @dev Revoke a capability from a user
     * @param contextId The context ID
     * @param memberId The member ID
     * @param capability The capability
     * @return Whether the capability was revoked
     */
    function revokeCapability(
        bytes32 contextId,
        bytes32 memberId,
        Capability capability
    ) internal returns (bool) {
        Context storage context = contexts[contextId];

        // Remove capability
        bytes32[] storage privileged;
        if (capability == Capability.ManageApplication) {
            privileged = context.applicationGuard.privileged;
            unchecked { context.applicationGuard.revision++; }
        } else if (capability == Capability.ManageMembers) {
            privileged = context.membersGuard.privileged;
            unchecked { context.membersGuard.revision++; }
        } else if (capability == Capability.Proxy) {
            privileged = context.proxyGuard.privileged;
            unchecked { context.proxyGuard.revision++; }
        } else {
            revert InvalidRequest();
        }

        for (uint i = 0; i < privileged.length; i++) {
            if (privileged[i] == memberId) {
                // Move last element to removed position (if not last)
                if (i != privileged.length - 1) {
                    privileged[i] = privileged[privileged.length - 1];
                }
                privileged.pop();
                break;
            }
        }

        emit CapabilityRevoked(contextId, memberId, capability);
        return true;
    }

    /**
     * @dev Check if a user has a privilege in a guard
     * @param privileged The privileged users
     * @param userId The user ID
     * @return Whether the user has the privilege
     */
    function hasPrivilege(bytes32[] memory privileged, bytes32 userId) internal pure returns (bool) {
        for (uint i = 0; i < privileged.length; i++) {
            if (privileged[i] == userId) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Check if a user is in an array
     * @param arr The array
     * @param length The length
     * @param user The user
     * @return Whether the user is in the array
     */
    function isUserInArray(bytes32[] memory arr, uint256 length, bytes32 user) internal pure returns (bool) {
        for (uint i = 0; i < length; i++) {
            if (arr[i] == user) return true;
        }
        return false;
    }

    /**
     * @dev Get privileges for users
     * @param contextId The context ID
     * @param identities The identities
     * @return The user capabilities
     */
    function privileges(
        bytes32 contextId,
        bytes32[] calldata identities
    ) external view returns (UserCapabilities[] memory) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        return _privileges(
            context.applicationGuard.privileged,
            context.membersGuard.privileged,
            context.proxyGuard.privileged,
            identities
        );
    }

    /**
     * @dev Internal function to get privileges
     * @param applicationPrivileged The application privileged users
     * @param membersPrivileged The members privileged users
     * @param proxyPrivileged The proxy privileged users
     * @param identities The identities
     * @return The user capabilities
     */
    function _privileges(
        bytes32[] memory applicationPrivileged,
        bytes32[] memory membersPrivileged,
        bytes32[] memory proxyPrivileged,
        bytes32[] memory identities
    ) internal pure returns (UserCapabilities[] memory) {
        // If no specific identities requested, check all privileged users
        if (identities.length == 0) {
            // First collect all unique users into an array
            bytes32[] memory uniqueUsers = new bytes32[](
                applicationPrivileged.length + 
                membersPrivileged.length + 
                proxyPrivileged.length
            );
            uint256 uniqueCount = 0;

            // Collect unique users
            for (uint i = 0; i < applicationPrivileged.length; i++) {
                if (!isUserInArray(uniqueUsers, uniqueCount, applicationPrivileged[i])) {
                    uniqueUsers[uniqueCount++] = applicationPrivileged[i];
                }
            }
            for (uint i = 0; i < membersPrivileged.length; i++) {
                if (!isUserInArray(uniqueUsers, uniqueCount, membersPrivileged[i])) {
                    uniqueUsers[uniqueCount++] = membersPrivileged[i];
                }
            }
            for (uint i = 0; i < proxyPrivileged.length; i++) {
                if (!isUserInArray(uniqueUsers, uniqueCount, proxyPrivileged[i])) {
                    uniqueUsers[uniqueCount++] = proxyPrivileged[i];
                }
            }

            // Create result array with actual size
            UserCapabilities[] memory result = new UserCapabilities[](uniqueCount);
            
            // Fill in capabilities for each unique user
            for (uint i = 0; i < uniqueCount; i++) {
                result[i].userId = uniqueUsers[i];
                
                // Count capabilities first
                uint256 capCount = 0;
                if (hasPrivilege(applicationPrivileged, uniqueUsers[i])) capCount++;
                if (hasPrivilege(membersPrivileged, uniqueUsers[i])) capCount++;
                if (hasPrivilege(proxyPrivileged, uniqueUsers[i])) capCount++;
                
                // Allocate exact size array
                result[i].capabilities = new Capability[](capCount);
                
                // Fill capabilities
                uint256 capIndex = 0;
                if (hasPrivilege(applicationPrivileged, uniqueUsers[i])) {
                    result[i].capabilities[capIndex++] = Capability.ManageApplication;
                }
                if (hasPrivilege(membersPrivileged, uniqueUsers[i])) {
                    result[i].capabilities[capIndex++] = Capability.ManageMembers;
                }
                if (hasPrivilege(proxyPrivileged, uniqueUsers[i])) {
                    result[i].capabilities[capIndex++] = Capability.Proxy;
                }
            }
            
            return result;
        } else {
            // Check specific identities
            UserCapabilities[] memory result = new UserCapabilities[](identities.length);
            for (uint i = 0; i < identities.length; i++) {
                result[i].userId = identities[i];
                
                // Count capabilities first
                uint256 capCount = 0;
                if (hasPrivilege(applicationPrivileged, identities[i])) capCount++;
                if (hasPrivilege(membersPrivileged, identities[i])) capCount++;
                if (hasPrivilege(proxyPrivileged, identities[i])) capCount++;
                
                // Allocate exact size array
                result[i].capabilities = new Capability[](capCount);
                
                // Fill capabilities
                uint256 capIndex = 0;
                if (hasPrivilege(applicationPrivileged, identities[i])) {
                    result[i].capabilities[capIndex++] = Capability.ManageApplication;
                }
                if (hasPrivilege(membersPrivileged, identities[i])) {
                    result[i].capabilities[capIndex++] = Capability.ManageMembers;
                }
                if (hasPrivilege(proxyPrivileged, identities[i])) {
                    result[i].capabilities[capIndex++] = Capability.Proxy;
                }
            }
            return result;
        }
    }

    /**
     * @dev Get the application revision
     * @param contextId The context ID
     * @return The application revision
     */
    function applicationRevision(bytes32 contextId) external view contextExists(contextId) returns (uint32) {
        return contexts[contextId].applicationGuard.revision;
    }

    /**
     * @dev Get the members revision
     * @param contextId The context ID
     * @return The members revision
     */
    function membersRevision(bytes32 contextId) external view contextExists(contextId) returns (uint32) {
        return contexts[contextId].membersGuard.revision;
    }

    /**
     * @dev Check if a user is a member of a context
     * @param contextId The context ID
     * @param userId The user ID
     * @return Whether the user is a member
     */
    function hasMember(bytes32 contextId, bytes32 userId) external view returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            return false;
        }
        
        for (uint i = 0; i < context.members.length; i++) {
            if (context.members[i] == userId) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Get the nonce for a user
     * @param contextId The context ID
     * @param userId The user ID
     * @return The nonce
     */
    function fetchNonce(bytes32 contextId, bytes32 userId) external view contextExists(contextId) returns (uint64) {
        return contexts[contextId].memberNonces[userId];
    }

    /**
     * @dev Set the proxy bytecode
     * @param newBytecode The new proxy bytecode
     * @return Whether the operation was successful
     */
    function setProxyCode(bytes calldata newBytecode) external returns (bool) {
        // Only owner can set proxy bytecode
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        
        proxyBytecode = newBytecode;
        proxyCodeHash = keccak256(newBytecode);
        
        emit ProxyCodeUpdated(proxyCodeHash);
        return true;
    }

    /**
     * @dev Deploy a proxy contract for a context
     * @param contextId The context ID
     * @return The address of the deployed proxy
     */
    function deployProxy(bytes32 contextId) internal returns (address) {
        if (proxyBytecode.length == 0) {
            revert ProxyBytecodeNotSet();
        }
        
        // Get the current context
        Context storage context = contexts[contextId];
        
        // For context creation or updates, use a different salt based on the revision
        uint32 revisionToUse = context.applicationGuard.revision == 0 ? 1 : context.proxyGuard.revision + 1;
        
        // Create a unique salt using the contextId and revision
        bytes32 salt = keccak256(abi.encodePacked(contextId, revisionToUse, block.timestamp));
        
        // Encode constructor parameters
        bytes memory constructorArgs = abi.encode(contextId, address(this));
        
        // Concatenate bytecode and constructor args
        bytes memory bytecode = bytes.concat(
            proxyBytecode,
            constructorArgs
        );
        
        // Deploy the proxy
        address proxyAddress;
        assembly {
            proxyAddress := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        
        if (proxyAddress == address(0)) {
            revert ProxyDeploymentFailed();
        }
        
        return proxyAddress;
    }

    /**
     * @dev Get the proxy contract address for a context
     * @param contextId The context ID
     * @return The proxy contract address
     */
    function proxyContract(bytes32 contextId) external view contextExists(contextId) returns (address) {
        return contexts[contextId].proxyAddress;
    }

    /**
     * @dev Update the application for a context
     * @param contextId The context ID
     * @param app The new application
     * @return Whether the operation was successful
     */
    function updateApplication(
        bytes32 contextId,
        Application memory app
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        
        context.application = app;
        unchecked { context.applicationGuard.revision++; }
        
        emit ApplicationUpdated(contextId);
        return true;
    }

    /**
     * @dev Update the proxy for a context
     * @param contextId The context ID
     * @return Whether the operation was successful
     */
    function updateProxy(
        bytes32 contextId
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        
        if (proxyBytecode.length == 0) {
            revert ProxyBytecodeNotSet();
        }
        
        address proxyAddress = deployProxy(contextId);
        if (proxyAddress == address(0)) {
            revert ProxyDeploymentFailed();
        }
        
        // Update the proxy address in storage
        context.proxyAddress = proxyAddress;
        
        unchecked {
            context.proxyGuard.revision++;
        }
        
        emit ProxyUpdated(contextId, proxyAddress);
        emit ProxyDeployed(contextId, proxyAddress);
        return true;
    }
} 