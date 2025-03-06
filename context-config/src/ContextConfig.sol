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
    event LogAuthorizationCheck(bytes32 contextId, address signer, bool hasCapability);
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

    event DebugLog(string message);
    event DebugLogUint(string message, uint value);
    event DebugLogBytes32(string message, bytes32 value);

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
     * @dev Get the message hash that needs to be signed
     * @param request The request to hash
     * @return The message hash
     */
    function getMessageHash(Request calldata request) public pure returns (bytes32) {
        return keccak256(abi.encode(request));
    }

    /**
     * @dev Get the Ethereum signed message hash
     * @param messageHash The message hash
     * @return The Ethereum signed message hash
     */
    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
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

        bytes32 messageHash = keccak256(abi.encode(request));
        // Add debug logs
        console.log("=== Debug Signature Verification ===");
        console.log("Input message hash:");
        console.logBytes32(messageHash);
        
        // Calculate the Ethereum signed message hash manually for debugging
        bytes32 manualEthHash = keccak256(abi.encodePacked(messageHash));
        console.log("Manual Ethereum signed message hash:");
        console.logBytes32(manualEthHash);
        
        // Get the Ethereum signed message hash using the function
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        console.log("Function Ethereum signed message hash:");
        console.logBytes32(ethSignedMessageHash);
        
        // Verify they match
        if (manualEthHash == ethSignedMessageHash) {
            console.log("Manual and function hashes match");
        } else {
            console.log("Manual and function hashes DO NOT match");
        }
        
        // Verify the signature using ECDSA key with ethSignedMessageHash
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        console.log("Recovered signer address:");
        console.log(signer);
        
        // Convert signer address to bytes32 for comparison
        bytes32 signerAsBytes32 = bytes32(uint256(uint160(signer)));
        console.log("Recovered signer as bytes32:");
        console.logBytes32(signerAsBytes32);
        
        console.log("Request signerId:");
        console.logBytes32(request.signerId);
        
        if (signer == address(0)) {
            console.log("SIGNATURE VERIFICATION FAILED: Recovered address is zero");
            revert InvalidSignature();
        }
        
        if (signerAsBytes32 != request.signerId) {
            console.log("SIGNATURE VERIFICATION FAILED: Recovered signer doesn't match signerId");
            revert InvalidSignature();
        }
        
        console.log("Signature verification passed!");

        // Check nonce to prevent replay attacks
        ContextRequest memory contextRequest = abi.decode(request.data, (ContextRequest));
        
        // For initial context creation, we don't need to check authorization
        if (contextRequest.kind == ContextRequestKind.Add) {
            return true;
        }

        Context storage context = contexts[contextRequest.contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        // Check if nonce is valid (except for context creation)
        if (context.memberNonces[request.userId] >= request.nonce) {
            revert InvalidNonce();
        }
        
        // Update nonce
        context.memberNonces[request.userId] = request.nonce;

        // For capability management, check if user is authorized (is in membersGuard)
        if (contextRequest.kind == ContextRequestKind.AddCapability ||
            contextRequest.kind == ContextRequestKind.RevokeCapability) {
            return isAuthorized(request.userId, contextRequest.contextId);
        }

        // For member management operations, check ManageMembers capability
        if (contextRequest.kind == ContextRequestKind.AddMembers ||
            contextRequest.kind == ContextRequestKind.RemoveMembers) {
            bool hasCap = hasCapability(request.userId, contextRequest.contextId, Capability.ManageMembers);
            emit LogAuthorizationCheck(contextRequest.contextId, signer, hasCap);
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
        Context storage context = contexts[contextId];
        for (uint i = 0; i < context.membersGuard.privileged.length; i++) {
            if (context.membersGuard.privileged[i] == userId) {
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
        emit DebugLog("mutate function called");

        
        // bytes32 messageHash = getMessageHash(request.payload);
        // emit DebugLog("messageHash calculated");
        
        emit DebugLogUint("request.payload.kind", uint(request.payload.kind));

        console.log("messageHash");
        
        if (!verifyAndAuthorize(
            request.payload,
            request.r,
            request.s,
            request.v
        )) {
            revert InvalidSignature();
        }

        console.log("request.payload.kind");

        if (request.payload.kind == RequestKind.Context) {
            console.log("request.payload.kind == RequestKind.Context");
            ContextRequest memory contextRequest = abi.decode(request.payload.data, (ContextRequest));
            console.log("contextRequest.kind");
            if (contextRequest.kind == ContextRequestKind.Add) {
                console.log("contextRequest.kind == ContextRequestKind.Add");
    
                // Log the data length and first bytes
                console.log("contextRequest.data length:", contextRequest.data.length);
                
                // Log the first 64 bytes (or less if the data is shorter)
                bytes memory dataPrefix = new bytes(contextRequest.data.length < 64 ? contextRequest.data.length : 64);
                for (uint i = 0; i < dataPrefix.length; i++) {
                    dataPrefix[i] = contextRequest.data[i];
                }
                console.log("First bytes of contextRequest.data:");
                console.logBytes(dataPrefix);
                
                // Attempt to decode just the authorId first
                bytes32 authorId;
                bytes memory data = contextRequest.data;
                assembly {
                    // Load the first 32 bytes from the data
                    authorId := mload(add(data, 0x20))
                }
                console.log("Extracted authorId (first 32 bytes):");
                console.logBytes32(authorId);
                
                // Now try the full decode
                (bytes32 decodedAuthorId, Application memory app) = abi.decode(
                    contextRequest.data,
                    (bytes32, Application)
                );
                
                console.log("Decoding successful!");
                console.log("Decoded authorId:");
                console.logBytes32(decodedAuthorId);
                console.log("contextRequest.contextId");
                console.logBytes32(contextRequest.contextId);
                
                return addContext(decodedAuthorId, contextRequest.contextId, app);
            }
            else if (contextRequest.kind == ContextRequestKind.AddMembers) {
                bytes32[] memory newMembers = abi.decode(contextRequest.data, (bytes32[]));
                return addMembers(
                    contextRequest.contextId,
                    request.payload.userId,
                    newMembers
                );
            }
            else if (contextRequest.kind == ContextRequestKind.RemoveMembers) {
                bytes32[] memory membersToRemove = abi.decode(contextRequest.data, (bytes32[]));
                return removeMembers(
                    contextRequest.contextId,
                    request.payload.userId,
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
                    request.payload.userId,
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
                    request.payload.userId,
                    memberId,
                    capability
                );
            }
            else if (contextRequest.kind == ContextRequestKind.UpdateProxy) {
                return updateProxy(
                    contextRequest.contextId,
                    request.payload.userId
                );
            }
            else if (contextRequest.kind == ContextRequestKind.UpdateApplication) {
                Application memory newApp = abi.decode(contextRequest.data, (Application));
                return updateApplication(
                    contextRequest.contextId,
                    request.payload.userId,
                    newApp
                );
            }
        }

        return false;

        // revert InvalidRequest();
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
        console.log("addContext");

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

        console.log("deployProxy");

        // Deploy proxy contract
        address proxyAddress = deployProxy(contextId);
        if (proxyAddress == address(0)) {
            revert ProxyDeploymentFailed();
        }

        console.log("assignFields");

        // Assign fields individually
        Context storage newContext = contexts[contextId];
        newContext.applicationGuard = guard;
        newContext.application = app;
        newContext.membersGuard = guard;
        newContext.members = contextMembers;
        newContext.proxyGuard = guard;
        newContext.proxyAddress = proxyAddress;
        newContext.memberNonces[authorId] = 0;

        console.log("emitContextCreated");

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
     * @param signerId The signer ID
     * @param newMembers The new members
     * @return Whether the members were added
     */
    function addMembers(
        bytes32 contextId,
        bytes32 signerId,
        bytes32[] memory newMembers
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        if (!hasCapability(signerId, contextId, Capability.ManageMembers)) {
            revert Unauthorized();
        }

        // Add new members
        for (uint i = 0; i < newMembers.length; i++) {
            bytes32 newMember = newMembers[i];
            bool alreadyMember = false;
            
            // Check if already a member
            for (uint j = 0; j < context.members.length; j++) {
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

        // Increment revision
        context.membersGuard.revision++;
        
        emit MembersAdded(contextId, newMembers);
        return true;
    }

    /**
     * @dev Remove members from a context
     * @param contextId The context ID
     * @param signerId The signer ID
     * @param membersToRemove The members to remove
     * @return Whether the members were removed
     */
    function removeMembers(
        bytes32 contextId,
        bytes32 signerId,
        bytes32[] memory membersToRemove
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        if (!hasCapability(signerId, contextId, Capability.ManageMembers)) {
            revert Unauthorized();
        }

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

        // Increment revision
        context.membersGuard.revision++;
        
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
     * @param signerId The signer ID
     * @param memberId The member ID
     * @param capability The capability
     * @return Whether the capability was added
     */
    function addCapability(
        bytes32 contextId,
        bytes32 signerId,
        bytes32 memberId,
        Capability capability
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        // Check if signer has the capability they're trying to grant
        if (!hasCapability(signerId, contextId, capability)) {
            revert Unauthorized();
        }

        // Add capability
        if (capability == Capability.ManageApplication) {
            context.applicationGuard.privileged.push(memberId);
            context.applicationGuard.revision++;
        } else if (capability == Capability.ManageMembers) {
            context.membersGuard.privileged.push(memberId);
            context.membersGuard.revision++;
        } else if (capability == Capability.Proxy) {
            context.proxyGuard.privileged.push(memberId);
            context.proxyGuard.revision++;
        }

        emit CapabilityAdded(contextId, memberId, capability);
        return true;
    }

    /**
     * @dev Revoke a capability from a user
     * @param contextId The context ID
     * @param signerId The signer ID
     * @param memberId The member ID
     * @param capability The capability
     * @return Whether the capability was revoked
     */
    function revokeCapability(
        bytes32 contextId,
        bytes32 signerId,
        bytes32 memberId,
        Capability capability
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }

        // Check if signer has the capability they're trying to revoke
        if (!hasCapability(signerId, contextId, capability)) {
            revert Unauthorized();
        }

        // Remove capability
        bytes32[] storage privileged;
        if (capability == Capability.ManageApplication) {
            privileged = context.applicationGuard.privileged;
        } else if (capability == Capability.ManageMembers) {
            privileged = context.membersGuard.privileged;
        } else if (capability == Capability.Proxy) {
            privileged = context.proxyGuard.privileged;
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
    function applicationRevision(bytes32 contextId) external view returns (uint32) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        return context.applicationGuard.revision;
    }

    /**
     * @dev Get the members revision
     * @param contextId The context ID
     * @return The members revision
     */
    function membersRevision(bytes32 contextId) external view returns (uint32) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        return context.membersGuard.revision;
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
    function fetchNonce(bytes32 contextId, bytes32 userId) external view returns (uint64) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        
        return context.memberNonces[userId];
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
    function proxyContract(bytes32 contextId) external view returns (address) {
        Context storage context = contexts[contextId];
        console.log("context.applicationGuard.revision", context.applicationGuard.revision);
        console.log("context.proxyAddress", context.proxyAddress);
        console.logBytes32(contextId);
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        console.log("context.proxyAddress", context.proxyAddress);
        return context.proxyAddress;
    }

    /**
     * @dev Update the application for a context
     * @param contextId The context ID
     * @param userId The user ID making the request
     * @param app The new application
     * @return Whether the operation was successful
     */
    function updateApplication(
        bytes32 contextId,
        bytes32 userId,
        Application memory app
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        
        // Check if user has ManageApplication capability
        if (!hasCapability(userId, contextId, Capability.ManageApplication)) {
            revert Unauthorized();
        }
        
        context.application = app;
        context.applicationGuard.revision++;
        
        emit ApplicationUpdated(contextId);
        return true;
    }

    /**
     * @dev Update the proxy for a context
     * @param contextId The context ID
     * @param userId The user ID
     * @return Whether the operation was successful
     */
    function updateProxy(
        bytes32 contextId,
        bytes32 userId
    ) internal returns (bool) {
        Context storage context = contexts[contextId];
        if (context.applicationGuard.revision == 0) {
            revert ContextNotFound();
        }
        
        // Check if user has Proxy capability
        if (!hasCapability(userId, contextId, Capability.Proxy)) {
            revert Unauthorized();
        }
        
        // Deploy a new proxy (this will replace the existing one if any)
        if (proxyBytecode.length == 0) {
            revert ProxyBytecodeNotSet();
        }
        
        // If there's an existing proxy, we'll redeploy and update the address
        address proxyAddress = deployProxy(contextId);
        if (proxyAddress == address(0)) {
            revert ProxyDeploymentFailed();
        }
        
        return true;
    }

    // Add this simple test function to your contract
    function testLog() external {
        emit DebugLog("This is a test log");
        emit DebugLogUint("A number", 42);
        emit DebugLogBytes32("A bytes32", bytes32(uint256(123)));
    }

    function testSignedRequest(SignedRequest calldata request) external returns (bool) {
        emit DebugLog("testSignedRequest called");
        return true;
    }
} 