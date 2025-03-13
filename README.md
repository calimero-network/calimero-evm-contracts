## Calimero EVM Contracts

Smart contracts for the Calimero EVM implementation.

This repository contains two separate contract projects:
- **Context Config**: Located in the `context-config` directory
- **Context Proxy**: Located in the `context-proxy` directory

Each contract needs to be built separately in its respective directory.

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Development Workflow

### Build Contracts

You need to build each contract in its respective directory:

```shell
# Build Context Config
$ cd context-config
$ forge install foundry-rs/forge-std --no-git
$ forge build

# Build Context Proxy
$ cd ../context-proxy
$ forge install foundry-rs/forge-std --no-git
$ forge build

# Build Mock Contract
$ cd ../mock
$ forge install foundry-rs/forge-std --no-git
$ forge build
```

### Deployment Process

1. Start a local devnet with Anvil:
```shell
$ anvil
```

2. Deploy the Context Config contract using the script:

Before deploying, you need to modify the script to use one of Anvil's default accounts as the owner:

```shell
$ cd context-config/script/ContextConfig.s.sol
```

Deploy the contract:

```shell
$ cd context-config
$ forge script script/ContextConfig.s.sol \
    --rpc-url http://localhost:8545 \
    --private-key <ONE_OF_ANVIL_PRIVATE_KEYS> \
    --broadcast
```

This will output the contract address which you need to use in next step.

3. Set the proxy code by calling the endpoint on the Context Config contract with the Context Proxy bytecode:
```shell
$ cd context-config
$ cast send <CONTEXT_CONFIG_CONTRACT_ADDRESS> \
    "setProxyCode(bytes)" \
    $(cd context-proxy && forge inspect ContextProxy bytecode) \
    --private-key <SAME_KEY_AS_IN_DEPLOYMENT> \
    --rpc-url http://localhost:8545
```


### Testing

Run tests for each contract in its respective directory:

```shell
# Test Context Config
$ cd context-config
$ forge test --via-ir --optimize --optimizer-runs 200

# Test Context Proxy
$ cd ../context-proxy
$ forge test --via-ir --optimize --optimizer-runs 200
```

You can also run tests with verbosity for more detailed output:

```shell
$ forge test --via-ir --optimize --optimizer-runs 200 -vvv
```

Or run a specific test function:

```shell
$ forge test --match-test testFunctionName
```

