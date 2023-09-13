Hello halo2
===========

## Halo2

### Columns

### How to write a circuit in halo2

1. Define a Config struct that holds the columns used in the circuit
2. Define a Chip struct that configures the constraints in the circuit and provides assignment functions
3. Define a circuit struct that implements the Circuit trait and
4. Instantiate a circuit instance and feed it into the prover

## Steps

### 1. Write circuits

### 2. Generate Onchain verifier

> Requirement: install `solc`

### 3. WASM prover (WIP)

### 4. Aggregator proof (TODO)

## Solidity verifier

```solidity
pragma solidity ^0.8.19;

contract Verifier {
    function verify(address yulVerifier, bytes calldata input) external view returns (bool) {
        (bool success, ) = yulVerifier.staticcall(input);
        return success;
    }
}
```

## Development

### Generate contract and calldata (TODO: refactor to cli)

```
cargo run src/main.rs
```

### IoTeX testnet deployment

The universal solidity contract address: `0xF6577c31eaE769aE303e6D38070fE88A3e8830c9`
The simple yul verifier contract address: `0x9c96BD9C822cFb56F5324d29e45d36edf36aD5C3`
