Halo2 EVM Verifier
==================

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

## Usage

### Builder

```
docker build -t wasm-builder .
```

### Build

```
// bundler, nodejs, web, no-modules, default is bundler
wasm-pack build --target nodejs --out-name prover.wasm --out-dir pkg

// docker
docker run --rm -v `pwd`:/src -w /src wasm-builder cargo build --target wasm32-wasi
```

### Run

TODO
