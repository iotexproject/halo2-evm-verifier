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

### 4. Aggregator proof

## Solidity verifier

```solidity
pragma solidity ^0.8.19;

contract Verifier {
    address yulVerifier;

    constructor(address _yulVerifier) {
        yulVerifier = _yulVerifier;
    }

    function verify(bytes calldata input) external view returns (bool) {
        (bool success, ) = yulVerifier.staticcall(input);
        return success;
    }
}
```