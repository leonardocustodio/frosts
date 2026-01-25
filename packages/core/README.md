# @frost/core

Core types and traits for FROST (Flexible Round-Optimized Schnorr Threshold) signatures in TypeScript.

This package implements the base traits and types that enable [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/) generically for different ciphersuites.

## Overview

FROST is a threshold signature scheme that allows a group of participants to collaboratively generate Schnorr signatures. The core package provides:

- **Ciphersuite trait**: Abstract interface for different elliptic curve implementations
- **Field trait**: Operations on scalar field elements
- **Group trait**: Operations on group elements (elliptic curve points)
- **Identifier**: Participant identifiers for threshold signing
- **Signature**: Schnorr signature representation
- **Error types**: Comprehensive error handling for FROST operations

## Installation

```bash
bun add @frost/core
```

## Usage

This package provides the foundational types used by ciphersuite-specific implementations. You typically won't use this package directly, but instead use a ciphersuite package like:

- `@frost/ed25519` - FROST with Ed25519
- `@frost/ristretto255` - FROST with Ristretto255
- `@frost/secp256k1` - FROST with secp256k1
- `@frost/p256` - FROST with P-256

## Documentation

For more details on FROST, refer to:

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/)
- [The ZF FROST Book](https://frost.zfnd.org/)

## License

BSD-2-Clause-Patent
