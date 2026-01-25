# FROST for TypeScript

[![Version](https://img.shields.io/badge/version-0.2.2-green)](https://github.com/leonardocustodio/bcts/releases)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)](https://www.typescriptlang.org/)
[![Monorepo](https://img.shields.io/badge/Monorepo-Turborepo-blueviolet)](https://turbo.build/)
[![Package Manager](https://img.shields.io/badge/Package%20Manager-Bun-FFD700)](https://bun.sh/)
[![Status](https://img.shields.io/badge/Status-Early%20Development-orange)](#-disclaimer)

> **Disclaimer:** This project is in early development stages and has **not been audited**. Use for testing purposes only.

## Overview

This is a port of the [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost). It implements [FROST (Flexible Round-Optimized Schnorr Threshold)](https://datatracker.ietf.org/doc/rfc9591/).

FROST is a threshold signature scheme that allows a group of participants to collaboratively generate Schnorr signatures without any single party holding the complete private key.

## Packages

| Package | Description |
|---------|-------------|
| `@frosts/core` | Core types and traits for FROST |
| `@frosts/rerandomized` | Re-randomized FROST variant |
| `@frosts/ed25519` | FROST with Ed25519 |
| `@frosts/ristretto255` | FROST with Ristretto255 |
| `@frosts/secp256k1` | FROST with secp256k1 |
| `@frosts/secp256k1-tr` | FROST with secp256k1 + Taproot |
| `@frosts/p256` | FROST with P-256 |
| `@frosts/ed448` | FROST with Ed448 |

## Documentation

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/)
- [The ZF FROST Book](https://frost.zfnd.org/)

## Credits

This implementation is based on the FROST library by the Zcash Foundation.

## License

MIT License - See [LICENSE](LICENSE) for details.
