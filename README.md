# frosTS - FROST for TypeScript

[![Version](https://img.shields.io/badge/version-0.2.2-green)](https://github.com/leonardocustodio/bcts/releases)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)](https://www.typescriptlang.org/)
[![Monorepo](https://img.shields.io/badge/Monorepo-Turborepo-blueviolet)](https://turbo.build/)
[![Package Manager](https://img.shields.io/badge/Package%20Manager-Bun-FFD700)](https://bun.sh/)
[![RFC 9591](https://img.shields.io/badge/RFC-9591-informational)](https://datatracker.ietf.org/doc/rfc9591/)
[![Status](https://img.shields.io/badge/Status-Early%20Development-orange)](#-disclaimer)

🧊 **Community Implementation:** This is a TypeScript port of the [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) library. It implements [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/).

> ⚠️ **Disclaimer:** This project is in early development stages and has **not been audited**. Use for testing and development purposes only. For production use, we recommend the audited [Rust](https://github.com/ZcashFoundation/frost) or [Go](https://github.com/bytemare/frost) implementations.

## Overview

FROST (Flexible Round-Optimized Schnorr Threshold) is a threshold signature scheme that allows a group of participants to collaboratively generate Schnorr signatures without any single party holding the complete private key. Key features include:

- **Threshold Security:** t-of-n signing where any t participants can sign, but fewer than t learn nothing
- **Two-Round Protocol:** Efficient signing with only two communication rounds
- **Distributed Key Generation:** Built-in DKG protocol for decentralized key setup
- **Multiple Curves:** Support for Ed25519, Ed448, P-256, secp256k1, Ristretto255, and Taproot


## 📚 Resources

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/) - The official IETF specification
- [The ZF FROST Book](https://frost.zfnd.org/) - Comprehensive documentation from the Zcash Foundation
- [FROST Paper](https://eprint.iacr.org/2020/852) - Original academic paper by Chelsea Komlo and Ian Goldberg
- [threshold.network](https://threshold.network/) - Real-world threshold cryptography applications
- [FROST Demo](https://frost.zfnd.org/tutorial.html) - Interactive tutorial

## 📦 Packages

| Package | Description | Curve |
|---------|-------------|-------|
| [**@frosts/core**](packages/core) | Core types, traits, and generic FROST protocol implementation. Provides the foundation for all ciphersuite packages. | N/A |
| [**@frosts/ed25519**](packages/ed25519) | FROST with Ed25519-SHA512. The most widely used curve for signatures, compatible with SSH keys and many blockchain protocols. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-ed25519) | Ed25519 |
| [**@frosts/ed448**](packages/ed448) | FROST with Ed448-SHAKE256. Higher security margin (224-bit) for applications requiring stronger guarantees. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-ed448) | Ed448 |
| [**@frosts/p256**](packages/p256) | FROST with P-256-SHA256. NIST standard curve, widely supported in hardware security modules and enterprise systems. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-p256) | P-256 |
| [**@frosts/ristretto255**](packages/ristretto255) | FROST with Ristretto255-SHA512. Prime-order group built on Curve25519, eliminates cofactor issues. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-ristretto255) | Ristretto255 |
| [**@frosts/secp256k1**](packages/secp256k1) | FROST with secp256k1-SHA256. Bitcoin and Ethereum compatible curve for blockchain applications. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1) | secp256k1 |
| [**@frosts/secp256k1-tr**](packages/secp256k1-tr) | FROST with secp256k1 + Taproot (BIP-340). Bitcoin Taproot compatible with x-only public keys. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1-tr) | secp256k1 |
| [**@frosts/rerandomized**](packages/rerandomized) | Re-randomized FROST variant with unlinkable signatures. Signatures cannot be correlated across signing sessions. [🦀 Rust](https://github.com/ZcashFoundation/frost/tree/main/frost-rerandomized) | Any |

## 👥 Credits

This TypeScript implementation is a port of the excellent work by the [Zcash Foundation](https://zfnd.org/) FROST team. The original FROST paper was authored by Chelsea Komlo and Ian Goldberg.

## 🤝 Contributing

Contributions are welcome! The **best way to contribute** to this library is to provide a **security audit** - as a cryptographic library, independent review is invaluable for production readiness.

### Other Ways to Contribute

- 🐛 **Bug Reports:** Found an issue? Please open a GitHub issue with reproduction steps
- 📝 **Documentation:** Help improve docs, examples, and tutorials
- 🧪 **Testing:** Add test cases, especially edge cases and test vectors
- 🔧 **Code:** Submit PRs for bug fixes or new features
- 🌍 **Translations:** Help translate documentation

For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
