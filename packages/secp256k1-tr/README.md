# @frost/secp256k1-tr

> **Disclaimer:** This project is in early development stages and has **not been audited**. Use for testing purposes only.

FROST(secp256k1, SHA-256) Taproot - A **BIP-340 compatible** Schnorr signature scheme over the secp256k1 curve that supports FROST threshold signatures.

This package is a re-export of the ciphersuite-generic [@frost/core](https://www.npmjs.com/package/@frost/core) package, parametrized with the secp256k1 curve and modified for **Bitcoin Taproot** compatibility. For more details, refer to [The ZF FROST Book](https://frost.zfnd.org/).
