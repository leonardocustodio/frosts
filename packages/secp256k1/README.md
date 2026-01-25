# @frost/secp256k1

FROST(secp256k1, SHA-256) - A Schnorr signature scheme over the secp256k1 curve that supports FROST threshold signatures.

This package is a re-export of the ciphersuite-generic [@frost/core](https://www.npmjs.com/package/@frost/core) package, parametrized with the secp256k1 curve. For more details, refer to [The ZF FROST Book](https://frost.zfnd.org/).

**Note:** This crate is not compatible with Bitcoin BIP-340 (Taproot) signatures. Use [@frost/secp256k1-tr](https://www.npmjs.com/package/@frost/secp256k1-tr) instead for Taproot compatibility.

## Features

- **Threshold Signatures**: Generate Schnorr signatures with a configurable threshold of signers
- **Distributed Key Generation (DKG)**: Generate keys without a trusted dealer
- **Trusted Dealer Key Generation**: Generate and split keys with a trusted dealer
- **Key Refresh**: Refresh key shares without changing the group public key
- **RFC 9591 Compliant**: Implements the FROST protocol as specified in RFC 9591 Section 6.5

## Ciphersuite Parameters

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 |
| Hash Function | SHA-256 |
| Scalar Size | 32 bytes |
| Element Size | 33 bytes (SEC1 compressed) |
| Signature Size | 65 bytes |
| Context String | `FROST-secp256k1-SHA256-v1` |

## Installation

```bash
bun add @frost/secp256k1
```

Or with npm:

```bash
npm install @frost/secp256k1
```

## Usage

### Key Generation with Trusted Dealer

Creating a key with a trusted dealer and splitting into shares:

```typescript
import * as frost from '@frost/secp256k1';

const maxSigners = 5;
const minSigners = 3;

// Generate key shares with a trusted dealer
const { shares, pubkeyPackage } = frost.keys.generateWithDealer(
  maxSigners,
  minSigners,
  frost.keys.IdentifierList.Default
);

// Verify and convert secret shares to key packages
const keyPackages = new Map<frost.Identifier, frost.keys.KeyPackage>();

for (const [identifier, secretShare] of shares) {
  const keyPackage = frost.keys.KeyPackage.tryFrom(secretShare);
  keyPackages.set(identifier, keyPackage);
}
```

### Round 1: Generating Nonces and Commitments

Each participant generates nonces and signing commitments:

```typescript
const noncesMap = new Map<frost.Identifier, frost.round1.SigningNonces>();
const commitmentsMap = new Map<frost.Identifier, frost.round1.SigningCommitments>();

// Each participant generates their nonces and commitments
for (let i = 1; i <= minSigners; i++) {
  const participantId = frost.Identifier.fromU16(i);
  const keyPackage = keyPackages.get(participantId)!;

  // Generate nonces and commitments
  const { nonces, commitments } = frost.round1.commit(keyPackage.signingShare());

  // Nonces are kept secret, commitments are shared
  noncesMap.set(participantId, nonces);
  commitmentsMap.set(participantId, commitments);
}
```

### Round 2: Signing

The coordinator creates a signing package and each participant signs:

```typescript
// Coordinator creates the signing package
const message = new TextEncoder().encode('message to sign');
const signingPackage = new frost.SigningPackage(commitmentsMap, message);

// Each participant generates their signature share
const signatureShares = new Map<frost.Identifier, frost.round2.SignatureShare>();

for (const [participantId, nonces] of noncesMap) {
  const keyPackage = keyPackages.get(participantId)!;

  // Generate signature share
  const signatureShare = frost.round2.sign(signingPackage, nonces, keyPackage);
  signatureShares.set(participantId, signatureShare);
}
```

### Aggregation and Verification

Aggregate signature shares and verify the final signature:

```typescript
// Aggregate all signature shares into the final signature
const groupSignature = frost.aggregate(signingPackage, signatureShares, pubkeyPackage);

// Verify the threshold signature with the group public key
const isValid = pubkeyPackage.verifyingKey().verify(message, groupSignature);
console.log('Signature valid:', isValid);
```

## API Reference

### Keys Module (`frost.keys`)

- `generateWithDealer(maxSigners, minSigners, identifiers)` - Generate keys with a trusted dealer
- `KeyPackage` - A participant's key package containing their signing share
- `PublicKeyPackage` - The group's public key package for verification
- `SecretShare` - A secret share from key generation
- `IdentifierList` - List of participant identifiers

### Round 1 Module (`frost.round1`)

- `commit(signingShare)` - Generate nonces and signing commitments
- `SigningNonces` - A participant's nonces (kept secret)
- `SigningCommitments` - A participant's commitments (shared publicly)

### Round 2 Module (`frost.round2`)

- `sign(signingPackage, nonces, keyPackage)` - Generate a signature share
- `SignatureShare` - A participant's signature share

### Aggregation

- `aggregate(signingPackage, signatureShares, pubkeyPackage)` - Aggregate shares into final signature
- `SigningPackage` - Package containing commitments and message for signing

### Verification

- `VerifyingKey.verify(message, signature)` - Verify a signature

## Bitcoin and Ethereum Compatibility

The secp256k1 curve is the same elliptic curve used by Bitcoin and Ethereum. However, there are important considerations:

- **Bitcoin BIP-340 (Taproot)**: This package produces standard Schnorr signatures and is NOT compatible with BIP-340 Taproot signatures. For Taproot compatibility, use [@frost/secp256k1-tr](https://www.npmjs.com/package/@frost/secp256k1-tr).
- **Ethereum**: Ethereum uses ECDSA signatures on secp256k1, not Schnorr signatures. This package cannot produce Ethereum-compatible transaction signatures directly.
- **Point Encoding**: This package uses SEC1 compressed point encoding (33 bytes) for public keys.

## Security Considerations

- **Nonce Security**: Nonces must be kept secret and never reused. Reusing nonces compromises the security of the signing key.
- **Authenticated Channels**: Commitments and signature shares should be transmitted over authenticated channels to prevent man-in-the-middle attacks.
- **Confidential Channels**: Key packages and secret shares must be transmitted over confidential and authenticated channels.
- **Threshold Selection**: Choose `minSigners` carefully - it represents the minimum number of honest participants required to sign.

## Documentation

For more details on FROST, refer to:

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/) - Section 6.5 for secp256k1 ciphersuite
- [The ZF FROST Book](https://frost.zfnd.org/)
- [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf) - secp256k1 curve specification

## License

MIT
