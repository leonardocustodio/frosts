# @frost/secp256k1-tr

FROST(secp256k1, SHA-256) Taproot - A **BIP-340 compatible** Schnorr signature scheme over the secp256k1 curve that supports FROST threshold signatures.

This package is a re-export of the ciphersuite-generic [@frost/core](https://www.npmjs.com/package/@frost/core) package, parametrized with the secp256k1 curve and modified for **Bitcoin Taproot** compatibility. For more details, refer to [The ZF FROST Book](https://frost.zfnd.org/).

**Note:** This crate IS compatible with Bitcoin BIP-340 (Taproot) signatures. For standard (non-Taproot) FROST signatures, use [@frost/secp256k1](https://www.npmjs.com/package/@frost/secp256k1) instead.

## Features

- **Threshold Signatures**: Generate Schnorr signatures with a configurable threshold of signers
- **Distributed Key Generation (DKG)**: Generate keys without a trusted dealer
- **Trusted Dealer Key Generation**: Generate and split keys with a trusted dealer
- **Key Refresh**: Refresh key shares without changing the group public key
- **BIP-340 Compatible**: 64-byte signatures with x-only R point encoding
- **BIP-341 Taproot Tweaking**: Support for Taproot key tweaking with merkle roots
- **RFC 9591 Compliant**: Implements the FROST protocol as specified in RFC 9591

## Ciphersuite Parameters

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 |
| Hash Function | SHA-256 |
| Scalar Size | 32 bytes |
| Element Size | 33 bytes (SEC1 compressed) |
| Signature Size | **64 bytes** (BIP-340 format) |
| Context String | `FROST-secp256k1-SHA256-TR-v1` |

## Bitcoin Taproot Compatibility

This package is specifically designed for **Bitcoin Taproot (BIP-341)** compatibility:

- **BIP-340 Schnorr Signatures**: Uses 64-byte compact signature format with x-only R point encoding
- **X-Only Public Keys**: Public keys use only the X coordinate, with even Y coordinate assumed
- **Taproot Tweaking**: Full support for BIP-341 taproot key tweaking with optional merkle roots
- **Tagged Hashing**: Uses BIP-340 tagged hashing (`BIP0340/challenge`) for challenge computation

### Key Differences from Standard FROST

| Feature | @frost/secp256k1 | @frost/secp256k1-tr |
|---------|------------------|---------------------|
| Signature Size | 65 bytes | 64 bytes |
| R Point | Full point | X-only (even Y) |
| Challenge Hash | FROST standard | BIP-340 tagged hash |
| Context String | `FROST-secp256k1-SHA256-v1` | `FROST-secp256k1-SHA256-TR-v1` |
| Taproot Tweaking | No | Yes |

## Installation

```bash
bun add @frost/secp256k1-tr
```

Or with npm:

```bash
npm install @frost/secp256k1-tr
```

## Usage

### Key Generation with Trusted Dealer

Creating a key with a trusted dealer and splitting into shares:

```typescript
import * as frost from '@frost/secp256k1-tr';

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

### Round 2: Signing (Standard)

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

### Round 2: Signing with Taproot Tweak

For Taproot addresses with script trees, use the tweaked signing functions:

```typescript
// Optional: Merkle root of the tapscript tree (32 bytes)
// Use undefined for key-path-only spending (unspendable script path)
const merkleRoot = undefined; // or: new Uint8Array(32)

// Each participant generates their signature share with tweak
const signatureShares = new Map<frost.Identifier, frost.round2.SignatureShare>();

for (const [participantId, nonces] of noncesMap) {
  const keyPackage = keyPackages.get(participantId)!;

  // Generate signature share with Taproot tweak
  const signatureShare = frost.round2.signWithTweak(
    signingPackage,
    nonces,
    keyPackage,
    merkleRoot
  );
  signatureShares.set(participantId, signatureShare);
}
```

### Aggregation and Verification

Aggregate signature shares and verify the final signature:

```typescript
// Aggregate all signature shares into the final signature (standard)
const groupSignature = frost.aggregate(signingPackage, signatureShares, pubkeyPackage);

// OR: Aggregate with Taproot tweak (must match signing tweak)
const groupSignature = frost.aggregateWithTweak(
  signingPackage,
  signatureShares,
  pubkeyPackage,
  merkleRoot
);

// Verify the threshold signature with the group public key
const isValid = pubkeyPackage.verifyingKey().verify(message, groupSignature);
console.log('Signature valid:', isValid);
```

## EvenY Trait

BIP-340 requires public keys to have an even Y coordinate (since only the X coordinate is encoded). The `EvenY` trait provides methods to ensure this:

```typescript
import { keys } from '@frost/secp256k1-tr';

// Check if a key has an even Y coordinate
const hasEvenY = pubkeyPackage.hasEvenY();

// Convert to ensure even Y coordinate (negates key if needed)
const evenYPackage = pubkeyPackage.intoEvenY();
```

Types implementing `EvenY`:
- `PublicKeyPackage`
- `KeyPackage`
- `VerifyingKey`
- `SigningKey`
- `Signature`
- `GroupCommitment`

## Tweak Trait

The `Tweak` trait provides BIP-341 Taproot key tweaking:

```typescript
import { keys } from '@frost/secp256k1-tr';

// Tweak with no merkle root (key-path-only, unspendable script path)
const tweakedPubkey = pubkeyPackage.tweak(undefined);

// Tweak with merkle root (for addresses with tapscripts)
const merkleRoot = new Uint8Array(32); // Your tapscript merkle root
const tweakedPubkey = pubkeyPackage.tweak(merkleRoot);
```

Types implementing `Tweak`:
- `PublicKeyPackage`
- `KeyPackage`

## API Reference

### Keys Module (`frost.keys`)

- `generateWithDealer(maxSigners, minSigners, identifiers)` - Generate keys with a trusted dealer
- `split(secret, maxSigners, minSigners, identifiers)` - Split an existing key into shares
- `reconstruct(secretShares)` - Reconstruct the original key from shares
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
- `signWithTweak(signingPackage, nonces, keyPackage, merkleRoot)` - Generate a signature share with Taproot tweak
- `SignatureShare` - A participant's signature share

### Aggregation

- `aggregate(signingPackage, signatureShares, pubkeyPackage)` - Aggregate shares into final signature
- `aggregateWithTweak(signingPackage, signatureShares, pubkeyPackage, merkleRoot)` - Aggregate with Taproot tweak
- `SigningPackage` - Package containing commitments and message for signing

### Verification

- `VerifyingKey.verify(message, signature)` - Verify a signature

### Traits

- `EvenY.hasEvenY()` - Check if the public key has an even Y coordinate
- `EvenY.intoEvenY()` - Convert to ensure even Y coordinate
- `Tweak.tweak(merkleRoot)` - Apply BIP-341 Taproot tweak

## Security Considerations

- **Nonce Security**: Nonces must be kept secret and never reused. Reusing nonces compromises the security of the signing key.
- **Authenticated Channels**: Commitments and signature shares should be transmitted over authenticated channels to prevent man-in-the-middle attacks.
- **Confidential Channels**: Key packages and secret shares must be transmitted over confidential and authenticated channels.
- **Threshold Selection**: Choose `minSigners` carefully - it represents the minimum number of honest participants required to sign.
- **Tweak Consistency**: When using Taproot tweaks, ensure all signers and the aggregator use the same merkle root.
- **DKG Output**: After DKG, keys are automatically tweaked with an unspendable script path to prevent rogue tapscript injection.

## Documentation

For more details on FROST and Bitcoin Taproot, refer to:

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/)
- [The ZF FROST Book](https://frost.zfnd.org/)
- [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341: Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf) - secp256k1 curve specification

## License

MIT
