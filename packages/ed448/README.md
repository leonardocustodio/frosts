# @frost/ed448

FROST(Ed448, SHAKE256) - A Schnorr signature scheme over the Ed448 curve that supports FROST threshold signatures.

This package is a re-export of the ciphersuite-generic [@frost/core](https://www.npmjs.com/package/@frost/core) package, parametrized with the Ed448 curve. For more details, refer to [The ZF FROST Book](https://frost.zfnd.org/).

## Features

- **Threshold Signatures**: Generate Schnorr signatures with a configurable threshold of signers
- **Distributed Key Generation (DKG)**: Generate keys without a trusted dealer
- **Trusted Dealer Key Generation**: Generate and split keys with a trusted dealer
- **Key Refresh**: Refresh key shares without changing the group public key
- **Rerandomization**: Support for rerandomized FROST signatures
- **RFC 9591 Compliant**: Implements the FROST protocol as specified in RFC 9591

## Installation

```bash
bun add @frost/ed448
```

Or with npm:

```bash
npm install @frost/ed448
```

## Usage

### Key Generation with Trusted Dealer

Creating a key with a trusted dealer and splitting into shares:

```typescript
import * as frost from '@frost/ed448';

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

## Documentation

For more details on FROST, refer to:

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/)
- [The ZF FROST Book](https://frost.zfnd.org/)

## License

MIT
