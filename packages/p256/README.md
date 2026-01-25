# @frost/p256

FROST(P-256, SHA-256) - A Schnorr signature scheme over the NIST P-256 curve that supports FROST threshold signatures.

This package is a re-export of the ciphersuite-generic [@frost/core](https://www.npmjs.com/package/@frost/core) package, parametrized with the P-256 curve. For more details, refer to [The ZF FROST Book](https://frost.zfnd.org/).

## Features

- **Threshold Signatures**: Generate Schnorr signatures with a configurable threshold of signers
- **Distributed Key Generation (DKG)**: Generate keys without a trusted dealer
- **Trusted Dealer Key Generation**: Generate and split keys with a trusted dealer
- **Key Refresh**: Refresh key shares without changing the group public key
- **RFC 9591 Compliant**: Implements the FROST protocol as specified in RFC 9591 Section 6.4

## Ciphersuite Parameters

| Parameter | Value |
|-----------|-------|
| Curve | P-256 (secp256r1, prime256v1) |
| Hash Function | SHA-256 |
| Scalar Size | 32 bytes |
| Element Size | 33 bytes (SEC1 compressed) |
| Signature Size | 65 bytes |
| Context String | `FROST-P256-SHA256-v1` |

## Installation

```bash
bun add @frost/p256
```

Or with npm:

```bash
npm install @frost/p256
```

## Usage

### Key Generation with Trusted Dealer

Creating a key with a trusted dealer and splitting into shares:

```typescript
import * as frost from '@frost/p256';

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

## P-256 Curve Details

The P-256 curve (also known as secp256r1 or prime256v1) is a NIST-standardized elliptic curve widely used in:

- **TLS/SSL**: Standard curve for ECDHE key exchange
- **WebAuthn/FIDO2**: Default curve for passkeys and hardware security keys
- **Government Standards**: Required by NIST SP 800-186 and FIPS 186-5
- **Smart Cards**: Commonly supported in hardware security modules

### Curve Parameters

- **Field Prime**: 2^256 - 2^224 + 2^192 + 2^96 - 1
- **Order**: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
- **Cofactor**: 1
- **Security Level**: 128 bits

### Point Encoding

This package uses SEC1 compressed point encoding:
- 33 bytes total
- First byte: 0x02 (even y) or 0x03 (odd y)
- Remaining 32 bytes: x-coordinate

## Security Considerations

- **Nonce Security**: Nonces must be kept secret and never reused. Reusing nonces compromises the security of the signing key.
- **Authenticated Channels**: Commitments and signature shares should be transmitted over authenticated channels to prevent man-in-the-middle attacks.
- **Confidential Channels**: Key packages and secret shares must be transmitted over confidential and authenticated channels.
- **Threshold Selection**: Choose `minSigners` carefully - it represents the minimum number of honest participants required to sign.

## Documentation

For more details on FROST, refer to:

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/) - Section 6.4 for P-256 ciphersuite
- [The ZF FROST Book](https://frost.zfnd.org/)
- [NIST SP 800-186: Recommendations for Discrete Logarithm-based Cryptography](https://csrc.nist.gov/pubs/sp/800/186/final) - P-256 curve specification
- [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)

## License

MIT
