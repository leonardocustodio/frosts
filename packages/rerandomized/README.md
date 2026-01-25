# @frost/rerandomized

Re-randomized FROST (Flexible Round-Optimized Schnorr Threshold) signatures for threshold cryptography with re-randomizable keys.

This package implements [Re-Randomized FROST](https://eprint.iacr.org/2024/436), which allows creating signatures using FROST under re-randomized keys.

## Overview

Re-randomized FROST extends the standard FROST protocol to support key re-randomization, enabling privacy-preserving applications where the public key and signatures can be randomized after key generation.

## Installation

```bash
bun add @frost/rerandomized
```

## Usage

Re-randomized signing follows a modified flow:

1. **Round 1** - Same as regular FROST (generate nonces and commitments)
2. **Coordinator** - Call `RandomizedParams.newFromCommitments()` and send the randomizer seed to all participants
3. **Participants** - Call `RandomizedParams.regenerateFromSeedAndCommitments()` and use `signWithRandomizerSeed()`
4. **Aggregation** - Call `aggregate()` with the randomized parameters

```typescript
import {
  RandomizedParams,
  signWithRandomizerSeed,
  aggregate,
} from "@frost/rerandomized";

// Coordinator generates randomized params
const [randomizedParams, randomizerSeed] = RandomizedParams.newFromCommitments(
  publicKeys.verifyingKey(),
  signingPackage.signingCommitments(),
  rng
);

// Each participant signs with the randomizer seed
const signatureShare = signWithRandomizerSeed(
  signingPackage,
  nonces,
  keyPackage,
  randomizerSeed
);

// Coordinator aggregates
const signature = aggregate(
  signingPackage,
  signatureShares,
  publicKeys,
  randomizedParams
);

// Verify with the randomized verifying key
randomizedParams.randomizedVerifyingKey().verify(message, signature);
```

## API

### Types

- `RandomizedCiphersuite` - A ciphersuite that supports re-randomization
- `Randomizer<C>` - A random scalar used to randomize keys
- `RandomizedParams<C>` - Parameters for a randomized signing session

### Functions

- `signWithRandomizerSeed()` - Sign with a randomizer seed (recommended)
- `sign()` - Sign with a randomizer (deprecated)
- `aggregate()` - Aggregate signature shares with randomization

## Documentation

- [RFC 9591: Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/rfc9591/)
- [Re-Randomized FROST Paper](https://eprint.iacr.org/2024/436)
- [The ZF FROST Book](https://frost.zfnd.org/)

## License

MIT
