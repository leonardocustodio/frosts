# FROST Core - Rust Test Analysis for TypeScript Port

## Executive Summary

The TypeScript `@frosts/core` package has **69 skipped tests (100% skip rate)**. This analysis documents what needs to be implemented based on the Rust `frost-core` test files.

The TypeScript implementation already has the **core structures in place** (batch verification, VSS commitments, coefficient commitments, repairable threshold scheme, and refresh). The tests are skipped because they need ciphersuite-specific implementations to run.

---

## Test File Analysis

### 1. batch.rs - Batch Verification Tests

**Location:** `/frost-rust/frost-core/src/tests/batch.rs`

**Functions Tested:**
- `batch_verify()` - Verifies multiple signatures in a batch
- Single signature verification fallback
- Empty batch validation

**Test Cases:**
1. `check_batch_verify<C>()` - Creates batch of valid signatures and verifies them together
2. `check_bad_batch_verify<C>()` - Creates 32 signatures with 1 invalid (at index 4), verifies batch fails and individual checks identify the bad one
3. Empty batch fails validation (NCC audit finding)

**TypeScript Status:**
- `Item` class: IMPLEMENTED in `src/batch.ts`
- `Verifier` class: IMPLEMENTED in `src/batch.ts`
- Tests: SKIPPED - Need working `SigningKey.sign()` and ciphersuite

**Dependencies to Enable Tests:**
```typescript
// Need these to work:
- SigningKey.new(rng)
- SigningKey.sign(rng, msg)
- VerifyingKey.from(SigningKey)
- Ciphersuite.challenge(R, vk, msg)
- Ciphersuite.preVerify(msg, sig, vk)
```

---

### 2. vss_commitment.rs - VSS Commitment Tests

**Location:** `/frost-rust/frost-core/src/tests/vss_commitment.rs`

**Functions Tested:**
- `VerifiableSecretSharingCommitment.serialize()`
- `VerifiableSecretSharingCommitment.serialize_whole()`
- `VerifiableSecretSharingCommitment.deserialize()`
- `VerifiableSecretSharingCommitment.deserialize_whole()`
- `PublicKeyPackage.from_commitment()`

**Test Cases:**
1. `check_serialize_vss_commitment<C>()` - Serialize 3 random elements as VSS commitment
2. `check_serialize_whole_vss_commitment<C>()` - Serialize as single concatenated byte vector
3. `check_deserialize_vss_commitment<C>()` - Roundtrip deserialization
4. `check_deserialize_whole_vss_commitment<C>()` - Deserialize from concatenated bytes
5. `check_deserialize_vss_commitment_error<C>()` - Invalid element fails deserialization
6. `check_deserialize_whole_vss_commitment_error<C>()` - Invalid element in concatenated form
7. `check_deserialize_whole_vss_commitment_error_length<C>()` - Wrong length fails with InvalidCoefficient
8. `check_compute_public_key_package<C>()` - Compute from commitment and verify matches dealer

**TypeScript Status:**
- `VerifiableSecretSharingCommitment` class: IMPLEMENTED in `src/keys.ts`
- `serialize()`: IMPLEMENTED
- `serializeWhole()`: IMPLEMENTED
- `deserialize()`: IMPLEMENTED
- `deserializeWhole()`: IMPLEMENTED
- `PublicKeyPackage.fromCommitment()`: IMPLEMENTED
- Tests: SKIPPED - Need ciphersuite and `generateElement()` helper

**Test Helpers Needed:**
```typescript
// From helpers.rs
function generateElement<C>(ciphersuite: C, rng: CryptoRng): C["Element"] {
  const scalar = ciphersuite.scalarRandom(rng);
  return ciphersuite.elementMul(ciphersuite.generator(), scalar);
}
```

**Test Vectors Needed:**
- `commitment_helpers` JSON with `invalid_element` hex string for error tests

---

### 3. coefficient_commitment.rs - Coefficient Commitment Tests

**Location:** `/frost-rust/frost-core/src/tests/coefficient_commitment.rs`

**Functions Tested:**
- `CoefficientCommitment.serialize()`
- `CoefficientCommitment.deserialize()`
- `CoefficientCommitment.value()`

**Test Cases:**
1. `check_serialization_of_coefficient_commitment<C>()` - Serialize random element
2. `check_create_coefficient_commitment<C>()` - Create from serialized element
3. `check_create_coefficient_commitment_error<C>()` - Invalid element fails
4. `check_get_value_of_coefficient_commitment<C>()` - Retrieve element from commitment

**TypeScript Status:**
- `CoefficientCommitment` class: IMPLEMENTED in `src/keys.ts`
- `serialize()`: IMPLEMENTED
- `deserialize()`: IMPLEMENTED
- `value()`: IMPLEMENTED
- Tests: SKIPPED - Need ciphersuite

**Test Vectors Needed:**
- `commitment_helpers` JSON with `invalid_element` hex string

---

### 4. repairable.rs - Repairable Threshold Scheme Tests

**Location:** `/frost-rust/frost-core/src/tests/repairable.rs`

**Functions Tested:**
- `repair_share_step_1()` - Generate delta values for helpers
- `repair_share_step_2()` - Sum deltas to produce sigma
- `repair_share_step_3()` - Recover share from sigmas

**Test Cases:**
1. `check_rts<C>()` - Full repair flow:
   - Generate 5 shares (threshold 3)
   - Signer 2 loses share
   - Helpers 1, 4, 5 generate deltas
   - Each helper computes sigma from received deltas
   - Participant 2 recovers share from sigmas
   - Verify recovered share matches original

2. `check_repair_share_step_1<C>()` - Verify deltas sum correctly:
   - Sum of deltas equals `lagrange_coeff * signing_share`

3. `check_repair_share_step_2<C>()` - Sum random scalars (test vectors)

4. `check_repair_share_step_3<C>()` - Recover from test vector sigmas

5. `check_repair_share_step_1_fails_with_invalid_min_signers<C>()` - Error with too few helpers

**TypeScript Status:**
- `Delta` class: IMPLEMENTED in `src/keys/repairable.ts`
- `Sigma` class: IMPLEMENTED in `src/keys/repairable.ts`
- `repairShareStep1()`: IMPLEMENTED
- `repairShareStep2()`: IMPLEMENTED
- `repairShareStep3()`: IMPLEMENTED
- Tests: SKIPPED - Need `generateWithDealer()` and ciphersuite

**Test Vectors Needed:**
```typescript
interface RepairShareHelpers {
  scalar_generation: {
    random_scalar_1: string;  // hex
    random_scalar_2: string;
    random_scalar_3: string;
    random_scalar_sum: string;  // sum of above
  };
  sigma_generation: {
    sigma_1: string;
    sigma_2: string;
    sigma_3: string;
    sigma_4: string;
    sigma_sum: string;  // sum of above
  };
}
```

---

### 5. refresh.rs - Share Refresh Tests

**Location:** `/frost-rust/frost-core/src/tests/refresh.rs`

**Functions Tested:**
- `compute_refreshing_shares()` - Dealer generates zero shares
- `refresh_share()` - Participant combines shares
- `refresh_dkg_part1()` - DKG round 1 for refresh
- `refresh_dkg_part2()` - DKG round 2 for refresh
- `refresh_dkg_shares()` - Final share computation

**Test Cases:**
1. `check_refresh_shares_with_dealer<C>()` - Full dealer refresh:
   - Generate 5 shares (threshold 3)
   - Remove signer 2, keep 1, 3, 4, 5
   - Dealer generates zero shares
   - Each participant refreshes
   - Verify signing works with new shares

2. `check_refresh_shares_with_dealer_fails_with_invalid_signers<C>()` - Error cases:
   - Duplicate identifiers
   - Unknown identifier
   - Too few signers

3. `check_refresh_shares_with_dealer_fails_with_invalid_public_key_package<C>()` - Unknown identifier error

4. `check_refresh_shares_with_dealer_serialisation<C>()` - Serialization roundtrip

5. `check_refresh_shares_with_dkg<C>()` - Full DKG refresh flow

6. `check_refresh_shares_with_dkg_smaller_threshold<C>()` - InvalidMinSigners error

**TypeScript Status:**
- `computeRefreshingShares()`: IMPLEMENTED in `src/keys/refresh.ts`
- `refreshShare()`: IMPLEMENTED
- `refreshDkgPart1()`: IMPLEMENTED
- `refreshDkgPart2()`: IMPLEMENTED
- `refreshDkgShares()`: IMPLEMENTED
- Tests: SKIPPED - Need `generateWithDealer()` and signing functions

---

### 6. ciphersuite_generic.rs - Core Protocol Tests

**Location:** `/frost-rust/frost-core/src/tests/ciphersuite_generic.rs`

**This is the most comprehensive test file covering:**

**Key Generation Tests:**
- `check_zero_key_fails<C>()` - Zero scalar fails SigningKey creation
- `check_share_generation<C>()` - Generate and verify shares
- `check_share_generation_fails_with_invalid_signers<C>()` - Error cases

**Reconstruction Tests:**
- Reconstruct secret from shares
- Empty shares fails
- Too few shares fails
- Duplicate identifiers fails

**Signing Tests:**
- `check_sign_with_dealer<C>()` - Complete signing flow with trusted dealer
- `check_sign_with_dkg<C>()` - Complete signing flow with DKG
- `check_sign_with_dealer_and_identifiers<C>()` - Custom identifiers

**DKG Error Tests:**
- `check_part1_fails_with_invalid_signers<C>()` - Invalid min/max signers
- DKG part2 with corrupted proof of knowledge
- DKG part3 with different participant sets
- DKG part3 with corrupted share (culprit identification)

**Signing Error Tests:**
- Incorrect number of commitments
- Missing identifier
- Incorrect commitment (nonces don't match)

**Aggregation Error Tests:**
- Corrupted share (cheater detection)
- Invalid share identifier (NCC audit finding)

**Identifier Tests:**
- `check_identifier_derivation<C>()` - Consistent derivation
- Custom identifiers work
- Duplicate identifiers fail
- Wrong number of identifiers fail

**Signature Share Verification:**
- Valid shares verify
- Corrupted shares fail

---

### 7. vectors.rs - Test Vector Validation

**Location:** `/frost-rust/frost-core/src/tests/vectors.rs`

**Tests signing protocol against RFC test vectors:**

1. Parse test vectors from JSON
2. Key generation matches vectors
3. Nonce generation from randomness matches
4. Binding factors match
5. Signature shares match
6. Final signature matches

**TestVectors Structure:**
```typescript
interface TestVectors {
  secretKey: SigningKey;
  verifyingKey: VerifyingKey;
  keyPackages: Map<Identifier, KeyPackage>;
  messageBytes: Uint8Array;
  sharePolynomialCoefficients: Scalar[];
  hidingNoncesRandomness: Map<Identifier, Uint8Array>;
  bindingNoncesRandomness: Map<Identifier, Uint8Array>;
  signerNonces: Map<Identifier, SigningNonces>;
  signerCommitments: Map<Identifier, SigningCommitments>;
  bindingFactorInputs: Map<Identifier, Uint8Array>;
  bindingFactors: Map<Identifier, BindingFactor>;
  signatureShares: Map<Identifier, SignatureShare>;
  signatureBytes: Uint8Array;
}
```

---

### 8. vectors_dkg.rs - DKG Test Vector Validation

**Location:** `/frost-rust/frost-core/src/tests/vectors_dkg.rs`

**Tests DKG protocol against test vectors:**

1. Parse DKG test vectors from JSON
2. Generate secret polynomial matches vectors
3. Round 1 packages match
4. Round 2 packages match
5. Final key packages match
6. Public key package matches

---

### 9. proptests.rs - Property-Based Tests

**Location:** `/frost-rust/frost-core/src/tests/proptests.rs`

**SignatureCase structure for property testing:**

```rust
struct SignatureCase {
    msg: Vec<u8>,
    sig: Signature,
    vk: VerifyingKey,
    invalid_vk: VerifyingKey,
    is_valid: bool,
}

enum Tweak {
    None,           // Unchanged, should verify
    ChangeMessage,  // Invalidates signature
    ChangePubkey,   // Invalidates signature
}
```

---

### 10. helpers.rs - Test Helpers

**Location:** `/frost-rust/frost-core/src/tests/helpers.rs`

**Shared test utilities:**

```rust
fn generate_element<C: Ciphersuite>(rng: &mut impl RngCore + CryptoRng) -> Element<C> {
    // Multiply generator by random scalar
    C::Group::generator() * C::random_nonzero_scalar(rng)
}
```

**TypeScript Implementation:** Already in `tests/helpers.ts`

---

## Implementation Priority

### High Priority (Core Functionality)

1. **Ciphersuite Implementation Required** - All tests depend on a concrete ciphersuite
   - Need at least one working ciphersuite (e.g., Ristretto255)
   - Ciphersuite must implement all required methods

2. **Test Vectors** - Load test vector JSON files for each ciphersuite

3. **SigningKey/VerifyingKey** - Complete signing functionality:
   - `SigningKey.new(rng)`
   - `SigningKey.sign(rng, msg)`
   - `VerifyingKey.verify(msg, sig)`

### Medium Priority (Enable More Tests)

4. **Full DKG Flow** - Verify DKG works end-to-end

5. **Aggregation** - `aggregate()` function with cheater detection

6. **Test Helper Functions** - Port remaining helpers from Rust

### Lower Priority (Advanced Features)

7. **Property-Based Tests** - Consider using a property testing library

8. **Serialization Tests** - Complete serialization roundtrip tests

---

## Test Dependencies Summary

| Test File | Required Dependencies |
|-----------|----------------------|
| batch.rs | SigningKey, VerifyingKey, Signature, Challenge, preVerify |
| vss_commitment.rs | generateElement, CoefficientCommitment, VSS classes |
| coefficient_commitment.rs | generateElement, CoefficientCommitment |
| repairable.rs | generateWithDealer, KeyPackage, SigningShare |
| refresh.rs | generateWithDealer, KeyPackage, DKG functions, signing |
| ciphersuite_generic.rs | ALL core functionality |
| vectors.rs | Test vector JSON files, full signing protocol |
| vectors_dkg.rs | Test vector JSON files, full DKG protocol |
| proptests.rs | SigningKey, VerifyingKey, Signature |

---

## Recommendations

1. **Start with a concrete ciphersuite** - Implement and test `@frosts/ristretto255` first

2. **Enable tests incrementally** - Unskip tests as functionality becomes available

3. **Use test vectors from Rust** - Copy JSON test vector files from Rust implementation

4. **Match API exactly** - Ensure TypeScript API matches Rust for test portability

5. **Add integration tests** - After unit tests pass, add full protocol integration tests

---

## Files to Create/Update

### New Test Vector Files Needed
- `tests/vectors/ristretto255.json` - Signing test vectors
- `tests/vectors/ristretto255-dkg.json` - DKG test vectors
- `tests/vectors/commitment-helpers.json` - Invalid element for error tests
- `tests/vectors/repair-share-helpers.json` - Scalar test vectors for repairable

### TypeScript Files to Update
- `src/signing_key.ts` - Add `sign()` method
- `src/verifying_key.ts` - Ensure `verify()` and `verifyPrehashed()` work
- `src/ciphersuite.ts` - Add `challenge()` and `preVerify()` to interface

---

---

## Test Vector JSON Structures

The Rust implementation uses the following JSON test vector files per ciphersuite:

### 1. elements.json
```json
{
  "elements": {
    "invalid_element": "abcdef7de8baf62d57fe0452581b147b152f776e830c346d1119cee0bc954a59"
  }
}
```
Used for deserialization error tests.

### 2. repair-share.json
```json
{
  "scalar_generation": {
    "random_scalar_1": "7e835f4c5453aea47a09e3925bfa23876de6fc9f92e6a7f8f1b45fe273fb850e",
    "random_scalar_2": "d79cbd35ae36865692f2f31f9ab6fa9109757accb18f10b416a6c99828b82707",
    "random_scalar_3": "73398badf5e53422d721e5acf901be840dbacb7c0c644cb171bd169df360550d",
    "random_scalar_sum": "eeb1bc75c3a9446d37e4cc1932bf1e74841543e950da045e7a18401890140303"
  },
  "sigma_generation": {
    "sigma_1": "19280c3694fc2881346c73fa9024cf3b710d1bc4651b01ac47e982a0c13ef004",
    "sigma_2": "bb8e111c18df8ad1af6710bb5845ff510a96cc37ceb99079cabe635ba0d3dd08",
    "sigma_3": "e37d76cbcbc44c14ef38043bff3b2154467095f0a7c6922444a1f09e4d563f09",
    "sigma_4": "898ea31783f13def4fb0cd9d97d24a18adb48050ed8c7b2af24d246f45b28e0c",
    "sigma_sum": "661b4c7bc6cb19a676836648c3847cd06ec8fd3cc928a0744897fb09f51a9c03"
  }
}
```
Used for repairable threshold scheme tests.

### 3. vectors.json (Signing Test Vectors)
```json
{
  "config": {
    "MAX_PARTICIPANTS": "3",
    "NUM_PARTICIPANTS": "2",
    "MIN_PARTICIPANTS": "2",
    "name": "FROST(ristretto255, SHA-512)",
    "group": "ristretto255",
    "hash": "SHA-512"
  },
  "inputs": {
    "participant_list": [1, 3],
    "group_secret_key": "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
    "verifying_key_key": "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
    "message": "74657374",
    "share_polynomial_coefficients": ["410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02"],
    "participant_shares": [
      {"identifier": 1, "participant_share": "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e"},
      {"identifier": 2, "participant_share": "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01"},
      {"identifier": 3, "participant_share": "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04"}
    ]
  },
  "round_one_outputs": {
    "outputs": [
      {
        "identifier": 1,
        "hiding_nonce_randomness": "...",
        "binding_nonce_randomness": "...",
        "hiding_nonce": "...",
        "binding_nonce": "...",
        "hiding_nonce_commitment": "...",
        "binding_nonce_commitment": "...",
        "binding_factor_input": "...",
        "binding_factor": "..."
      }
    ]
  },
  "round_two_outputs": {
    "outputs": [
      {"identifier": 1, "sig_share": "..."},
      {"identifier": 3, "sig_share": "..."}
    ]
  },
  "final_output": {
    "sig": "fa954853693068803615803a06e2c23a6228f7d6d6b442b72b26696aa776fe75532350f49b27a123b0c811d54671f6c008e319741a59918baf3c5455a5ec2603"
  }
}
```

### 4. vectors_dkg.json (DKG Test Vectors)
```json
{
  "config": {
    "MAX_PARTICIPANTS": 3,
    "MIN_PARTICIPANTS": 2,
    "name": "FROST(Ed25519, SHA-512)",
    "group": "ed25519",
    "hash": "SHA-512"
  },
  "inputs": {
    "verifying_key": "b83aed2f02a94ddd7f2b08543fb45f372aac439fc6001b91d8ddac25f1ce953c",
    "1": {
      "identifier": 1,
      "signing_key": "...",
      "coefficient": "...",
      "vss_commitments": ["...", "..."],
      "proof_of_knowledge": "...",
      "signing_shares": {"2": "...", "3": "..."},
      "verifying_share": "...",
      "signing_share": "..."
    },
    "2": { /* ... */ },
    "3": { /* ... */ }
  }
}
```

---

## Available Ciphersuite Test Vectors (Rust)

| Ciphersuite | Location |
|-------------|----------|
| ristretto255 | `frost-ristretto255/tests/helpers/` |
| ed25519 | `frost-ed25519/tests/helpers/` |
| ed448 | `frost-ed448/tests/helpers/` |
| p256 | `frost-p256/tests/helpers/` |
| secp256k1 | `frost-secp256k1/tests/helpers/` |
| secp256k1-tr | `frost-secp256k1-tr/tests/helpers/` |

Each ciphersuite has:
- `elements.json` - Invalid element for error tests
- `repair-share.json` - Repairable threshold scheme vectors
- `samples.json` - General sample data
- `vectors.json` - Signing protocol vectors
- `vectors_dkg.json` - DKG protocol vectors
- `vectors-big-identifier.json` - Large identifier edge case

---

## Conclusion

The TypeScript implementation is **structurally complete** - all the main classes and functions exist. The tests are skipped because they require:

1. A working ciphersuite implementation
2. Complete signing/verification functionality
3. Test vector JSON files

Once a ciphersuite like `@frosts/ristretto255` is fully implemented with signing capabilities, these tests can be enabled by removing the `.skip` modifier and providing the ciphersuite instance to the test functions.

### Immediate Next Steps

1. **Copy test vectors** from `frost-rust/frost-ristretto255/tests/helpers/` to TypeScript package
2. **Complete the ciphersuite interface** in `@frosts/ristretto255` or `@frosts/ed25519`
3. **Implement missing functionality**:
   - `SigningKey.sign(rng, msg)`
   - `Ciphersuite.challenge(R, vk, msg)`
   - `Ciphersuite.preVerify(msg, sig, vk)`
4. **Enable tests one file at a time**, starting with `coefficient-commitment.test.ts`
