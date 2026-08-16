# Ucan 1 Wire Profile Specification

## Purpose

Defines the `ucan-1-wire-profile` capability.

## Requirements

### Requirement: UCAN 1.0 wire types are separate

r[ucan.v1_wire.types] UCAN MUST expose separate bounded domain types for final `1.0.0` Delegation and Invocation payloads. These types MUST NOT alias, infer, or reuse the local compact token type as their wire representation.

#### Scenario: Delegation payload is admitted

- GIVEN a Delegation payload has the exact required tag and valid required fields
- WHEN the pure profile core validates it
- THEN it MUST return a typed Delegation value
- AND it MUST NOT return an Invocation or compact-token value

#### Scenario: Token kind is substituted

- GIVEN a payload has Invocation fields under a Delegation tag or Delegation fields under an Invocation tag
- WHEN validation runs
- THEN validation MUST fail with a stable token-kind reason

### Requirement: Profile fields follow final bounded shapes

r[ucan.v1_wire.fields] The pure core MUST validate required and optional fields, slash commands, finite IPLD values, nonces, proof references, subject and audience rules, timestamps from `-(2^53 - 1)` through `2^53 - 1`, and nullable expiry for each token kind.

#### Scenario: Maximum valid timestamp is supplied

- GIVEN a timestamp is within `-(2^53 - 1)` through `2^53 - 1`
- WHEN field validation runs
- THEN the timestamp MUST be admitted

#### Scenario: Timestamp exceeds the range

- GIVEN a timestamp is less than `-(2^53 - 1)` or greater than `2^53 - 1`
- WHEN field validation runs
- THEN validation MUST fail before signing or authority evaluation

### Requirement: Decoder resource use is bounded

r[ucan.v1_wire.limits] The profile decoder MUST enforce explicit input, nesting, collection, map, string, byte, proof, policy, and metadata limits before unbounded allocation or recursion.

#### Scenario: Input is within limits

- GIVEN canonical input stays within every configured limit
- WHEN decoding runs
- THEN decoding MAY proceed to structural validation

#### Scenario: Nested value exceeds a limit

- GIVEN one value exceeds a configured depth, count, or byte limit
- WHEN decoding runs
- THEN decoding MUST stop with a typed limit error
- AND signature verification MUST NOT run

### Requirement: DAG-CBOR admission is canonical and strict

r[ucan.v1_wire.codec] UCAN `1.0.0` wire encoding and signing input MUST use canonical DAG-CBOR. The decoder MUST reject non-canonical forms, duplicate fields, unsupported tags, trailing bytes, and cross-kind payloads.

#### Scenario: Canonical envelope round trips

- GIVEN a valid bounded typed envelope
- WHEN it is encoded, decoded, and encoded again
- THEN the canonical bytes MUST be identical

#### Scenario: Duplicate field is encoded

- GIVEN an envelope contains two encodings of the same map field
- WHEN decoding runs
- THEN decoding MUST reject the envelope
- AND no later field value MUST override an earlier value

### Requirement: UCAN token references use protocol CID rules

r[ucan.v1_wire.cid] UCAN `1.0.0` token references MUST use CIDv1 with DAG-CBOR multicodec and SHA-256 multihash. Base58btc presentation MUST round trip to the same typed CID.

#### Scenario: Canonical bytes produce a CID

- GIVEN canonical DAG-CBOR token bytes
- WHEN CID construction runs
- THEN the CID MUST bind those exact bytes with protocol-required SHA-256

#### Scenario: CID points to different bytes

- GIVEN a declared CID digest does not match the supplied canonical bytes
- WHEN binding validation runs
- THEN validation MUST fail before the token enters proof or authority evaluation

### Requirement: Varsig and signer profiles fail closed

r[ucan.v1_wire.crypto] The shell MUST parse Varsig as a self-describing signature header and MUST admit only implemented algorithm, curve, hash, encoding, and key combinations. The first supported profile MUST bind Ed25519 signatures to the issuer's resolved `did:key` key.

#### Scenario: Signature and issuer key match

- GIVEN an admitted Varsig header, canonical payload, valid signature, and matching issuer key
- WHEN cryptographic verification runs
- THEN the shell MUST return a typed verified envelope

#### Scenario: Header or key does not match

- GIVEN the Varsig algorithm, key class, issuer DID, or signature differs from the admitted profile
- WHEN cryptographic verification runs
- THEN verification MUST fail closed
- AND no verified envelope MUST be created

### Requirement: External capabilities remain caller-owned

r[ucan.v1_wire.ports] Signing and DID key resolution MUST be application-owned shell ports. The component MUST NOT install ambient network, filesystem, database, IPFS, clock, randomness, key custody, or trust-root behavior.

#### Scenario: Resolver cannot answer

- GIVEN the caller-owned key resolver returns missing, stale, denied, malformed, or backend failure
- WHEN verification runs
- THEN verification MUST fail with the corresponding bounded adapter error
- AND it MUST NOT fall back to another resolver

### Requirement: Pinned fixtures drive wire conformance

r[ucan.v1_wire.fixtures] The wire profile MUST replay applicable pinned final UCAN `1.0.0` Delegation and Invocation fixtures and MUST maintain derived negative mutation fixtures bound to their source BLAKE3 identities.

#### Scenario: Official positive fixture passes

- GIVEN an applicable pinned final fixture is structurally and cryptographically valid for the admitted subset
- WHEN the conformance rail runs
- THEN the fixture MUST pass with its exact source and byte identity

#### Scenario: Derived mutation is accepted

- GIVEN a derived fixture changes a required tag, field, canonical byte, signature, key, CID, or limit fact
- WHEN the conformance rail runs
- THEN the mutation MUST fail with the expected stable reason

### Requirement: Wire success does not imply authority

r[ucan.v1_wire.docs] A verified wire envelope MUST prove only bounded format, canonical identity, and cryptographic checks over supplied resolution facts. It MUST NOT imply delegation attenuation, policy satisfaction, invocation authority, revocation freshness, replay durability, transport security, or effect correctness.

#### Scenario: Verified envelope is reported

- GIVEN wire and signature validation succeed
- WHEN documentation or a receipt describes the result
- THEN the claim MUST remain limited to the implemented wire profile
- AND authority evaluation MUST remain a separate step

### Requirement: Wire validation includes positive and negative evidence

r[ucan.v1_wire.validation] The wire component MUST pass positive round-trip and signature tests plus negative malformed, non-canonical, duplicate, oversized, tag, kind, Varsig, key, signature, CID, and timestamp tests.

#### Scenario: Repository rail runs

- GIVEN the component and fixture evidence are current
- WHEN focused and repository checks run
- THEN positive cases MUST pass
- AND negative cases MUST fail with stable typed reasons
