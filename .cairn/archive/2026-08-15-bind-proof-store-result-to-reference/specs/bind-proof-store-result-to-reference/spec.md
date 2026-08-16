# Bind ProofStore Result to Reference

## ADDED Requirements

### Requirement: Resolved proofs must match their reference

r[ucan.pstore.matches] Before verification uses a proof token returned by `ProofStore::resolve_proof`, the shell MUST recompute the BLAKE3 digest of the returned compact token and compare it to the requested `ProofReference`.

#### Scenario: Store returns the referenced token

r[ucan.pstore.matches.same]
- GIVEN a store returns the exact token referenced in the child claim
- WHEN the shell resolves the reference
- THEN the token MUST enter verification unchanged
- AND the current behavior MUST be preserved

#### Scenario: Store returns a different token

r[ucan.pstore.matches.substituted]
- GIVEN a store returns a valid token whose digest differs from the requested reference
- WHEN the shell resolves the reference
- THEN resolution MUST fail with a deterministic bound-reference error
- AND the substituted token MUST NOT enter the delegation evaluation

### Requirement: The mismatch error is deterministic

r[ucan.pstore.error] A reference mismatch MUST produce a typed proof-store error that names the requested reference and the returned token digest.

#### Scenario: Consumer observes a mismatch

r[ucan.pstore.error.reported]
- GIVEN a mismatch occurs during resolution
- WHEN the consumer inspects the error
- THEN the error MUST identify the expected and actual references
- AND the error MUST distinguish mismatch from missing, stale, and backend failures

### Requirement: Built-in stores stay compatible

r[ucan.pstore.compat] `ProofCollection` and any in-repo `ProofStore` implementation MUST satisfy the binding without code changes.

#### Scenario: In-repo store round trip

r[ucan.pstore.compat.collection]
- GIVEN a consumer uses `ProofCollection`
- WHEN verification resolves an in-range proof
- THEN the stored token MUST match its reference by construction
- AND no behavioral change MUST be observable

### Requirement: The trait contract is documented

r[ucan.pstore.docs] The `ProofStore` trait documentation MUST state that the returned compact token must match the requested reference and that the shell enforces the binding.

#### Scenario: Store authors read the contract

r[ucan.pstore.docs.author]
- GIVEN an author implements `ProofStore`
- WHEN the author reads the trait documentation
- THEN the reference-binding obligation MUST be explicit
- AND the enforcement boundary MUST be explicit
