//! Verified chain hash integrity for append-only logs.
//!
//! Models a hash chain where each entry's hash depends on its predecessor,
//! its log index, its term, and its data. Blake3 is modeled as an
//! uninterpreted function with two trusted axioms (determinism and fixed
//! output size). Proves that appending a correctly-hashed entry preserves
//! chain validity.
//!
//! Matches aspen's `compute_entry_hash` and the chain validity invariant
//! from `spec/chain_hash.rs`.

use vstd::prelude::*;

verus! {

/// A chain hash entry: the hash of a log entry in the chain.
pub struct ChainEntry {
    /// The hash value (abstract — 32 bytes in practice).
    pub hash: u64,
    /// Log index this entry covers.
    pub index: u64,
    /// Election term.
    pub term: u64,
    /// Abstract data identifier (hash of the actual data).
    pub data_id: u64,
}

// --- hash function (axiomatized) ---

/// Abstract hash function modeled as uninterpreted.
///
/// In practice this is blake3(prev_hash || index || term || data).
/// We model it as a pure function from four u64 inputs to a u64 hash.
/// The axioms below assert determinism — Verus treats it as opaque.
// r[depends chain.hash-deterministic]
// r[impl chain.hash-deterministic]
pub uninterp spec fn hash_spec(prev: u64, index: u64, term: u64, data_id: u64) -> u64;

// r[verify chain.hash-deterministic]
/// Axiom: the hash function is deterministic.
/// @verified-logic:permanent-axiom — hash_spec is closed/uninterpreted
#[verifier::external_body]
pub proof fn hash_deterministic(
    prev1: u64, idx1: u64, term1: u64, data1: u64,
    prev2: u64, idx2: u64, term2: u64, data2: u64,
)
    requires prev1 == prev2, idx1 == idx2, term1 == term2, data1 == data2
    ensures hash_spec(prev1, idx1, term1, data1) == hash_spec(prev2, idx2, term2, data2)
{}

// --- compute_entry_hash ---

/// Genesis hash constant.
pub const GENESIS_HASH: u64 = 0u64;

// r[depends chain.compute-entry-hash]
/// Spec: compute the chain hash for an entry.
pub open spec fn compute_entry_hash_spec(
    prev_hash: u64, index: u64, term: u64, data_id: u64,
) -> u64 {
    hash_spec(prev_hash, index, term, data_id)
}

// r[impl chain.compute-entry-hash]
/// Computes the chain hash for a log entry.
///
/// Trusted external body — in production this is blake3. Verus trusts
/// the ensures clause and verifies all callers against the spec.
/// @verified-logic:permanent-axiom — crypto primitive, runtime-only
#[verifier::external_body]
pub fn compute_entry_hash(
    prev_hash: u64, index: u64, term: u64, data_id: u64,
) -> (result: u64)
    ensures result == compute_entry_hash_spec(prev_hash, index, term, data_id)
{
    // Runtime: deterministic mix for testing.
    // Verus ignores this body and trusts the ensures.
    let mut h = prev_hash;
    h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(index);
    h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(term);
    h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(data_id);
    h
}

// --- chain validity ---

// r[depends chain.chain-valid]
// r[impl chain.chain-valid]
/// Spec: chain is valid over entries [0, len).
///
/// Each entry's stored hash equals the hash computed from its predecessor.
pub open spec fn chain_valid_spec(entries: Seq<ChainEntry>) -> bool {
    forall|i: int| #![trigger entries[i]]
        0 <= i < entries.len() ==> {
        let prev_hash = if i == 0 { GENESIS_HASH as u64 } else { entries[i - 1].hash };
        entries[i].hash == compute_entry_hash_spec(
            prev_hash, entries[i].index, entries[i].term, entries[i].data_id,
        )
    }
}

// r[verify chain.chain-valid]
/// Empty chain is trivially valid.
proof fn empty_chain_valid()
    ensures chain_valid_spec(Seq::<ChainEntry>::empty())
{}

// --- append preserves chain ---

/// Spec: the new entry's hash is correctly computed from the chain tip.
pub open spec fn correctly_hashed(
    entries: Seq<ChainEntry>, new_entry: ChainEntry,
) -> bool {
    let prev_hash = if entries.len() == 0 {
        GENESIS_HASH as u64
    } else {
        entries[entries.len() - 1].hash
    };
    new_entry.hash == compute_entry_hash_spec(
        prev_hash, new_entry.index, new_entry.term, new_entry.data_id,
    )
}

// r[depends chain.append-preserves]
/// Spec: appending a correctly-hashed entry preserves validity.
pub open spec fn append_preserves_prop(
    entries: Seq<ChainEntry>, new_entry: ChainEntry,
) -> bool {
    (chain_valid_spec(entries) && correctly_hashed(entries, new_entry))
        ==> chain_valid_spec(entries.push(new_entry))
}

// r[impl chain.append-preserves]
// r[verify chain.append-preserves]
/// Proof: appending a correctly-hashed entry preserves chain validity.
proof fn prove_append_preserves(entries: Seq<ChainEntry>, new_entry: ChainEntry)
    requires
        chain_valid_spec(entries),
        correctly_hashed(entries, new_entry),
    ensures chain_valid_spec(entries.push(new_entry))
{
    let new_chain = entries.push(new_entry);

    assert forall|i: int| #![trigger new_chain[i]] 0 <= i < new_chain.len()
    implies {
        let prev_hash = if i == 0 { GENESIS_HASH as u64 } else { new_chain[i - 1].hash };
        new_chain[i].hash == compute_entry_hash_spec(
            prev_hash, new_chain[i].index, new_chain[i].term, new_chain[i].data_id,
        )
    } by {
        if i < entries.len() as int {
            // Existing entry: unchanged, validity preserved from pre-chain
            assert(new_chain[i] == entries[i]);
            if i > 0 {
                assert(new_chain[i - 1] == entries[i - 1]);
            }
        } else {
            // New entry: validity by construction
            assert(i == entries.len() as int);
            assert(new_chain[i] == new_entry);
            if i > 0 {
                assert(new_chain[i - 1] == entries[i - 1]);
            }
        }
    }
}

// r[verify chain.chain-valid]
/// Prefix of a valid chain is valid.
proof fn prefix_valid(entries: Seq<ChainEntry>, k: int)
    requires chain_valid_spec(entries), 0 <= k <= entries.len()
    ensures chain_valid_spec(entries.subrange(0, k))
{
    let sub = entries.subrange(0, k);
    assert forall|i: int| #![trigger sub[i]] 0 <= i < sub.len()
    implies {
        let prev_hash = if i == 0 { GENESIS_HASH as u64 } else { sub[i - 1].hash };
        sub[i].hash == compute_entry_hash_spec(
            prev_hash, sub[i].index, sub[i].term, sub[i].data_id,
        )
    } by {
        assert(sub[i] == entries[i]);
        if i > 0 {
            assert(sub[i - 1] == entries[i - 1]);
        }
    }
}

// --- collision resistance (axiom) ---

// r[depends chain.collision-free]
/// Spec: the hash function is collision-free.
/// Same output from hash_spec implies all four inputs are identical.
pub open spec fn hash_collision_free_prop(
    a1: u64, b1: u64, c1: u64, d1: u64,
    a2: u64, b2: u64, c2: u64, d2: u64,
) -> bool {
    hash_spec(a1, b1, c1, d1) == hash_spec(a2, b2, c2, d2)
        ==> (a1 == a2 && b1 == b2 && c1 == c2 && d1 == d2)
}

// r[impl chain.collision-free]
// r[verify chain.collision-free]
/// Axiom: hash_spec is collision-free (idealized cryptographic assumption).
/// Trusted — mirrors the real-world assumption that Blake3 is collision-resistant.
/// @verified-logic:permanent-axiom — cryptographic collision resistance
#[verifier::external_body]
pub proof fn hash_collision_free(
    a1: u64, b1: u64, c1: u64, d1: u64,
    a2: u64, b2: u64, c2: u64, d2: u64,
)
    requires hash_spec(a1, b1, c1, d1) == hash_spec(a2, b2, c2, d2)
    ensures a1 == a2, b1 == b2, c1 == c2, d1 == d2
{}

// --- chain agreement ---

// r[depends chain.agreement]
/// Spec: two valid chains with matching hashes at position k agree on entries 0..=k.
pub open spec fn chain_agreement_prop(
    chain1: Seq<ChainEntry>, chain2: Seq<ChainEntry>, k: int,
) -> bool {
    (chain_valid_spec(chain1) && chain_valid_spec(chain2)
        && 0 <= k && k < chain1.len() && k < chain2.len()
        && chain1[k].hash == chain2[k].hash)
    ==> forall|i: int| #![trigger chain1[i]]
        0 <= i <= k ==> chain1[i] == chain2[i]
}

/// Helper: one step of the agreement proof.
/// If two valid chains have matching hashes at position k, the entries
/// at k are identical and predecessor hashes also match.
/// Separated from the main recursive proof to keep Z3's workload bounded.
proof fn agreement_step(
    chain1: Seq<ChainEntry>, chain2: Seq<ChainEntry>, k: int,
)
    requires
        chain_valid_spec(chain1),
        chain_valid_spec(chain2),
        0 <= k < chain1.len(),
        0 <= k < chain2.len(),
        chain1[k].hash == chain2[k].hash,
    ensures
        chain1[k] == chain2[k],
        k > 0 ==> chain1[k - 1].hash == chain2[k - 1].hash,
{
    let prev1 = if k == 0 { GENESIS_HASH as u64 } else { chain1[k - 1].hash };
    let prev2 = if k == 0 { GENESIS_HASH as u64 } else { chain2[k - 1].hash };

    // Instantiate chain_valid_spec at position k for both chains.
    assert(chain1[k].hash == compute_entry_hash_spec(
        prev1, chain1[k].index, chain1[k].term, chain1[k].data_id,
    ));
    assert(chain2[k].hash == compute_entry_hash_spec(
        prev2, chain2[k].index, chain2[k].term, chain2[k].data_id,
    ));

    // Both hash outputs are equal (given). Collision-freeness:
    // same output → same inputs.
    hash_collision_free(
        prev1, chain1[k].index, chain1[k].term, chain1[k].data_id,
        prev2, chain2[k].index, chain2[k].term, chain2[k].data_id,
    );
}

/// Helper: prove agreement at a single position i, peeling back from k.
/// Non-quantified ensures — Z3 handles this without rlimit issues.
proof fn agreement_at(
    chain1: Seq<ChainEntry>, chain2: Seq<ChainEntry>, k: int, i: int,
)
    requires
        chain_valid_spec(chain1),
        chain_valid_spec(chain2),
        0 <= i <= k,
        k < chain1.len(),
        k < chain2.len(),
        chain1[k].hash == chain2[k].hash,
    ensures chain1[i] == chain2[i]
    decreases k
{
    agreement_step(chain1, chain2, k);
    if i < k {
        // chain1[k-1].hash == chain2[k-1].hash from agreement_step.
        // Peel back one level: prove agreement at i within 0..=k-1.
        agreement_at(chain1, chain2, k - 1, i);
    }
}

// r[impl chain.agreement]
// r[verify chain.agreement]
/// Proof: two valid chains with matching hashes at position k
/// have identical entries at all positions 0 through k.
///
/// The fundamental security guarantee of hash chains:
/// the hash at any position commits to the entire chain prefix.
/// Uses agreement_at to prove each position, assembled via assert-forall.
proof fn prove_chain_agreement(
    chain1: Seq<ChainEntry>, chain2: Seq<ChainEntry>, k: int,
)
    requires
        chain_valid_spec(chain1),
        chain_valid_spec(chain2),
        0 <= k < chain1.len(),
        0 <= k < chain2.len(),
        chain1[k].hash == chain2[k].hash,
    ensures
        forall|i: int| #![trigger chain1[i]]
            0 <= i <= k ==> chain1[i] == chain2[i]
{
    assert forall|i: int| #![trigger chain1[i]]
        0 <= i <= k implies chain1[i] == chain2[i] by {
        agreement_at(chain1, chain2, k, i);
    }
}

// --- chain divergence (tamper evidence) ---

// r[depends chain.divergence-detected]
/// Spec: if two valid chains differ at position j, hashes at k >= j must differ.
pub open spec fn chain_divergence_prop(
    chain1: Seq<ChainEntry>, chain2: Seq<ChainEntry>, j: int, k: int,
) -> bool {
    (chain_valid_spec(chain1) && chain_valid_spec(chain2)
        && 0 <= j <= k && k < chain1.len() && k < chain2.len()
        && chain1[j] != chain2[j])
    ==> chain1[k].hash != chain2[k].hash
}

// r[impl chain.divergence-detected]
// r[verify chain.divergence-detected]
/// Proof: divergence at position j forces different hashes at all k >= j.
/// Contrapositive of chain agreement. Hash chains are tamper-evident:
/// any modification to any entry is detectable by comparing tip hashes.
proof fn prove_chain_divergence(
    chain1: Seq<ChainEntry>, chain2: Seq<ChainEntry>, j: int, k: int,
)
    requires
        chain_valid_spec(chain1),
        chain_valid_spec(chain2),
        0 <= j <= k,
        k < chain1.len(),
        k < chain2.len(),
        chain1[j] != chain2[j],
    ensures chain1[k].hash != chain2[k].hash
{
    // Proof by contradiction: if hashes matched at k, agreement
    // gives identical entries 0..=k, contradicting divergence at j.
    if chain1[k].hash == chain2[k].hash {
        prove_chain_agreement(chain1, chain2, k);
        assert(chain1[j] == chain2[j]); // contradicts requires
    }
}

// --- single entry validity ---

// r[depends chain.single-entry-valid]
/// Spec: a single correctly-hashed entry from genesis forms a valid chain.
pub open spec fn single_entry_valid_prop(entry: ChainEntry) -> bool {
    correctly_hashed(Seq::<ChainEntry>::empty(), entry)
        ==> chain_valid_spec(seq![entry])
}

// r[impl chain.single-entry-valid]
// r[verify chain.single-entry-valid]
/// Proof: a single entry correctly hashed from genesis is a valid chain.
proof fn prove_single_entry_valid(entry: ChainEntry)
    requires correctly_hashed(Seq::<ChainEntry>::empty(), entry)
    ensures chain_valid_spec(seq![entry])
{
    let chain = seq![entry];
    // Trigger chain_valid_spec quantifier at i = 0.
    // correctly_hashed gives entry.hash == compute_entry_hash_spec(GENESIS_HASH, ...).
    // chain_valid_spec needs chain[0].hash == compute_entry_hash_spec(GENESIS_HASH, ...).
    // Since chain[0] == entry, these are identical.
    assert(chain[0] == entry);
}

} // verus!

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // Simple test hash for runtime tests (not the axiomatized one)
    fn test_hash(prev: u64, index: u64, term: u64, data_id: u64) -> u64 {
        // Deterministic mix for testing
        let mut h = prev;
        h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(index);
        h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(term);
        h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(data_id);
        h
    }

    fn build_chain(entries: &[(u64, u64, u64)]) -> Vec<ChainEntry> {
        let mut chain = Vec::new();
        let mut prev_hash = GENESIS_HASH;
        for &(index, term, data_id) in entries {
            let hash = test_hash(prev_hash, index, term, data_id);
            chain.push(ChainEntry {
                hash,
                index,
                term,
                data_id,
            });
            prev_hash = hash;
        }
        chain
    }

    fn is_chain_valid(chain: &[ChainEntry]) -> bool {
        for (i, entry) in chain.iter().enumerate() {
            let prev = if i == 0 { GENESIS_HASH } else { chain[i - 1].hash };
            let expected = test_hash(prev, entry.index, entry.term, entry.data_id);
            if entry.hash != expected {
                return false;
            }
        }
        true
    }

    // r[verify chain.chain-valid]
    #[test]
    fn test_empty_chain_valid() {
        assert!(is_chain_valid(&[]));
    }

    // r[verify chain.compute-entry-hash]
    #[test]
    fn test_hash_deterministic() {
        let h1 = test_hash(0, 1, 1, 42);
        let h2 = test_hash(0, 1, 1, 42);
        assert_eq!(h1, h2);
    }

    // r[verify chain.chain-valid]
    #[test]
    fn test_chain_valid() {
        let chain = build_chain(&[(1, 1, 100), (2, 1, 200), (3, 2, 300)]);
        assert!(is_chain_valid(&chain));
    }

    // r[verify chain.chain-valid]
    #[test]
    fn test_corruption_detected() {
        let mut chain = build_chain(&[(1, 1, 100), (2, 1, 200), (3, 2, 300)]);
        // Corrupt the second entry's hash
        chain[1].hash = 999;
        assert!(!is_chain_valid(&chain));
    }

    // r[verify chain.append-preserves]
    #[test]
    fn test_append_preserves() {
        let mut chain = build_chain(&[(1, 1, 100), (2, 1, 200)]);
        assert!(is_chain_valid(&chain));

        // Append correctly
        let prev_hash = chain.last().unwrap().hash;
        let new_hash = test_hash(prev_hash, 3, 2, 300);
        chain.push(ChainEntry {
            hash: new_hash,
            index: 3,
            term: 2,
            data_id: 300,
        });
        assert!(is_chain_valid(&chain));
    }

    // r[verify chain.single-entry-valid]
    #[test]
    fn test_single_entry_valid() {
        let hash = test_hash(GENESIS_HASH, 1, 1, 42);
        let chain = vec![ChainEntry {
            hash,
            index: 1,
            term: 1,
            data_id: 42,
        }];
        assert!(is_chain_valid(&chain));
    }

    // r[verify chain.agreement]
    #[test]
    fn test_agreement_matching_chains() {
        // Two chains built from identical inputs must have identical entries.
        let data = &[(1, 1, 100), (2, 1, 200), (3, 2, 300)];
        let chain_a = build_chain(data);
        let chain_b = build_chain(data);
        for i in 0..chain_a.len() {
            assert_eq!(chain_a[i].hash, chain_b[i].hash);
            assert_eq!(chain_a[i].index, chain_b[i].index);
            assert_eq!(chain_a[i].term, chain_b[i].term);
            assert_eq!(chain_a[i].data_id, chain_b[i].data_id);
        }
    }

    // r[verify chain.divergence-detected]
    #[test]
    fn test_divergence_propagates() {
        // Two chains that diverge at position 1 must have different
        // hashes at all subsequent positions.
        let chain_a = build_chain(&[(1, 1, 100), (2, 1, 200), (3, 2, 300)]);
        let chain_b = build_chain(&[(1, 1, 100), (2, 1, 999), (3, 2, 300)]);
        // Position 0: same inputs → same hash
        assert_eq!(chain_a[0].hash, chain_b[0].hash);
        // Position 1: different data → different hash
        assert_ne!(chain_a[1].hash, chain_b[1].hash);
        // Position 2: different predecessor hash propagates
        assert_ne!(chain_a[2].hash, chain_b[2].hash);
    }

    // r[verify chain.collision-free]
    #[test]
    fn test_collision_free_different_inputs() {
        // Different inputs should produce different hashes (probabilistic).
        let h1 = test_hash(0, 1, 1, 42);
        let h2 = test_hash(0, 1, 1, 43);
        assert_ne!(h1, h2);
        let h3 = test_hash(0, 1, 2, 42);
        assert_ne!(h1, h3);
        let h4 = test_hash(1, 1, 1, 42);
        assert_ne!(h1, h4);
    }

    proptest! {
        // r[verify chain.hash-deterministic]
        #[test]
        fn prop_hash_deterministic(prev: u64, idx: u64, term: u64, data: u64) {
            prop_assert_eq!(test_hash(prev, idx, term, data), test_hash(prev, idx, term, data));
        }

        // r[verify chain.chain-valid]
        // r[verify chain.append-preserves]
        #[test]
        fn prop_build_chain_valid(
            entries in proptest::collection::vec((1u64..100, 1u64..10, 0u64..1000), 0..=20),
        ) {
            let indexed: Vec<(u64, u64, u64)> = entries
                .iter()
                .enumerate()
                .map(|(i, &(_, term, data))| ((i + 1) as u64, term, data))
                .collect();
            let chain = build_chain(&indexed);
            prop_assert!(is_chain_valid(&chain));
        }

        // r[verify chain.chain-valid]
        #[test]
        fn prop_corruption_detected(
            entries in proptest::collection::vec((1u64..10, 0u64..1000), 2..=10),
            corrupt_idx in 0usize..10,
        ) {
            let indexed: Vec<(u64, u64, u64)> = entries
                .iter()
                .enumerate()
                .map(|(i, &(term, data))| ((i + 1) as u64, term, data))
                .collect();
            let mut chain = build_chain(&indexed);
            let idx = corrupt_idx % chain.len();
            chain[idx].hash = chain[idx].hash.wrapping_add(1);
            prop_assert!(!is_chain_valid(&chain));
        }

        // r[verify chain.chain-valid]
        #[test]
        fn prop_prefix_valid(
            entries in proptest::collection::vec((1u64..10, 0u64..1000), 1..=10),
            k_raw: usize,
        ) {
            let indexed: Vec<(u64, u64, u64)> = entries
                .iter()
                .enumerate()
                .map(|(i, &(term, data))| ((i + 1) as u64, term, data))
                .collect();
            let chain = build_chain(&indexed);
            let k = k_raw % (chain.len() + 1);
            prop_assert!(is_chain_valid(&chain[..k]));
        }

        // r[verify chain.agreement]
        #[test]
        fn prop_agreement_identical_inputs(
            entries in proptest::collection::vec((1u64..100, 1u64..10, 0u64..1000), 1..=20),
        ) {
            let indexed: Vec<(u64, u64, u64)> = entries
                .iter()
                .enumerate()
                .map(|(i, &(_, term, data))| ((i + 1) as u64, term, data))
                .collect();
            let chain_a = build_chain(&indexed);
            let chain_b = build_chain(&indexed);
            // Identical inputs → identical entries at every position.
            for i in 0..chain_a.len() {
                prop_assert_eq!(chain_a[i].hash, chain_b[i].hash);
                prop_assert_eq!(chain_a[i].index, chain_b[i].index);
                prop_assert_eq!(chain_a[i].term, chain_b[i].term);
                prop_assert_eq!(chain_a[i].data_id, chain_b[i].data_id);
            }
        }

        // r[verify chain.divergence-detected]
        #[test]
        fn prop_divergence_propagates(
            entries in proptest::collection::vec((1u64..10, 0u64..1000), 2..=10),
            diverge_raw: usize,
        ) {
            let indexed: Vec<(u64, u64, u64)> = entries
                .iter()
                .enumerate()
                .map(|(i, &(term, data))| ((i + 1) as u64, term, data))
                .collect();
            let chain_a = build_chain(&indexed);

            // Build chain_b with different data at the divergence point.
            let diverge_idx = diverge_raw % indexed.len();
            let mut modified = indexed.clone();
            modified[diverge_idx].2 = modified[diverge_idx].2.wrapping_add(1);
            let chain_b = build_chain(&modified);

            // All positions from diverge_idx onward must have different hashes.
            for k in diverge_idx..chain_a.len() {
                prop_assert_ne!(chain_a[k].hash, chain_b[k].hash,
                    "hashes should differ at position {} (diverged at {})", k, diverge_idx);
            }
        }

        // r[verify chain.single-entry-valid]
        #[test]
        fn prop_single_entry_valid(idx in 1u64..1000, term in 1u64..10, data in 0u64..1000) {
            let chain = build_chain(&[(idx, term, data)]);
            prop_assert_eq!(chain.len(), 1);
            prop_assert!(is_chain_valid(&chain));
        }
    }
}
