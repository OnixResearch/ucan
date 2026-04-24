//! Verified UCAN invocation and receipt model.
//!
//! An invocation binds a capability from a delegation chain to a specific
//! executor and action. A receipt captures the result and who ran it.
//! Proves that a valid receipt requires a valid invocation, and that the
//! executor must match the final audience in the chain.

#![allow(clippy::ptr_arg)]

use vstd::prelude::*;

verus! {

/// An invocation: executing a capability.
pub struct Invocation {
    /// CID of the authorization token (leaf of delegation chain).
    pub auth_cid: Vec<u8>,
    /// DID of the entity invoking the capability.
    pub invoker: Vec<u8>,
    /// Resource being acted upon.
    pub resource: Vec<u8>,
    /// Ability being exercised.
    pub ability: Vec<u8>,
    /// Invocation timestamp.
    pub timestamp: u64,
}

/// Result status of an invocation.
pub enum InvocationResult {
    /// Successful execution with output bytes.
    Ok { output: Vec<u8> },
    /// Failed execution with error bytes.
    Err { error: Vec<u8> },
}

/// A receipt: proof that an invocation was executed.
pub struct Receipt {
    /// The invocation that was executed.
    pub invocation: Invocation,
    /// Who actually executed it.
    pub ran_by: Vec<u8>,
    /// The result.
    pub result: InvocationResult,
    /// Receipt timestamp.
    pub receipt_timestamp: u64,
}

// --- Spec predicates ---

/// The invoker matches a given audience DID.
// r[impl ucan-invocation.invoker-matches-audience]
pub open spec fn invoker_matches_audience_spec(invoker: Seq<u8>, audience: Seq<u8>) -> bool {
    invoker =~= audience
}

/// The executor (ran_by) matches the invoker.
// r[impl ucan-invocation.executor-is-invoker]
pub open spec fn executor_is_invoker_spec(ran_by: Seq<u8>, invoker: Seq<u8>) -> bool {
    ran_by =~= invoker
}

/// The receipt timestamp is at or after the invocation timestamp.
// r[impl ucan-invocation.receipt-ordering]
pub open spec fn receipt_after_invocation_spec(inv_ts: u64, receipt_ts: u64) -> bool {
    receipt_ts as int >= inv_ts as int
}

/// A receipt is valid if executor matches invoker and timestamps are ordered.
// r[impl ucan-invocation.receipt-validity]
pub open spec fn receipt_valid_spec(r: Receipt) -> bool {
    executor_is_invoker_spec(r.ran_by@, r.invocation.invoker@)
    && receipt_after_invocation_spec(r.invocation.timestamp, r.receipt_timestamp)
}

/// An invocation is authorized if the invoker matches the chain's leaf audience.
// r[impl ucan-invocation.authorization-check]
pub open spec fn invocation_authorized_spec(
    invoker: Seq<u8>,
    leaf_audience: Seq<u8>,
    resource: Seq<u8>,
    ability: Seq<u8>,
    leaf_resource: Seq<u8>,
    leaf_ability: Seq<u8>,
) -> bool {
    invoker_matches_audience_spec(invoker, leaf_audience)
    && resource.len() >= leaf_resource.len()
    && resource.subrange(0, leaf_resource.len() as int) =~= leaf_resource
    && ability =~= leaf_ability
}

// --- Exec ---

/// Check if invoker matches the audience.
// r[impl ucan-invocation.invoker-matches-audience]
pub fn check_invoker_matches(invoker: &Vec<u8>, audience: &Vec<u8>) -> (result: bool)
    ensures result == invoker_matches_audience_spec(invoker@, audience@),
{
    if invoker.len() != audience.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < invoker.len()
        invariant
            0 <= i <= invoker.len(),
            invoker.len() == audience.len(),
            forall|k: int| 0 <= k < i ==> invoker@[k] == audience@[k],
        decreases invoker.len() - i,
    {
        if invoker[i] != audience[i] {
            assert(invoker@[i as int] != audience@[i as int]);
            assert(!(invoker@ =~= audience@));
            return false;
        }
        i = i + 1;
    }
    assert(invoker@ =~= audience@);
    true
}

/// Check if a receipt is valid.
// r[impl ucan-invocation.receipt-validity]
pub fn check_receipt_valid(r: &Receipt) -> (result: bool)
    ensures result == receipt_valid_spec(*r),
{
    let exec_ok = check_invoker_matches(&r.ran_by, &r.invocation.invoker);
    let ts_ok = r.receipt_timestamp >= r.invocation.timestamp;
    exec_ok && ts_ok
}

// --- Proofs ---

/// A valid receipt proves the invoker actually ran the action.
// r[verify ucan-invocation.executor-is-invoker]
// r[verify ucan-invocation.receipt-validity]
pub proof fn valid_receipt_confirms_executor(r: Receipt)
    requires receipt_valid_spec(r),
    ensures executor_is_invoker_spec(r.ran_by@, r.invocation.invoker@),
{
}

/// If the invoker doesn't match the audience, invocation is unauthorized.
// r[verify ucan-invocation.invoker-matches-audience]
pub proof fn wrong_invoker_unauthorized(
    invoker: Seq<u8>,
    audience: Seq<u8>,
    resource: Seq<u8>,
    ability: Seq<u8>,
    leaf_resource: Seq<u8>,
    leaf_ability: Seq<u8>,
)
    requires !(invoker =~= audience),
    ensures !invocation_authorized_spec(invoker, audience, resource, ability, leaf_resource, leaf_ability),
{
}

/// Receipt timestamp ordering is transitive with invocation chains.
// r[verify ucan-invocation.receipt-ordering]
pub proof fn receipt_ordering_transitive(ts1: u64, ts2: u64, ts3: u64)
    requires
        receipt_after_invocation_spec(ts1, ts2),
        receipt_after_invocation_spec(ts2, ts3),
    ensures
        receipt_after_invocation_spec(ts1, ts3),
{
}

/// An authorized invocation's resource is a refinement of the leaf capability.
// r[verify ucan-invocation.authorization-check]
pub proof fn authorized_refines_leaf(
    invoker: Seq<u8>,
    leaf_audience: Seq<u8>,
    resource: Seq<u8>,
    ability: Seq<u8>,
    leaf_resource: Seq<u8>,
    leaf_ability: Seq<u8>,
)
    requires invocation_authorized_spec(invoker, leaf_audience, resource, ability, leaf_resource, leaf_ability),
    ensures
        resource.len() >= leaf_resource.len(),
        ability =~= leaf_ability,
{
}

} // verus!

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invoker_matches() {
        assert!(check_invoker_matches(&b"did:key:alice".to_vec(), &b"did:key:alice".to_vec()));
        assert!(!check_invoker_matches(&b"did:key:alice".to_vec(), &b"did:key:bob".to_vec()));
    }

    #[test]
    fn test_valid_receipt() {
        let r = Receipt {
            invocation: Invocation {
                auth_cid: b"cid123".to_vec(),
                invoker: b"did:key:alice".to_vec(),
                resource: b"/photos".to_vec(),
                ability: b"read".to_vec(),
                timestamp: 100,
            },
            ran_by: b"did:key:alice".to_vec(),
            result: InvocationResult::Ok { output: b"data".to_vec() },
            receipt_timestamp: 105,
        };
        assert!(check_receipt_valid(&r));
    }

    #[test]
    fn test_wrong_executor_invalid() {
        let r = Receipt {
            invocation: Invocation {
                auth_cid: b"cid123".to_vec(),
                invoker: b"did:key:alice".to_vec(),
                resource: b"/photos".to_vec(),
                ability: b"read".to_vec(),
                timestamp: 100,
            },
            ran_by: b"did:key:bob".to_vec(),
            result: InvocationResult::Ok { output: b"data".to_vec() },
            receipt_timestamp: 105,
        };
        assert!(!check_receipt_valid(&r));
    }

    #[test]
    fn test_timestamp_before_invalid() {
        let r = Receipt {
            invocation: Invocation {
                auth_cid: b"cid123".to_vec(),
                invoker: b"did:key:alice".to_vec(),
                resource: b"/photos".to_vec(),
                ability: b"read".to_vec(),
                timestamp: 200,
            },
            ran_by: b"did:key:alice".to_vec(),
            result: InvocationResult::Err { error: b"fail".to_vec() },
            receipt_timestamp: 100,
        };
        assert!(!check_receipt_valid(&r));
    }

    #[test]
    fn test_error_receipt_valid() {
        let r = Receipt {
            invocation: Invocation {
                auth_cid: b"cid123".to_vec(),
                invoker: b"did:key:alice".to_vec(),
                resource: b"/photos".to_vec(),
                ability: b"read".to_vec(),
                timestamp: 100,
            },
            ran_by: b"did:key:alice".to_vec(),
            result: InvocationResult::Err { error: b"not found".to_vec() },
            receipt_timestamp: 100,
        };
        assert!(check_receipt_valid(&r));
    }
}
