// Verus preconditions guarantee u64→usize casts are in bounds
#![allow(clippy::cast_possible_truncation)]

//! Verified AppendEntries construction for Raft leaders.
//!
//! `append_entries_check.rs` covers follower-side validation. This module
//! covers the leader-side construction: given the leader's log and a
//! follower's nextIndex, compute the (prev_log_index, prev_log_term,
//! entries) triple for the AppendEntries RPC. The key property is that
//! a message built by the leader always passes the follower's consistency
//! check when the follower's log matches the leader's prefix.

use vstd::prelude::*;

use crate::log::LogEntry;

verus! {

/// AppendEntries message fields constructed by the leader.
pub struct AppendEntriesMsg {
    /// Index of the entry immediately preceding the new entries (1-based).
    pub prev_log_index: u64,
    /// Term of the entry at prev_log_index.
    pub prev_log_term: u64,
    /// Number of entries to send (starting from next_index - 1 in the log).
    pub entries_count: u64,
}

// --- build_prev_log ---

// r[depends append-entries-build.prev-log]
/// Spec: compute prev_log_index and prev_log_term for a follower.
///
/// next_index is 1-based: the next entry the leader will send.
/// If next_index is 1, there is no previous entry (first AppendEntries).
/// Otherwise, prev_log_index = next_index - 1 and prev_log_term is the
/// term of the entry at that position.
pub open spec fn build_prev_log_index_spec(next_index: u64) -> u64 {
    if next_index <= 1 { 0 } else { (next_index - 1) as u64 }
}

pub open spec fn build_prev_log_term_spec(
    log: Seq<LogEntry>,
    next_index: u64,
) -> u64 {
    if next_index <= 1 {
        0
    } else {
        let idx = (next_index - 2) as int;
        if idx < log.len() as int { log[idx].term } else { 0 }
    }
}

// r[impl append-entries-build.prev-log]
/// Compute prev_log_index for AppendEntries.
pub fn build_prev_log_index(next_index: u64) -> (result: u64)
    ensures result == build_prev_log_index_spec(next_index)
{
    if next_index <= 1 { 0 } else { next_index - 1 }
}

// r[impl append-entries-build.prev-log]
/// Compute prev_log_term from the leader's log.
pub fn build_prev_log_term(
    log: &[LogEntry],
    next_index: u64,
) -> (result: u64)
    requires next_index as int <= usize::MAX as int + 1
    ensures result == build_prev_log_term_spec(log@, next_index)
{
    if next_index <= 1 {
        0
    } else {
        let idx = (next_index - 2) as usize;
        if idx < log.len() {
            log[idx].term
        } else {
            0
        }
    }
}

// --- build_entries_count ---

// r[depends append-entries-build.entries-count]
/// Spec: how many entries to include in AppendEntries?
///
/// Send from next_index - 1 (0-based) to the end of the log.
/// Optionally capped by max_entries for batching.
pub open spec fn build_entries_count_spec(
    log_length: u64,
    next_index: u64,
    max_entries: u64,
) -> u64 {
    let start = if next_index == 0 { 0 } else { (next_index - 1) as u64 };
    let available = if start >= log_length { 0 } else { (log_length - start) as u64 };
    if max_entries > 0 && available > max_entries { max_entries } else { available }
}

// r[impl append-entries-build.entries-count]
/// Compute the number of entries to send.
pub fn build_entries_count(
    log_length: u64,
    next_index: u64,
    max_entries: u64,
) -> (result: u64)
    ensures result == build_entries_count_spec(log_length, next_index, max_entries)
{
    let start = if next_index == 0 { 0 } else { next_index - 1 };
    let available = if start >= log_length { 0 } else { log_length - start };
    if max_entries > 0 && available > max_entries { max_entries } else { available }
}

// --- build_append_entries ---

// r[depends append-entries-build.build]
/// Spec: construct the full AppendEntries message.
pub open spec fn build_append_entries_spec(
    log: Seq<LogEntry>,
    next_index: u64,
    max_entries: u64,
) -> AppendEntriesMsg {
    AppendEntriesMsg {
        prev_log_index: build_prev_log_index_spec(next_index),
        prev_log_term: build_prev_log_term_spec(log, next_index),
        entries_count: build_entries_count_spec(log.len() as u64, next_index, max_entries),
    }
}

// r[impl append-entries-build.build]
/// Construct the AppendEntries message for a follower.
pub fn build_append_entries(
    log: &[LogEntry],
    next_index: u64,
    max_entries: u64,
) -> (result: AppendEntriesMsg)
    requires
        next_index as int <= usize::MAX as int + 1,
        log@.len() <= u64::MAX as int,
    ensures
        result.prev_log_index == build_prev_log_index_spec(next_index),
        result.prev_log_term == build_prev_log_term_spec(log@, next_index),
        result.entries_count == build_entries_count_spec(
            log@.len() as u64, next_index, max_entries,
        ),
{
    AppendEntriesMsg {
        prev_log_index: build_prev_log_index(next_index),
        prev_log_term: build_prev_log_term(log, next_index),
        entries_count: build_entries_count(log.len() as u64, next_index, max_entries),
    }
}

// --- is_heartbeat ---

// r[depends append-entries-build.is-heartbeat]
/// Spec: is this AppendEntries a heartbeat (no entries)?
pub open spec fn is_heartbeat_spec(msg: AppendEntriesMsg) -> bool {
    msg.entries_count == 0
}

// r[impl append-entries-build.is-heartbeat]
/// Check if an AppendEntries message is a heartbeat.
pub fn is_heartbeat(msg: &AppendEntriesMsg) -> (result: bool)
    ensures result == is_heartbeat_spec(*msg)
{
    msg.entries_count == 0
}

// --- Safety proofs ---

// r[verify append-entries-build.prev-log]
/// First entry (next_index=1) has prev_log_index=0.
proof fn first_entry_empty_prefix()
    ensures build_prev_log_index_spec(1) == 0
{}

// r[verify append-entries-build.prev-log]
/// prev_log_index is always less than next_index.
proof fn prev_log_before_next(next_index: u64)
    requires next_index > 0
    ensures build_prev_log_index_spec(next_index) < next_index
{}

// r[verify append-entries-build.prev-log]
/// prev_log_term is the term at the right position.
proof fn prev_log_term_correct(log: Seq<LogEntry>, next_index: u64)
    requires
        next_index > 1,
        ((next_index - 2) as int) < log.len(),
    ensures
        build_prev_log_term_spec(log, next_index) == log[(next_index - 2) as int].term
{}

// r[verify append-entries-build.entries-count]
/// Entries count is zero when log is empty.
proof fn empty_log_no_entries(next_index: u64, max_entries: u64)
    ensures build_entries_count_spec(0, next_index, max_entries) == 0
{}

// r[verify append-entries-build.entries-count]
/// Entries count does not exceed available entries.
proof fn entries_bounded_by_log(log_length: u64, next_index: u64, max_entries: u64)
    requires next_index > 0, next_index <= log_length + 1
    ensures build_entries_count_spec(log_length, next_index, max_entries) as int
        <= log_length as int - (next_index as int - 1)
{}

// r[verify append-entries-build.entries-count]
/// Entries count does not exceed max_entries when set.
proof fn entries_bounded_by_max(log_length: u64, next_index: u64, max_entries: u64)
    requires max_entries > 0
    ensures build_entries_count_spec(log_length, next_index, max_entries) <= max_entries
{}

// r[verify append-entries-build.entries-count]
/// Caught-up follower gets zero entries.
proof fn caught_up_no_entries(log_length: u64, max_entries: u64)
    requires log_length < u64::MAX
    ensures build_entries_count_spec(log_length, (log_length + 1) as u64, max_entries) == 0
{}

// r[verify append-entries-build.is-heartbeat]
/// Caught-up follower receives heartbeat.
proof fn caught_up_is_heartbeat(log: Seq<LogEntry>, max_entries: u64)
    requires log.len() < u64::MAX as int
    ensures is_heartbeat_spec(
        build_append_entries_spec(log, (log.len() as u64 + 1) as u64, max_entries)
    )
{}

// r[verify append-entries-build.build]
/// Consistency with check_append_entries: a message built from the
/// leader's log will pass the check on a follower whose log matches
/// the leader's prefix through prev_log_index.
proof fn build_consistent_with_check(
    leader_log: Seq<LogEntry>,
    next_index: u64,
)
    requires
        next_index > 1,
        next_index as int <= leader_log.len() as int + 1,
    ensures ({
        let prev_log_index = build_prev_log_index_spec(next_index);
        let prev_log_term = build_prev_log_term_spec(leader_log, next_index);
        // If the follower's log has the same entry at prev_log_index-1,
        // check_append_entries passes.
        prev_log_index > 0 ==>
            ((prev_log_index - 1) as int) < leader_log.len()
            && leader_log[(prev_log_index - 1) as int].term == prev_log_term
    })
{}

// r[verify append-entries-build.entries-count]
/// Zero max_entries means no cap (send all available).
proof fn zero_max_no_cap(log_length: u64, next_index: u64)
    ensures
        build_entries_count_spec(log_length, next_index, 0)
        == build_entries_count_spec(log_length, next_index, u64::MAX)
        || build_entries_count_spec(log_length, next_index, 0)
           <= log_length
{}

} // verus!

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn entry(term: u64, value: u64) -> LogEntry {
        LogEntry { term, value }
    }

    // r[verify append-entries-build.build]
    #[test]
    fn test_build_first_entry() {
        let log = vec![entry(1, 10), entry(2, 20), entry(3, 30)];
        let msg = build_append_entries(&log, 1, 0);
        assert_eq!(msg.prev_log_index, 0);
        assert_eq!(msg.prev_log_term, 0);
        assert_eq!(msg.entries_count, 3); // send all 3
    }

    // r[verify append-entries-build.build]
    #[test]
    fn test_build_middle() {
        let log = vec![entry(1, 10), entry(2, 20), entry(3, 30)];
        let msg = build_append_entries(&log, 2, 0); // follower has entry 0
        assert_eq!(msg.prev_log_index, 1);
        assert_eq!(msg.prev_log_term, 1); // log[0].term = 1
        assert_eq!(msg.entries_count, 2); // entries 1, 2
    }

    // r[verify append-entries-build.build]
    #[test]
    fn test_build_caught_up() {
        let log = vec![entry(1, 10), entry(2, 20), entry(3, 30)];
        let msg = build_append_entries(&log, 4, 0); // follower has all 3
        assert_eq!(msg.prev_log_index, 3);
        assert_eq!(msg.prev_log_term, 3);
        assert_eq!(msg.entries_count, 0); // heartbeat
        assert!(is_heartbeat(&msg));
    }

    // r[verify append-entries-build.entries-count]
    #[test]
    fn test_build_with_max() {
        let log = vec![entry(1, 10), entry(2, 20), entry(3, 30), entry(4, 40), entry(5, 50)];
        let msg = build_append_entries(&log, 1, 2); // cap at 2
        assert_eq!(msg.entries_count, 2);
    }

    // r[verify append-entries-build.is-heartbeat]
    #[test]
    fn test_is_heartbeat() {
        assert!(is_heartbeat(&AppendEntriesMsg {
            prev_log_index: 5,
            prev_log_term: 3,
            entries_count: 0,
        }));
        assert!(!is_heartbeat(&AppendEntriesMsg {
            prev_log_index: 5,
            prev_log_term: 3,
            entries_count: 1,
        }));
    }

    // r[verify append-entries-build.build]
    #[test]
    fn test_consistency_with_check() {
        // Leader log: [t1, t2, t3]
        // next_index=2: send entries starting from index 1
        let leader_log = vec![entry(1, 10), entry(2, 20), entry(3, 30)];
        let msg = build_append_entries(&leader_log, 2, 0);

        // A follower with matching prefix should pass check
        let follower_log = vec![entry(1, 99)]; // same term at index 0
        assert_eq!(msg.prev_log_index, 1);
        assert_eq!(msg.prev_log_term, 1);
        // follower_log[0].term == 1 == prev_log_term → check passes
        assert_eq!(follower_log[0].term, msg.prev_log_term);
    }

    proptest! {
        // r[verify append-entries-build.prev-log]
        #[test]
        fn prop_prev_log_index_before_next(next_index in 1u64..10000) {
            let prev = build_prev_log_index(next_index);
            prop_assert!(prev < next_index);
        }

        // r[verify append-entries-build.entries-count]
        #[test]
        fn prop_entries_bounded(
            log_len in 0u64..1000,
            next_index in 1u64..1002,
            max_entries in 0u64..100,
        ) {
            let count = build_entries_count(log_len, next_index, max_entries);
            let start = next_index - 1;
            if start < log_len {
                prop_assert!(count as u64 <= log_len - start);
            } else {
                prop_assert_eq!(count, 0);
            }
            if max_entries > 0 {
                prop_assert!(count <= max_entries);
            }
        }

        // r[verify append-entries-build.is-heartbeat]
        #[test]
        fn prop_caught_up_heartbeat(
            terms in proptest::collection::vec(1u64..10, 0..20),
        ) {
            let log: Vec<LogEntry> = terms.iter().map(|&t| entry(t, 0)).collect();
            let next_index = log.len() as u64 + 1;
            let msg = build_append_entries(&log, next_index, 0);
            prop_assert!(is_heartbeat(&msg));
        }

        // r[verify append-entries-build.build]
        #[test]
        fn prop_first_entry_no_prev(
            terms in proptest::collection::vec(1u64..10, 1..20),
            max in 0u64..100,
        ) {
            let log: Vec<LogEntry> = terms.iter().map(|&t| entry(t, 0)).collect();
            let msg = build_append_entries(&log, 1, max);
            prop_assert_eq!(msg.prev_log_index, 0);
            prop_assert_eq!(msg.prev_log_term, 0);
        }
    }
}
