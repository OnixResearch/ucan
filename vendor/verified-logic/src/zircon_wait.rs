//! Verified Zircon wait readiness.
//!
//! Waiting is signal-driven: a wait is ready exactly when the observed
//! signal mask intersects the requested mask.

use vstd::prelude::*;

use crate::signal::signal_intersect;
#[cfg(verus_keep_ghost)]
use crate::signal::signal_intersect_spec;

verus! {

pub struct ZirconWatch {
    pub observed: u64,
    pub requested: u64,
}

// r[depends zircon-wait.readiness]
pub open spec fn wait_ready_spec(observed: u64, requested: u64) -> bool {
    signal_intersect_spec(observed, requested) != 0
}

// r[impl zircon-wait.readiness]
pub fn wait_ready(observed: u64, requested: u64) -> (result: bool)
    ensures result == wait_ready_spec(observed, requested)
{
    signal_intersect(observed, requested) != 0
}

// r[depends zircon-wait.wait-set]
pub open spec fn wait_set_ready_spec(watches: Seq<ZirconWatch>, i: int) -> bool
    recommends 0 <= i < watches.len()
{
    wait_ready_spec(watches[i].observed, watches[i].requested)
}

// r[impl zircon-wait.wait-set]
pub fn wait_set_ready(watches: &[ZirconWatch]) -> (result: Vec<bool>)
    ensures
        result@.len() == watches@.len(),
        forall|i: int| 0 <= i < watches@.len() ==> #[trigger] result@[i] == wait_set_ready_spec(watches@, i),
{
    let mut out: Vec<bool> = Vec::new();
    let mut i: usize = 0;
    while i < watches.len()
        invariant
            0 <= i <= watches@.len(),
            out@.len() == i as int,
            forall|j: int| 0 <= j < i as int ==> #[trigger] out@[j] == wait_set_ready_spec(watches@, j),
        decreases watches.len() - i,
    {
        out.push(wait_ready(watches[i].observed, watches[i].requested));
        i += 1;
    }
    out
}

// r[verify zircon-wait.readiness]
proof fn wait_ready_exact(observed: u64, requested: u64)
    ensures wait_ready_spec(observed, requested) <==> signal_intersect_spec(observed, requested) != 0
{}

// r[verify zircon-wait.wait-set]
proof fn wait_set_entry_exact(watches: Seq<ZirconWatch>, i: int)
    requires 0 <= i < watches.len()
    ensures wait_set_ready_spec(watches, i) == wait_ready_spec(watches[i].observed, watches[i].requested)
{}

} // verus!

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::signal::signal_add;

    // r[verify zircon-wait.readiness]
    #[test]
    fn test_single_wait_ready() {
        let observed = signal_add(0, 3);
        let requested = signal_add(0, 3);
        assert!(wait_ready(observed, requested));
        assert!(!wait_ready(observed, signal_add(0, 4)));
    }

    // r[verify zircon-wait.wait-set]
    #[test]
    fn test_wait_set() {
        let a = ZirconWatch {
            observed: signal_add(0, 1),
            requested: signal_add(0, 1),
        };
        let b = ZirconWatch {
            observed: signal_add(0, 2),
            requested: signal_add(0, 3),
        };
        let ready = wait_set_ready(&[a, b]);
        assert_eq!(ready, vec![true, false]);
    }

    proptest! {
        // r[verify zircon-wait.readiness]
        #[test]
        fn prop_wait_ready_is_intersection(observed: u64, requested: u64) {
            prop_assert_eq!(wait_ready(observed, requested), (observed & requested) != 0);
        }

        // r[verify zircon-wait.wait-set]
        #[test]
        fn prop_wait_set_matches_entries(
            observed in proptest::collection::vec(any::<u64>(), 0..20),
            requested in proptest::collection::vec(any::<u64>(), 0..20),
        ) {
            let n = core::cmp::min(observed.len(), requested.len());
            let mut watches = Vec::new();
            for i in 0..n {
                watches.push(ZirconWatch { observed: observed[i], requested: requested[i] });
            }
            let ready = wait_set_ready(&watches);
            for i in 0..n {
                prop_assert_eq!(ready[i], (observed[i] & requested[i]) != 0);
            }
        }
    }
}
