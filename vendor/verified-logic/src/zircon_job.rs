//! Verified Zircon job containment model.
//!
//! Jobs form a parent-pointer tree. Processes belong to exactly one job.
//! Kill propagation is modeled as subtree membership. A critical process
//! with non-zero exit status kills its owning job. A parent stays live when
//! any running process exists in its subtree.

use vstd::prelude::*;

verus! {

pub open spec fn parents_view(parents: Seq<Option<usize>>) -> Seq<Option<int>> {
    parents.map(|_i: int, p: Option<usize>| match p {
        Some(j) => Some(j as int),
        None => None::<int>,
    })
}

pub open spec fn owners_view(owners: Seq<usize>) -> Seq<int> {
    owners.map(|_i: int, j: usize| j as int)
}

// r[depends zircon-job.containment]
pub open spec fn well_formed_jobs_from_spec(parents: Seq<Option<int>>, from: int) -> bool
    decreases if from <= parents.len() { parents.len() - from } else { 0 }
{
    if from >= parents.len() {
        true
    } else {
        (match parents[from] {
            Some(p) => 0 <= p < from,
            None => true,
        }) && well_formed_jobs_from_spec(parents, from + 1)
    }
}

// r[depends zircon-job.containment]
pub open spec fn well_formed_jobs_spec(parents: Seq<Option<int>>) -> bool {
    well_formed_jobs_from_spec(parents, 0)
}

proof fn well_formed_jobs_suffix(parents: Seq<Option<int>>, from: int)
    requires well_formed_jobs_spec(parents), 0 <= from < parents.len()
    ensures well_formed_jobs_from_spec(parents, from)
    decreases from
{
    if from > 0 {
        well_formed_jobs_suffix(parents, from - 1);
    }
}

fn well_formed_jobs_from_exec(parents: &[Option<usize>], from: usize) -> (result: bool)
    requires from <= parents@.len()
    ensures result == well_formed_jobs_from_spec(parents_view(parents@), from as int)
    decreases parents@.len() - from
{
    if from >= parents.len() {
        true
    } else {
        (match parents[from] {
            Some(parent) => parent < from,
            None => true,
        }) && well_formed_jobs_from_exec(parents, from + 1)
    }
}

// r[impl zircon-job.containment]
pub fn well_formed_jobs(parents: &[Option<usize>]) -> (result: bool)
    ensures result == well_formed_jobs_spec(parents_view(parents@))
{
    well_formed_jobs_from_exec(parents, 0)
}

// r[depends zircon-job.containment]
pub open spec fn unique_parent_spec(parents: Seq<Option<int>>, job: int) -> bool {
    0 <= job < parents.len() && match parents[job] {
        Some(p) => 0 <= p < job,
        None => true,
    }
}

// r[impl zircon-job.containment]
pub fn unique_parent(parents: &[Option<usize>], job: usize) -> (result: bool)
    requires job < parents@.len()
    ensures result == unique_parent_spec(parents_view(parents@), job as int)
{
    match parents[job] {
        Some(p) => p < job,
        None => true,
    }
}

// r[depends zircon-job.containment]
pub open spec fn process_owner_spec(owners: Seq<int>, process: int) -> int
    recommends 0 <= process < owners.len()
{
    owners[process]
}

// r[impl zircon-job.containment]
pub fn process_owner(owners: &[usize], process: usize) -> (result: usize)
    requires process < owners@.len()
    ensures result as int == process_owner_spec(owners_view(owners@), process as int)
{
    owners[process]
}

pub open spec fn job_in_subtree_fuel(parents: Seq<Option<int>>, root: int, job: int, fuel: nat) -> bool
    decreases fuel
{
    if fuel == 0 || root < 0 || root >= parents.len() || job < 0 || job >= parents.len() {
        false
    } else if job == root {
        true
    } else {
        match parents[job] {
            Some(p) => job_in_subtree_fuel(parents, root, p, (fuel - 1) as nat),
            None => false,
        }
    }
}

pub open spec fn job_in_subtree_spec(parents: Seq<Option<int>>, root: int, job: int) -> bool
    recommends well_formed_jobs_spec(parents), 0 <= root < parents.len(), 0 <= job < parents.len()
{
    job_in_subtree_fuel(parents, root, job, (job + 1) as nat)
}

fn job_in_subtree_fuel_exec(parents: &[Option<usize>], root: usize, job: usize, fuel: usize) -> (result: bool)
    requires
        root < parents@.len(),
        job < parents@.len(),
        well_formed_jobs_spec(parents_view(parents@)),
    ensures result == job_in_subtree_fuel(parents_view(parents@), root as int, job as int, (fuel as int + 1) as nat)
    decreases fuel
{
    let ghost pv = parents_view(parents@);
    let ghost r = root as int;
    let ghost j = job as int;
    if job == root {
        proof {
            assert(job_in_subtree_fuel(pv, r, j, (fuel as int + 1) as nat));
        }
        true
    } else if fuel == 0 {
        proof {
            assert(job != root);
            match parents@[j] {
                Some(parent) => {
                    assert(job_in_subtree_fuel(pv, r, j, 1)
                        == job_in_subtree_fuel(pv, r, parent as int, 0));
                    assert(job_in_subtree_fuel(pv, r, parent as int, 0) == false);
                }
                None => {
                    assert(job_in_subtree_fuel(pv, r, j, 1) == false);
                }
            }
        }
        false
    } else {
        match parents[job] {
            Some(parent) => {
                proof {
                    well_formed_jobs_suffix(pv, j);
                    assert(pv[j] == Some(parent as int));
                    assert(match pv[j] { Some(p) => 0 <= p < j, None => true });
                }
                assert(parent < job);
                let result = job_in_subtree_fuel_exec(parents, root, parent, fuel - 1);
                proof {
                    assert(job_in_subtree_fuel(pv, r, j, (fuel as int + 1) as nat)
                        == job_in_subtree_fuel(pv, r, parent as int, fuel as nat));
                }
                result
            }
            None => {
                proof {
                    assert(job_in_subtree_fuel(pv, r, j, (fuel as int + 1) as nat) == false);
                }
                false
            }
        }
    }
}

// r[depends zircon-job.kill-propagation]
pub open spec fn process_in_subtree_spec(parents: Seq<Option<int>>, owners: Seq<int>, root: int, process: int) -> bool
    recommends
        well_formed_jobs_spec(parents),
        0 <= root < parents.len(),
        0 <= process < owners.len(),
        0 <= owners[process] < parents.len()
{
    job_in_subtree_spec(parents, root, owners[process])
}

// r[impl zircon-job.kill-propagation]
pub fn job_in_subtree(parents: &[Option<usize>], root: usize, job: usize) -> (result: bool)
    requires
        root < parents@.len(),
        job < parents@.len(),
        well_formed_jobs_spec(parents_view(parents@)),
    ensures result == job_in_subtree_spec(parents_view(parents@), root as int, job as int)
{
    job_in_subtree_fuel_exec(parents, root, job, job)
}

// r[impl zircon-job.kill-propagation]
pub fn process_in_subtree(parents: &[Option<usize>], owners: &[usize], root: usize, process: usize) -> (result: bool)
    requires
        root < parents@.len(),
        process < owners@.len(),
        owners@[process as int] < parents@.len(),
        well_formed_jobs_spec(parents_view(parents@)),
    ensures result == process_in_subtree_spec(
        parents_view(parents@),
        owners_view(owners@),
        root as int,
        process as int,
    )
{
    job_in_subtree(parents, root, owners[process])
}

// r[depends zircon-job.critical-process]
pub open spec fn critical_exit_kills_job_spec(is_critical: bool, exit_code: i32) -> bool {
    is_critical && exit_code != 0
}

// r[impl zircon-job.critical-process]
pub fn critical_exit_kills_job(is_critical: bool, exit_code: i32) -> (result: bool)
    ensures result == critical_exit_kills_job_spec(is_critical, exit_code)
{
    is_critical && exit_code != 0
}

pub open spec fn running_in_subtree_from_spec(
    parents: Seq<Option<int>>,
    owners: Seq<int>,
    running: Seq<bool>,
    job: int,
    from: int,
) -> bool
    decreases if from <= running.len() { running.len() - from } else { 0 }
{
    if from >= running.len() {
        false
    } else {
        (running[from] && process_in_subtree_spec(parents, owners, job, from))
            || running_in_subtree_from_spec(parents, owners, running, job, from + 1)
    }
}

fn running_in_subtree_from_exec(
    parents: &[Option<usize>],
    owners: &[usize],
    running: &[bool],
    job: usize,
    from: usize,
) -> (result: bool)
    requires
        job < parents@.len(),
        from <= running@.len(),
        owners@.len() == running@.len(),
        forall|i: int| 0 <= i < owners@.len() ==> #[trigger] owners@[i] < parents@.len(),
        well_formed_jobs_spec(parents_view(parents@)),
    ensures result == running_in_subtree_from_spec(
        parents_view(parents@),
        owners_view(owners@),
        running@,
        job as int,
        from as int,
    )
    decreases running@.len() - from
{
    if from >= running.len() {
        false
    } else {
        (running[from] && process_in_subtree(parents, owners, job, from))
            || running_in_subtree_from_exec(parents, owners, running, job, from + 1)
    }
}

// r[depends zircon-job.parent-lifetime]
pub open spec fn parent_kept_live_spec(
    parents: Seq<Option<int>>,
    owners: Seq<int>,
    running: Seq<bool>,
    job: int,
) -> bool
    recommends
        well_formed_jobs_spec(parents),
        0 <= job < parents.len(),
        owners.len() == running.len(),
        forall|i: int| 0 <= i < owners.len() ==> #[trigger] owners[i] < parents.len(),
{
    running_in_subtree_from_spec(parents, owners, running, job, 0)
}

// r[impl zircon-job.parent-lifetime]
pub fn parent_kept_live(parents: &[Option<usize>], owners: &[usize], running: &[bool], job: usize) -> (result: bool)
    requires
        job < parents@.len(),
        owners@.len() == running@.len(),
        forall|i: int| 0 <= i < owners@.len() ==> #[trigger] owners@[i] < parents@.len(),
        well_formed_jobs_spec(parents_view(parents@)),
    ensures result == parent_kept_live_spec(
        parents_view(parents@),
        owners_view(owners@),
        running@,
        job as int,
    )
{
    running_in_subtree_from_exec(parents, owners, running, job, 0)
}

// r[verify zircon-job.containment]
proof fn root_job_has_no_parent(parents: Seq<Option<int>>, root: int)
    requires well_formed_jobs_spec(parents), 0 <= root < parents.len(), parents[root] == None::<int>
    ensures unique_parent_spec(parents, root)
{}

// r[verify zircon-job.kill-propagation]
proof fn root_kills_self(parents: Seq<Option<int>>, root: int)
    requires well_formed_jobs_spec(parents), 0 <= root < parents.len()
    ensures job_in_subtree_spec(parents, root, root)
{}

// r[verify zircon-job.kill-propagation]
proof fn process_owner_in_root_subtree(parents: Seq<Option<int>>, owners: Seq<int>, root: int, process: int)
    requires
        well_formed_jobs_spec(parents),
        0 <= root < parents.len(),
        0 <= process < owners.len(),
        owners[process] == root,
    ensures process_in_subtree_spec(parents, owners, root, process)
{}

// r[verify zircon-job.critical-process]
proof fn clean_exit_does_not_kill_job(is_critical: bool)
    ensures !critical_exit_kills_job_spec(is_critical, 0)
{}

} // verus!

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn parents() -> Vec<Option<usize>> {
        vec![None, Some(0), Some(1), Some(1)]
    }

    // r[verify zircon-job.containment]
    #[test]
    fn test_unique_parent_and_owner() {
        let ps = parents();
        let owners = vec![2usize, 3usize];
        assert!(well_formed_jobs(&ps));
        assert!(unique_parent(&ps, 1));
        assert_eq!(process_owner(&owners, 0), 2);
    }

    // r[verify zircon-job.kill-propagation]
    #[test]
    fn test_kill_propagates_to_subtree() {
        let ps = parents();
        let owners = vec![2usize, 3usize];
        assert!(job_in_subtree(&ps, 1, 2));
        assert!(job_in_subtree(&ps, 1, 3));
        assert!(process_in_subtree(&ps, &owners, 1, 0));
        assert!(process_in_subtree(&ps, &owners, 1, 1));
        assert!(!job_in_subtree(&ps, 2, 3));
    }

    // r[verify zircon-job.critical-process]
    #[test]
    fn test_critical_process() {
        assert!(critical_exit_kills_job(true, 1));
        assert!(!critical_exit_kills_job(true, 0));
        assert!(!critical_exit_kills_job(false, 1));
    }

    // r[verify zircon-job.parent-lifetime]
    #[test]
    fn test_parent_kept_live_by_running_descendant() {
        let ps = parents();
        let owners = vec![2usize, 3usize];
        let running = vec![true, false];
        assert!(parent_kept_live(&ps, &owners, &running, 1));
        assert!(parent_kept_live(&ps, &owners, &running, 0));
        assert!(!parent_kept_live(&ps, &owners, &running, 3));
    }

    proptest! {
        // r[verify zircon-job.critical-process]
        #[test]
        fn prop_critical_exit_matches_pred(is_critical: bool, exit_code: i32) {
            prop_assert_eq!(critical_exit_kills_job(is_critical, exit_code), is_critical && exit_code != 0_i32);
        }
    }
}
