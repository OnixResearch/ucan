# verified-logic

Reusable logic building blocks with machine-checked correctness.

The house style is a `spec fn` (mathematical definition) plus an
`exec fn` whose `ensures result == spec(args)` clause is verified by
[Verus](https://verus-lang.github.io/verus/guide/). The specs are embedded
directly in `src/`; tracked exceptions such as `src/ssa_construction.rs`
are listed in `openspec/specs/verification-gaps/spec.md` so any weaker
bridge stays explicit. Requirement coverage is tracked by
[Tracey](https://tracey.bearcove.eu/).

**8332 Verus proofs · 4116 tests · 1716 requirements · 370 modules · 19 trusted boundaries**

## How it works

```rust
verus! {

// Mathematical definition (ghost code, erased at compile time)
pub open spec fn abs_diff_spec(a: u64, b: u64) -> u64 {
    if a >= b { (a - b) as u64 } else { (b - a) as u64 }
}

// Runtime implementation — Verus checks `ensures` against the body
pub fn abs_diff(a: u64, b: u64) -> (result: u64)
    ensures result == abs_diff_spec(a, b)    // ← mechanically checked
{
    if a >= b { a - b } else { b - a }
}

// Machine-checked proof of a property
proof fn abs_diff_symmetric(a: u64, b: u64)
    ensures abs_diff_spec(a, b) == abs_diff_spec(b, a)
{}

} // verus!
```

## Modules

### Core arithmetic and data structures

| Module | What it verifies |
|---|---|
| `arithmetic` | abs diff, saturating add/sub, checked mul, gcd, div ceil |
| `bitwise` | power-of-two, bit get/set/clear/toggle |
| `bitfield` | multi-bit field extraction and insertion in u64 words |
| `bitmap` | fixed-size bit set over u64 words |
| `bounds` | range predicates, clamping |
| `collections` | sorted insert, binary search, merge sorted, partitioning, find, count |
| `conversion` | checked narrowing (u32/u16/u8), signed↔unsigned |
| `integer` | parity, alignment, log2, next-power-of-two |
| `interval` | half-open interval contains, overlap, split, adjacent, merge |
| `option` | verified Option combinators (map, and_then, or_else, flatten, zip, filter) |
| `ordering` | min, max, median, sign, compare-and-swap |
| `result` | verified Result combinators (map_ok, map_err, and_then, or_else) |
| `ring_buffer` | FIFO queue with power-of-two capacity |
| `sequence` | monotonic sequence generator with batch reservation |
| `slice` | chunk count, prefix/suffix equality, all-equal, mismatch |

### Raft consensus

| Module | What it verifies |
|---|---|
| `election` | leader election state machine |
| `election_init` | candidate election initiation |
| `election_jitter` | election jitter via Knuth multiplicative hash |
| `election_timer` | election timer reset conditions |
| `election_safety_proof` | at most one leader per term (system-level) |
| `pre_vote` | pre-vote protocol |
| `pre_vote_tally` | pre-vote response counting |
| `pre_vote_lease` | PreVote + CheckQuorum interaction |
| `priority_election` | priority-based leader election with delay and yield |
| `vote_tally` | vote response counting |
| `ballot` | vote tracking |
| `epoch` | lexicographic (term, index) comparison |
| `quorum` | majority threshold, intersection theorem, fault tolerance |
| `heartbeat` | heartbeat send/receive primitives |
| `check_quorum` | leader liveness via active peer counting |
| `term_authority` | step-down on higher term |
| `log` | append-only log with Log Matching Property |
| `log_conflict` | log conflict detection and resolution |
| `log_compaction` | prefix truncation for snapshot-based compaction |
| `log_invariant_inductive` | inductive proof of LMP preservation across transitions |
| `append_entries_build` | AppendEntries RPC construction |
| `append_entries_check` | AppendEntries consistency check |
| `append_response` | AppendEntries response dispatch |
| `match_index` | match/next index tracking for replication |
| `commit_advance` | commit index advancement |
| `commit_notify` | commit notification dispatch |
| `fast_backtrack` | accelerated log backtracking |
| `replication_mode` | per-peer FSM (Probe/Replicate/Snapshot) |
| `replication_pipeline` | pipelined replication flow control |
| `follower_commit` | follower commit index update |
| `follower_read` | follower linearizable reads via leader confirmation |
| `follower_redirect` | follower redirect primitives |
| `request_forward` | follower→leader write forwarding |
| `read_index` | read index protocol for linearizable reads |
| `lease_read` | lease-based reads |
| `noop_commit` | no-op entry for leader commitment |
| `install_snapshot` | snapshot installation |
| `snapshot_compaction` | snapshot creation and compaction trigger |
| `snapshot_transfer` | chunked snapshot transfer |
| `snapshot_integrity` | dual-hash integrity scheme |
| `config_change` | configuration change state machine |
| `joint_consensus` | joint consensus for membership changes |
| `voter_set` | voter set promotion |
| `learner_change` | learner add/remove primitives |
| `learner_readiness` | learner catch-up readiness |
| `leadership_transfer` | leadership transfer protocol |
| `witness` | witness replica primitives (vote without full log) |
| `bounded_peers` | bounded peer collection for bootstrap |
| `node_classify` | node classification for cluster reporting |
| `persistent_state` | crash recovery state management |
| `client_routing` | client request routing |
| `client_session` | exactly-once session tracking |
| `entry_type` | log entry type routing |
| `last_applied` | state machine application tracking |
| `linearizability` | linearizability specification |
| `state_machine_safety` | state machine safety theorem |
| `leader_append_only` | leader append-only invariant |
| `leader_completeness` | leader completeness theorem |
| `leader_completeness_ghost` | leader completeness with ghost state |
| `ghost_history` | ghost vote/provenance records for inductive proofs |
| `raft_step` | step decomposition for modular invariant proofs |
| `raft_timing` | timeout configuration validators |
| `trace_relation` | Raft internal state → client-visible trace |

### Other consensus protocols

| Module | What it verifies |
|---|---|
| `paxos` | single-decree Paxos acceptor: ballot ordering, prepare/accept, promise safety |
| `quorum_cert` | quorum certificate aggregation, vote counting, threshold checks |
| `view_change` | view-based reconfiguration: consecutive views, leader rotation |

### Capability authorization

| Module | What it verifies |
|---|---|
| `access_mode` | access mode partial order (Read ⊂ Full) |
| `authorize` | authorization composition |
| `containment` | delegation containment |
| `delegation` | delegation chain validation |
| `glob` | glob pattern matching with wildcards |
| `pattern` | set-membership pattern matching |
| `scope` | scope coverage, compound scoping |
| `subsumption` | variant subsumption |
| `token_timestamp` | UCAN token timestamp validity |

### Memory management

| Module | What it verifies |
|---|---|
| `buddy` | block sizing, buddy addressing, alignment, coalescing, order-for-size |
| `page` | virtual address decomposition, frame numbers, page alignment |
| `region` | address region contains, disjoint, adjacent, merge, split |
| `slab` | slot index/offset/address, generation handles, slab capacity |
| `watermark` | bump allocation with remaining/fits/alloc/reset |
| `heap_index` | binary heap parent/left/right child index arithmetic |

### Memory allocator

| Module | What it verifies |
|---|---|
| `alloc_token` | allocation lifecycle FSM: free → allocated → freed |
| `size_class` | size class bucketing, waste bounds, delegates to buddy order |
| `free_list` | intrusive free list: LIFO push/pop, no-cycle, containment |
| `split_coalesce` | buddy split/coalesce sequences with block conservation |
| `alloc_bitmap` | generational bitmap allocation, double-free detection |
| `arena` | region-based bump allocation with collective free |
| `pool` | fixed-size slab pool: alloc/free with bounded capacity |
| `segregated_free` | per-size-class segregated free lists |
| `coalesce_policy` | immediate vs deferred coalescing policies |
| `fragmentation` | external/internal fragmentation metrics with formal bounds |

### Concurrency primitives

| Module | What it verifies |
|---|---|
| `lock_ordering` | lock acquisition order, deadlock detection, cycle freedom via strict total order |
| `epoch_reclaim` | epoch-based reclamation: three-epoch cycling, pin/unpin, safe-to-reclaim gap proof |
| `hazard_pointer` | hazard pointer protocol: protect/unprotect, no-use-after-free, reclaimable scan |
| `seqlock` | sequence lock: even/odd counter, valid read detection, writer versioning |
| `ref_count` | reference counting: strong/weak, dealloc trigger, upgrade conditions |
| `work_stealing` | work-stealing deque: push/pop/steal bounds, circular buffer index |
| `barrier` | thread barrier: arrive/release, generation counter, leader detection |
| `spin_backoff` | spin-wait backoff: two-phase (spin then yield), phase state machine |
| `rcu` | read-copy-update: grace periods, quiescent state, safe reclamation |
| `mpsc_bounds` | MPSC channel bounds: occupancy, send/receive, capacity, close/drain |
| `futex_state` | futex wait/wake FSM: idle/waiting/notified, notify idempotence |
| `ticket_lock` | FIFO-fair spinlock: ticket/serving counters, fairness, bounded waiters |
| `cas_loop` | CAS retry loop modeling: ABA detection via pack/unpack, retry bounds |
| `bounded_mpmc` | bounded MPMC ring buffer: head/tail, lap-based empty/full, occupancy |
| `memory_order` | memory ordering lattice: Relaxed ⊏ Acquire/Release ⊏ AcqRel ⊏ SeqCst |
| `cache_hierarchy` | inclusive/exclusive/non-inclusive L1/L2 invariants, back-invalidation, capacity, and snoop scope |
| `cache_prefetch` | architecturally invisible prefetch hints with MESI-compatible cache effects and dirty-victim writeback |
| `store_buffer` | fixed-capacity store queue with youngest-match forwarding, FIFO drain, and fence-empty semantics |
| `tlb_shootdown` | page-local TLB shootdown: initiator self-invalidation, monotone acknowledgments, completion freshness, disjoint-page isolation, and range coverage |
| `semaphore` | counting semaphore: acquire/release permits, capacity bounds |
| `two_phase_lock` | two-phase locking: growing/shrinking phase discipline |
| `lease_mutex` | lease-based distributed mutual exclusion with fencing tokens |

### Financial accounting

| Module | What it verifies |
|---|---|
| `balance` | debit/credit with overflow guards |
| `double_entry` | double-entry bookkeeping invariants |
| `escrow` | fund/release/refund/dispute state machine with conservation |
| `fee` | basis-point fee computation, monotonicity, conservation |
| `journal` | append-only transaction journal with running balances |
| `ledger` | multi-account ledger with total conservation theorem |
| `settlement` | bilateral netting with positions-sum-zero theorem |
| `transfer` | value transfer between accounts, duplicate detection |

### Storage engine primitives

| Module | What it verifies |
|---|---|
| `btree_balance` | B-tree node fill percentage, split/merge sizing, underfull detection |
| `btree_insert` | B-tree node insert: sorted position, split on overflow |
| `btree_delete` | B-tree node delete: key removal, merge/rebalance on underflow |
| `lsm_level` | LSM level target sizing, level count, space/write amplification |
| `wal_segment` | WAL entry sequencing, segment space, truncation, contiguity |
| `wal_recovery` | WAL crash recovery: replay range, idempotent replay, checkpoint |
| `compaction_fence` | log compaction coordination with replication, safe compact index |
| `page_checksum` | Fletcher-style two-sum checksum, torn-write detection |
| `free_space_map` | free-space bitmap tracking: allocate/free, count, find-first-free |
| `write_buffer` | write buffer (memtable): size tracking, flush threshold, swap |
| `write_policy` | write-back/write-through dirty invariants, eviction, flush, read equivalence |
| `block_cache` | block cache: occupancy, eviction, dirty tracking, write-back |
| `set_associative_lookup` | cache address decomposition, per-set tag lookup, duplicate-tag checks |

### Distributed systems

| Module | What it verifies |
|---|---|
| `causal_order` | vector-clock-based causal ordering |
| `circuit_breaker` | circuit breaker state machine |
| `consistent_hash` | consistent hash ring lookup |
| `consistent_snapshot` | consistent cut: vector-clock-based cut validity, monotonicity |
| `crdt` | G-Counter, PN-Counter, LWW-Register |
| `distributed_lock` | distributed lock protocol |
| `fencing` | fencing tokens for stale-write rejection |
| `gossip` | gossip infection bounds |
| `markov` | Markov chain prediction |
| `merkle` | Merkle proof verification |
| `rwlock` | read-write lock mode transitions, mutual exclusion |
| `per_core_rwlock` | per-core reader aggregation, writer drain, and rwlock mode refinement |
| `vector_clock` | vector clock merge, happens-before, concurrency |

### Nix package manager

| Module | What it verifies |
|---|---|
| `nix_attrset` | attribute set operations (get, has, merge, intersect, remove) |
| `nix_closure` | generic closure computation |
| `nix_list` | list operations (head, tail, elem, concat, gen_list) |
| `nix_string` | string operations (substring, length, replace) |
| `nix_version` | version comparison (same algorithm as Nix's compareVersions) |

### Nickel language semantics

| Module | What it verifies |
|---|---|
| `nickel_priority` | Nickel merge priority total order: Bottom < Neutral < Numeral(n) < Top |
| `nickel_merge_split` | Nickel three-way record split: left-only, center, right-only |
| `nickel_field_merge` | Nickel field-level merge resolution by priority |
| `nickel_record_merge` | Nickel full record merge with identity, disjoint commutativity, and neutral-record associativity proofs |
| `nickel_subtype` | Nickel gradual type subtyping: reflexivity, covariance, record-dict |
| `nickel_polarity` | Nickel contract blame polarity: flip on domain, double-flip identity |
| `nickel_pattern_coverage` | Nickel pattern completeness and overlap detection |

### Networking

| Module | What it verifies |
|---|---|
| `tcp_state` | TCP connection state machine (RFC 793): 11 states, 18 transitions, reachability |

### Database internals

| Module | What it verifies |
|---|---|
| `txn_isolation` | SQL isolation level hierarchy: Read Uncommitted through Serializable |
| `mvcc` | multi-version concurrency control: version visibility, snapshot reads |
| `snapshot_isolation` | write-write conflict detection for snapshot isolation |
| `query_cost` | query plan cost model: sequential scan, index scan, selectivity |
| `index_select` | covering index checks, index selection by estimated cost |
| `txn_dependency` | transaction dependency graph: read-write and write-write conflicts |

### Graph algorithms

| Module | What it verifies |
|---|---|
| `topo_sort` | topological sort via Kahn's algorithm: validity, completeness |
| `cycle_detect` | cycle detection: remaining node count proves acyclicity |
| `reachability` | BFS reachability: soundness, visited-set monotonicity |
| `dominator_tree` | iterative dominator sets, immediate dominators, and dominance frontiers |
| `loop_detection` | back-edge classification, loop bodies over reachability/dominator views, exit edges, and nesting |
| `liveness_analysis` | backward live-in/live-out analysis, fixed-point checks, and live-range projection |
| `ssa_construction` | iterated-dominance-frontier phi placement, SSA renaming, and phi elimination |
| `dead_code_elimination` | dead-instruction classification, block elimination, observable-trace preservation, idempotence |
| `graph_color` | graph 2-coloring (bipartiteness): no adjacent same-color |
| `shortest_path` | unweighted shortest path via BFS: distance bounds |

### Compiler backend

| Module | What it verifies |
|---|---|
| `stack_frame_layout` | aligned stack-slot placement, exact rounded frame sizing, and explicit safe-reuse checks over live ranges |

### Scheduling primitives

| Module | What it verifies |
|---|---|
| `deadline_queue` | earliest-deadline-first ordering, deadline comparison |
| `fair_share` | weighted fair allocation: monotonicity, conservation |
| `priority_inversion` | priority inheritance protocol: effective priority, inversion detection |
| `weighted_round_robin` | weighted round-robin: fairness, wrap-around, next consumer |
| `job_dag` | job dependency DAG: all-deps-satisfied, ready-to-run |

### Job runner

| Module | What it verifies |
|---|---|
| `job_state` | job lifecycle FSM: Pending → Ready → Running → Completed/Failed/Cancelled |
| `job_priority` | priority ordering: (class, sequence) total order, higher-first selection |
| `job_slot` | bounded concurrency slot pool: acquire/release, capacity |
| `job_cancel` | cancellation propagation: dependent cancellation, surviving paths |
| `job_idempotency` | idempotency tokens: consume-once, duplicate rejection |
| `durable_history` | append-only durable event history, contiguous prefix, append admission |
| `durable_replay` | replay gate for durable prefix reads and effect deduplication |
| `durable_resume` | checkpoint advancement and crash-recovery resume-point derivation |
| `durable_terminal` | terminal outcome detection and deterministic recovery status |
| `job_retry` | retry decisions: attempts, budget, retryable classification |
| `job_timeout` | deadline computation, timeout checking, not-timed-out-at-start |
| `job_result` | exit code classification: success/failure/error, completion status |

### Serialization

| Module | What it verifies |
|---|---|
| `serialize_inj` | canonical byte encoding injectivity: tag-length-value roundtrips, u64 encode/decode |

### Systems decision logic

| Module | What it verifies |
|---|---|
| `approval` | merge gating: approval counting, stale detection |
| `backoff` | exponential backoff with cap and jitter bounds |
| `batch` | write batch limit checking and flush decisions |
| `bloom` | Bloom filter insert/query monotonicity, no false negatives |
| `bounded_range` | ranges with optional upper bound |
| `cas` | compare-and-swap condition evaluation |
| `chunk` | ceiling-division chunk arithmetic |
| `constant_time_eq` | constant-time 32-byte equality |
| `cost_tracker` | cost accumulation, budget enforcement, model selection |
| `cow` | copy-on-write ref counting, snapshot isolation |
| `drain` | graceful shutdown admission protocol |
| `drain_protocol` | drain with double-check admission |
| `env_scrub` | environment variable scrubbing for sandbox isolation |
| `eviction` | LRU cache eviction with protected entries |
| `eviction_score` | multi-factor eviction scoring |
| `expiration` | TTL calculation, lease/key expiration |
| `hash_bucket` | hash-to-bucket assignment (modular and power-of-two) |
| `kv_version` | KV entry version computation |
| `layout_constraint` | layout constraint resolution |
| `lease` | lease management with disjointness and renewal |
| `monotonic` | advancement predicates for terms, indices |
| `node_lifecycle` | node lifecycle state machine |
| `partition` | non-overlapping gap-free interval partitions |
| `peer_spec` | peer specification parsing |
| `permission` | Unix file permission bit manipulation |
| `pressure` | multi-threshold severity classification |
| `process_state` | process lifecycle state machine |
| `rate_limit` | integer token bucket rate limiting |
| `retry` | retry decision logic with budget tracking |
| `sequential` | sequential access detection, prefetch triggering |
| `signal` | signal set operations |
| `tier` | tier classification for tiered caching |
| `tiered_rate_limit` | two-tier rate limit (global + per-peer) |
| `tiling` | tiling layout: disjoint rects, containment, scroll bounds |
| `trust_level` | trust level resolution and access control |
| `two_phase` | two-phase commit decision logic |
| `type_lattice` | type conversion lattice |
| `typed_state` | compile-time verification pipeline enforcement via phantom types |
| `quota` | resource quota enforcement: remaining capacity, overcommit detection |

### Generic proof infrastructure

| Module | What it verifies |
|---|---|
| `algebraic` | commutative, associative, idempotent, semilattice, partial order predicates |
| `pointwise` | scalar operation lifting to sequences |
| `seq_fold` | recursive counting and folding over sequences |
| `seq_set` | set-theoretic operations over integer sequences |
| `forest` | parent-pointer forest: ancestors, LCA, subtree walks |
| `session_tree` | session tree as forest + seq_set composition |
| `chain` | chain hash integrity with append-preserves proof |
| `choreography_global` | finite global choreography syntax, participants, and well-formedness |
| `choreography_local` | finite local choreography syntax, branch lookup, and merge |
| `choreography_projection` | projectability checks and endpoint projection |
| `choreography_step` | one-step global/local reduction and shared-prefix alignment |
| `debruijn` | de Bruijn shifting, substitution, beta reduction, and scope preservation |
| `acid` | atomicity, consistency, isolation, durability over state vectors |

### Cross-module properties

| Module | What it verifies |
|---|---|
| `properties` | 200+ cross-module proofs: signal↔bitwise, permission independence, escrow↔balance, ledger↔transfer, fee conservation, election↔quorum, fencing↔CAS, vector clock↔CRDT, mpmc↔mpsc occupancy, spin↔CAS retry, seqlock↔memory order, RCU↔epoch reclaim, ref count↔hazard pointer, lock ordering↔ticket lock, barrier↔quorum, futex↔notify roundtrip, job state↔timeout↔result, CAS ABA↔pack roundtrip, concurrency protocol↔data structure composition, choreography projection/choice/step correspondence |
| `concurrent_composition` | concurrency protocol ↔ data structure invariant chains across 7 groups |
| `consensus_path` | end-to-end Raft read/write path composition proofs |

## Usage

```toml
[dependencies]
verified-logic = { git = "https://github.com/yourname/verified-logic" }
```

```rust
use verified_logic::arithmetic::abs_diff;
use verified_logic::bounds::clamp;
use verified_logic::quorum::majority;
use verified_logic::drain::can_start_op;

let d = abs_diff(10, 3);       // 7
let c = clamp(15, 0, 10);      // 10
let m = majority(5);           // 3
let ok = can_start_op(false);  // true (not draining)
```

For normal `cargo build`, the `vstd` crate erases all ghost code. No
runtime cost from specs, proofs, requires, or ensures.

## Development

```bash
nix develop                # enter devshell
cargo check                # compile (ghost code erased)
cargo test                 # 4106 tests (unit + property + doc)
cargo clippy --all-targets -- -D warnings
```

## Verification

```bash
./scripts/verify.sh        # all gates: clippy → tests → verus → coverage
./scripts/verus.sh         # verus only (8332 proofs)
./scripts/check-coverage.sh   # every pub fn has r[impl] annotation
./scripts/check-ensures.sh    # every pub fn in verus! has ensures
```

## Structure

```
src/lib.rs              ← crate root, 370 module declarations
src/<module>.rs         ← spec fn + exec fn + proof fn + #[cfg(test)] tests
docs/requirements.md    ← 1716 tracey requirements
scripts/verus.sh        ← verus wrapper with nix store paths
scripts/verify.sh       ← full verification pipeline
scripts/check-*.sh      ← annotation enforcement
```

Most modules follow the same pattern (tracked exceptions are listed in
`openspec/specs/verification-gaps/spec.md`):

1. `pub open spec fn *_spec(...)` — mathematical definition with `r[depends]` annotation
2. `pub fn *(...)` with `ensures result == *_spec(args)` — runtime code with `r[impl]` annotation
3. `proof fn` — properties of the spec with `r[verify]` annotation
4. `#[cfg(test)]` — unit tests and proptest property tests

## Trusted items

`16` items are marked `#[verifier::external_body]` across `6` files.
In addition, `src/ssa_construction.rs` currently carries `3`
`assume_specification[...]` bridges from thin verified wrappers to plain-Rust
runtime helpers.

**16 permanent** (architectural trust boundaries):

- **6 cryptographic axioms / exec bridges** (`chain.rs`, `snapshot_integrity.rs`) —
  BLAKE3-style hashing is modeled with uninterpreted specs plus trusted exec wrappers.
- **4 version comparison bridges** (`nix_version.rs`) — the recursive `cv_fuel`
  reasoning still exceeds solver budget.
- **2 nix store-path hash bridges** (`nix_store_path.rs`) — external hash/model bridge.
- **3 log matching inductive bridges** (`log_invariant_inductive.rs`) — local lemmas are
  only sound under the global Raft leader-chain invariant.
- **1 web-of-trust principal bridge** (`web_of_trust_principal.rs`) — principal digest bytes stay behind a trusted exec/model boundary.

**3 closeable** (`src/ssa_construction.rs`) — `assume_specification[...]`
exec bridges for phi placement, SSA construction, and dominance/use
checking. Def-site collection, IDF computation, SSA-property checking, and
phi elimination are internalized now; runtime tests and manual oracles
still cover the stronger remaining semantic claims.

In addition to `external_body`, the current audit also tracks:

- `3` `assume_specification[...]` exec bridges
- `0` `assume(...)` soundness oracles
- `0` `@verified-logic:no-ensures` / placeholder-spec surfaces

All trusted items remain listed in `openspec/specs/verification-gaps/spec.md` with rationale.
