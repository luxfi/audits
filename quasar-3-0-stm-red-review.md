# QuasarSTM (Block-STM 3.0) — Red Adversarial Review

**Author**: Red (adversarial)
**Date**: 2026-04-26
**Scope**: LP-010 (QuasarSTM), LP-132 (QuasarGPU), Metal kernel, layout, host driver, tests
**Target launch**: 2025-12-25
**Threat model**: An adversary submits transactions designed to cause two honest validators on the same input to produce divergent `state_root`, `receipts_root`, `execution_root`, `block_hash`, or `tx_count`. Any divergence is a chain split.

---

## Executive Summary

**16 findings: 4 Critical, 5 High, 4 Medium, 3 Low/Informational.**

The 3.0 spec is well thought out — lanes, three-tier validation, commit horizons, deterministic policy ordering, and the discipline against "retry-until-success" loops are real safety primitives. **None of that is implemented.** The shipping substrate is closer to 2.0 with v0.40 DAG bolted on. The gap between the LP and the kernel is the headline architectural risk: LP-010 documents anti-livelock hard limits (`MAX_FAST_REPAIRS=3`, `MAX_TOTAL_REPAIRS=8`, `HOT_LANE_CONFLICT_THRESHOLD=16`) as "mandatory on GPU"; the kernel enforces none of them. Repair amplification is theoretically O(N²) and the only thing capping it in practice is the host's `max_epochs` argument to `run_until_done`.

The most concerning concrete issue is **Q3.0-STM-001**: on the slow path, `drain_validate` performs `mvcc_apply_writes` *before* `ring_try_push(commit_hdr, ...)`. If the commit ring is full (the spec calls this out as expected backpressure), the version is bumped, the tx is requeued onto Validate, and on the next tick it re-validates, finds its own bumped version, and is shoveled to Repair — incrementing `conflict_count`, `repair_count`, and corrupting the `execution_root` chain order across runs because *which* tick the commit ring fills is timing-dependent. Two validators on the same input will produce different roots if the host on validator A drains the commit ring with different latency than validator B.

The next-most-concerning is **Q3.0-STM-002**: `mvcc_locate` writes `key_lo`/`key_hi` as plain non-atomic stores. Two GPU threads racing to claim the same empty slot can both succeed (the second tx's store overwrites the first), and a concurrent reader can observe `key_lo` set with `key_hi` still zero. This is sufficient on its own to cause root divergence between validators.

These are both fixable inside 3.0 before 2025-12-25 with bounded local changes. Critical & high findings are all must-fix-pre-launch.

---

## Findings

### Q3.0-STM-001 — Commit ring backpressure produces nondeterministic repair counts and divergent execution_root [Critical]

**Description**. In `drain_validate`, the order of operations on a passing tx is:
1. `mvcc_apply_writes(...)` (atomic version bump)
2. construct CommitItem, compute receipt_hash
3. `ring_try_push(commit_hdr, c)`
4. on push failure: requeue the *original ExecResult* back onto Validate.

The version bump in step 1 is permanent. If step 3 fails (commit ring full — explicitly called out as expected backpressure in the LP), the tx will re-enter Validate on the next tick, but `mvcc_check_consistent` will now find its own bumped version (`cur != e.version_seen`) and route it to Repair. This double-counts conflicts and repairs, AND alters which tx wins the keccak chain in `drain_commit`.

Worse: the comment in the code admits this is wrong:
> "Roll back the MVCC version bump? In v0.36 substrate the version monotonically advances; if commit ring is full we requeue and let downstream catch up next tick. The version mismatch this introduces only causes other concurrent txs to repair, which is correct under Block-STM."

It is **not** correct under Block-STM. It introduces a new conflict that depends on whether the commit ring was full at that exact moment. Two validators racing the GPU scheduler differently will fill the commit ring at different points and produce different `repair_count`, different commit ordering (different receipts/execution_root), and ultimately different `block_hash`.

**Affected**: `quasar_wave.metal:978-1004`, `quasar_wave.cu:691-708`.

**Attack scenario**. Adversary submits a block where validate-throughput exceeds commit-throughput for a sustained tick. Easiest construction: a moderate flood of independent-key txs (no real conflicts) + a tight `wave_tick_budget` so the commit drain falls behind. On validator A the commit ring fills at tick K, on validator B at tick K+1. Their receipts_root chains observe a different commit order. Roots diverge.

**Fix**. The commit-side push must be tried *before* the MVCC mutation, OR the mutation must be tentatively rolled back on push failure. Cleanest fix:
1. Try `ring_try_push(commit_hdr, c)` first.
2. If it fails, push the ExecResult back to Validate without mutating MVCC. Tx will re-validate next tick and re-apply.

Or: split commit into a "reserve commit slot" → "apply MVCC writes" → "fill receipt" sequence that is atomic against the commit-ring-full case.

**Must-fix pre-launch**: YES.

---

### Q3.0-STM-002 — Non-atomic key claim in `mvcc_locate` allows double-claim and torn key reads [Critical]

**Description**. `mvcc_locate` claims an empty slot via plain (non-atomic) stores:
```
if (s->key_lo == 0UL && s->key_hi == 0UL) {
    s->key_lo = key_lo;
    s->key_hi = key_hi;
    return idx;
}
```

Two concurrent fibers landing on the same empty slot — possible because `drain_exec` runs on workgroup `gid=4` but `drain_validate` (`gid=5`) and `drain_dagready` (`gid=3`) **also call `mvcc_locate`** from their own workgroups concurrently within one wave-tick dispatch. (Confirmed: `drain_dagready` doesn't call `mvcc_locate`, but `drain_exec`, `drain_validate.mvcc_check_consistent`, and `drain_validate.mvcc_apply_writes` all do, from gid=4 and gid=5 simultaneously. The kernel does NOT serialize these via `gid==4` only.)

Even worse: the comment claims "races on (last_writer_tx, version) atomics" make this safe, but those atomics only protect the version once the slot is claimed. The *claim itself* is racy:
- Thread T1 reads (0, 0), starts writing key_lo = K.
- Thread T2 reads (0, 0), also writes key_lo = K, key_hi = 0.
- Thread T1 writes key_hi = K_HI.
- Final state: key_lo=K (correct), key_hi=K_HI (correct), version=0 — but T1 returned `idx` and T2 also returned `idx`. Both think they own the slot for *different* keys if the keys happened to differ in the unlikely-collision case, OR for the same key (no harm) if they match.

The actually-exploitable case: **torn key read by another concurrent fiber.** If a third thread T3 reaches the same idx during the window between `s->key_lo = key_lo` and `s->key_hi = key_hi`, T3 sees `(key_lo=K, key_hi=0)` and either (a) misidentifies the slot as "occupied by some other key (K,0)" and probes onward, or (b) finds the comparator passes coincidentally and corrupts the wrong key's version.

**Affected**: `quasar_wave.metal:489-510`, `quasar_wave.cu:411-428`.

**Attack scenario**. Adversary submits a block whose first 16 transactions all touch *different* keys whose FNV-1a hash collides on the same MVCC slot. (FNV-1a is not cryptographic; finding 16 colliding keys is trivial — pre-image / second-pre-image). Multiple drain_exec/validate workgroups race the empty slot, and depending on GPU scheduling, the version chain on that slot is associated with a nondeterministic key, producing different `state_root` between validators.

**Fix**. Use `atomic_compare_exchange` on a sentinel field (e.g., on a packed (key_lo|busy) marker, or on a separate `slot_state` atomic) to claim the slot:
```
// Compete to install key_lo using atomic CAS from 0 → key_lo.
// On success, store key_hi (no race since only the winner reaches here),
// then publish the slot via a fence + store of a "ready" flag.
```
Pair with `atomic_thread_fence(memory_order_acq_rel)` to publish the key bytes before any reader can match them.

Also: replace FNV-1a with a keyed hash (or use a structured key with sufficient cryptographic mixing) so an adversary cannot trivially hand-craft hash collisions. FNV-1a is fine for non-adversarial workloads, not for a public chain accepting adversarial inputs.

**Must-fix pre-launch**: YES.

---

### Q3.0-STM-003 — Anti-livelock hard limits (`MAX_FAST_REPAIRS`, `MAX_TOTAL_REPAIRS`, `HOT_LANE_CONFLICT_THRESHOLD`) are not enforced anywhere in code [Critical]

**Description**. LP-010 §4.0 ("Anti-livelock hard limits — mandatory on GPU") documents:
```
constexpr uint32_t MAX_FAST_REPAIRS                = 3;
constexpr uint32_t MAX_TOTAL_REPAIRS               = 8;
constexpr uint32_t HOT_LANE_CONFLICT_THRESHOLD     = 16;
```
with the caption: "Unbounded repair loops are unacceptable on GPU."

Grep across `quasar_wave.metal`, `quasar_wave.cu`, `quasar_gpu_engine.mm`, `quasar_gpu_engine_cuda.cpp`, and `quasar_gpu_layout.hpp`: **none of these constants exist**. There is no per-tx repair counter check, no abort-on-repair-bound, no cold-queue demotion. `drain_validate` increments `result->repair_count` (a global counter) and pushes the ExecResult back to Repair → Exec without any bound.

The only thing limiting an N² repair storm is the host's choice of `max_epochs` in `run_until_done`. The test `test_block_stm_conflict_repair` passes `max_epochs=256` and asserts only that `r.status == 1u`. If 256 ticks are insufficient (because the adversary submits a block that requires more), the round fails non-deterministically: validator A might have a fast GPU and finish in 200 ticks; validator B with a slower GPU times out at 256.

**Affected**: entire kernel — there is nowhere to put the counter check because it doesn't exist.

**Attack scenario**. Adversary submits 1024 transactions all writing the same key. Theoretical bound is O(N²) ≈ 524K repairs; even with an aggressive 1M ops/sec drain that's 0.5 seconds of pure repair churn — but the worst-case bound is actually higher because repair → exec → validate can re-enter validation without the original tx ever committing (the schedule is GPU-nondeterministic). Easier attack: 256 same-key txs guaranteed to produce ~32K repairs. The adversary picks block size to land just past whatever the host chose for `max_epochs`. Some validators fail to finalize; others succeed; chain splits.

**Fix**. Add `repair_count` and `incarnation` to the FiberSlot or a per-tx state record. In `drain_validate`, before pushing to Repair:
```
if (er.incarnation >= MAX_TOTAL_REPAIRS) {
    // emit deterministic abort: status = 4 (Error), zero gas, deterministic receipt
    // this is the "deterministic block-pathological-tx" outcome
}
```
The abort path must be deterministic — same input must produce the same abort across validators — which means the threshold must be enforced *and* the abort must produce a fixed receipt regardless of how many wave-ticks were consumed.

Also publish `MAX_TOTAL_REPAIRS` to consensus, because changing it is a hard fork.

**Must-fix pre-launch**: YES.

---

### Q3.0-STM-004 — Cross-backend determinism is unverified; CUDA backend lacks v0.40 DAG construction [Critical]

**Description**. LP-010 §"Correctness Invariants" #7 states:
> Cross-backend equivalence — Metal == CUDA == CPU reference for state_root, receipts_root, execution_root, mode_root, and conflict/repair behavior wherever deterministic.

Reality:
1. The CUDA backend (`quasar_wave.cu:571-587`) ships **only the v0.35 pass-through `drain_dagready`**. It has no DagWriterSlot table, no PredictedKey lookup, no parent→child edge construction. The Metal backend has full v0.40 DAG construction (`quasar_wave.metal:736-825`).
2. The CUDA `drain_commit` (`quasar_wave.cu:770-809`) does NOT walk DAG children to decrement unresolved_parents. The Metal `drain_commit` (`quasar_wave.metal:1107-1127`) does.
3. In Nebula mode (`desc->mode == 1u`), Metal builds a real DAG and uses unresolved_parents to gate emission to Exec; CUDA pass-through's antichain is just FIFO.
4. The CUDA vote verifier (`drain_vote` in `quasar_wave.cu:811-860`) uses a different signature scheme entirely (`verify_signature_stub` byte-equality check on subject vs sig) than the Metal vote-batch verifier (HMAC-keccak with master secret + chain_id binding).

**Two validators, one on Metal (Apple node) and one on CUDA (Linux x86), running the same Nebula-mode block, will produce different execution_roots** because the order in which children are released to Exec is different.

There is also no cross-backend test harness: no `cevm/test/cross_backend/...`, no CI step that runs the same block through both kernels and diff'd the roots.

**Affected**: `quasar_wave.cu:571-587`, `quasar_wave.cu:770-809`, `quasar_wave.cu:811-860`, all of vote verification, missing test harness.

**Attack scenario**. Geographically separated validators have heterogeneous GPUs (Apple silicon vs NVIDIA — explicit goal of the multi-backend design). Adversary submits a Nebula-mode block with a multi-key DAG. Apple-side validators emit DAG children in the order computed by drain_commit's child walk; CUDA-side validators emit them in FIFO order from the dagready ring. Different commit order → different keccak chain → different roots → chain split.

**Fix**.
1. Port v0.40 drain_dagready and drain_commit-with-children to CUDA. Add the same DagWriterSlot table and the same PredictedKey lookup. Same atomic and same fence semantics.
2. Port the HMAC-keccak vote verifier (matching kernel signatures must match across backends — the byte-equality stub is also a critical security bug, see Q3.0-STM-008).
3. Build a CPU reference (LP-010 v0.49 promises this — must land for 2025-12-25).
4. Add `cevm/test/cross_backend/quasar_round_diff_test.cpp` that runs the same QuasarRoundDescriptor + tx batch through Metal, CUDA, and CPU reference, asserts byte-identical roots.
5. CI must reject any commit that produces different roots across backends.

**Must-fix pre-launch**: YES — this is the difference between "GPU-accelerated chain" and "permanent fork on heterogeneous hardware."

---

### Q3.0-STM-005 — `drain_dagready` cross-workgroup race on `last_writer_tx` and `unresolved_parents` allows missed wake-ups [High]

**Description**. The Metal kernel comments above `DagWriterSlot` claim "drain_dagready is single-threaded (gid=3, tid=0), so last_writer_tx is plain (not atomic)" — but the protocol still has a real race against `drain_commit` (gid=7, tid=0) which concurrently:
- Walks `dag_nodes[c.tx_index].children` (line 1108-1124)
- Calls `atomic_fetch_sub_explicit(&C->unresolved_parents, 1u)` and re-emits child to Exec
- Stores `state = kDagNodeCommitted`

drain_dagready (gid=3) reads `dag_nodes[prev].state` (line 788), increments `T->unresolved_parents` (line 790), and *only then* checks state again at line 797. The double-check is racy:

```
1. drain_dagready reads P->state == Registered          (T1 at gid=3)
2. drain_commit transitions P → Committed and walks
   children[*]; the walk completes BEFORE drain_dagready
   has incremented T->unresolved_parents               (T2 at gid=7)
3. drain_dagready increments T->unresolved_parents      (T1)
4. drain_dagready reads P->state == Committed and 
   decrements T->unresolved_parents                     (T1)
5. T->unresolved_parents settles at 0 — correct in
   isolation, but T's state never transitioned to 
   Emitted because drain_dagready's emit-when-zero 
   check at line 814 fires only on the increment path.
```

Specifically: at line 815, `unresolved` is read after the for-loop processing all parents. If the very last parent's `state` flipped to Committed *between* line 798's check and line 814's read, but drain_commit's child-walk of that last parent had already completed (it walked children before transitioning to Committed at line 1126, but the walk is per-parent, not per-(parent, predicted-edge-key)), then drain_commit's `atomic_fetch_sub_explicit` ran on a `unresolved_parents` value that did NOT include this child's increment yet, and the "old == 1u" check at line 1118 fires on an old value that's wrong. Children can either (a) miss being re-emitted, or (b) be double-emitted (race between drain_dagready's emit-when-zero at line 814 and drain_commit's emit-when-zero at line 1120).

**Affected**: `quasar_wave.metal:736-825` (drain_dagready), `quasar_wave.metal:1107-1127` (drain_commit DAG child walk).

**Attack scenario**. Adversary submits a Nebula block with carefully timed parent/child relationships such that drain_commit's walk of P's children completes exactly when drain_dagready is processing a new child of P. Validator A's GPU schedules drain_commit slightly earlier; validator B's slightly later. Validator A re-emits the child once (correct). Validator B re-emits twice OR not at all. tx_count diverges.

**Fix**. The drain_commit child walk and the drain_dagready edge-add must be linearized. Options:
1. Move drain_commit's child-walk and state-transition into a CAS-based protocol: child increments unresolved, then drain_commit's decrement+emit only fires if it observes the increment. The current "double-check after store" pattern in drain_dagready is correct *if* drain_commit uses release semantics around `state = Committed` and a `mem_device` fence between child-walk and state-store. The kernel currently uses `memory_order_relaxed` for both state load and store. **That is the bug.**
2. Use `memory_order_release` for `state = Committed` after the child-walk, and `memory_order_acquire` for the second `state` read in drain_dagready. The C++ memory model guarantees the new edge — added before the increment — is visible to drain_commit.

In Metal, replace `memory_order_relaxed` with `memory_order_release`/`memory_order_acquire` on the `state` atomic. Same for CUDA's `__threadfence()` placement.

**Must-fix pre-launch**: YES (high). Determinism violation under Nebula mode.

---

### Q3.0-STM-006 — `predicted_keys[tx_index]` indexing assumes drain_ingress assigns sequential tx_index, but the host pre-fills before GPU consumes [High]

**Description**. The host driver (`quasar_gpu_engine.mm:276-291`) writes:
```cpp
const uint32_t tidx = round_.next_predicted_idx;
if (tidx < kDagNodeCapacity) {
    PredictedKeyHost* slot = &predicted_arena[tidx * kMaxPredictedKeys];
    ...
}
round_.next_predicted_idx += 1u;
```

This assumes `tx_index_seq` on the GPU side will exactly match `next_predicted_idx` on the host side. The GPU assigns `tx_index = atomic_fetch_add(tx_index_seq, 1)` in drain_ingress (`quasar_wave.metal:527`). drain_ingress runs single-threaded on `gid=0`, FIFO over Ingress, so the assignment IS deterministic FIFO — but only as long as:

1. The host pushes txs in the same order as it pre-fills `predicted_keys`.
2. No tx is dropped at admission (e.g., decode failure routes back to `(void)ring_try_push(ingress_hdr, ...)` on overflow).
3. Across multiple `push_txs(...)` calls, no other writer pre-fills predicted_keys at indices the host hasn't reserved yet.

Concrete failure: on lines 535-538 of drain_ingress, if `ring_try_push(decode_hdr, ...)` fails (decode ring full), the pop'd tx is requeued to Ingress with `(void)ring_try_push(ingress_hdr, ingress_items, in)`. **But the `tx_index` was already consumed by `atomic_fetch_add(tx_index_seq, 1)` at line 527.** On the next tick that same tx pops back, gets a *new* tx_index, and the slot at the old tx_index is `predicted_keys` indexed by the old (orphaned) value. The slot at the *new* tx_index belongs to a different tx that hasn't been pushed yet — so `predicted_keys[new_tx_index]` reads zeroed data. The DAG misses the predicted dependency.

Also: if `push_txs` is called multiple times within a round, `next_predicted_idx` increments host-side per tx pushed, but if the *first* push's drain_ingress fails the decode push (some txs successfully decoded, some requeued), the host side believes tx_index=0..N-1 has the predicted_access for txs 0..N-1, but the GPU's tx_index_seq is at 0..N-K (some requeued, will get index N..N+K-1 next round). The mapping is broken.

**Affected**: `quasar_gpu_engine.mm:276-291`, `quasar_wave.metal:527, 535-538`.

**Attack scenario**. Adversary spam-fills the decode ring in early ticks so drain_ingress requeues txs. The orphaned tx_indexes leave gaps in tx_index space; predicted_access lookup misses real edges; DAG construction omits dependencies; downstream Block-STM detects the conflict and forces repairs OR worse, commits in the wrong order. Different validators hit the requeue at different ticks → different tx_index assignments → different DAG → different roots.

**Fix**. Either:
1. Move `tx_index_seq` increment to *after* successful decode push, not before. (Cleanest.)
2. Index predicted_keys by a stable key (origin || nonce) rather than tx_index.
3. Use a per-round content-addressed predicted_access lookup (hash of tx envelope → predicted_keys offset).

Option 1 is the smallest change.

**Must-fix pre-launch**: YES (high). Causes Nebula determinism violation under any backpressure.

---

### Q3.0-STM-007 — `drain_vote` reads `vote_verified[head_pre & mask]` AFTER popping; race with verifier produces accept-tampered-vote [High]

**Description**. The Metal `drain_vote` (line 1148-1187) reads:
```
uint head_pre = atomic_load_explicit(&vote_hdr->head, memory_order_relaxed);
VoteIngress v;
if (!ring_try_pop(vote_hdr, vote_items, v)) break;
uint vidx = head_pre & (vote_verified_capacity - 1u);
if (vote_verified[vidx] == 0u) { ++processed; continue; }
```

Two issues:
1. `head_pre` is read *before* `ring_try_pop` advances head. ring_try_pop loops on CAS — if multiple drain_vote workgroups raced, the `head_pre` here might NOT match the slot that was actually popped. (In current dispatch, `gid=10` runs single-threaded with `tid==0`, so this works in v0.38 — but it is fragile and assumes the dispatcher never schedules two threads on gid=10.)
2. The vote_verified bitmap is written by `quasar_verify_votes_kernel` BEFORE the wave-tick scheduler runs (line 437-448 in `quasar_gpu_engine.mm` — separate encoder, ordered within one MTLCommandBuffer). The verifier writes verified[slot_idx] = 1 if signature matches. **But the wave-tick scheduler also runs `drain_ingress` which advances tx_index_seq, and inside the same dispatch can call `drain_vote` against a vote_verified bitmap computed for the previous tail — meaning a vote pushed *during this run_epoch* is popped without ever being verified.** Specifically: host pushes vote V at tail=T. The verifier ran at tail<T, so vote_verified[T mask] is stale (might be 0 from initialization, OR might be 1 from a stale match for a previous vote at the same slot).

Combined, the bitmap can return either:
- 0 → vote rejected (best-case false negative, denies vote even though sig is valid)
- 1 → vote accepted (worst-case false positive: stale verified=1 from a previous round/vote at the same slot causes a tampered/replayed vote to count for stake)

**Affected**: `quasar_wave.metal:1148-1154`, `quasar_gpu_engine.mm:430-475`.

**Attack scenario**. Adversary controls a validator account with low stake. Adversary submits two consecutive rounds. Round N: legitimate vote at slot S, verified=1. Round N+1: adversary submits a forged vote (different validator, different signature) at slot S' where S' & mask == S & mask. If the host doesn't memset vote_verified between rounds (`begin_round` does memset at line 212, so this specific case is safe per-round), or if the same round has high vote churn (legitimate vote at slot S; verifier marks verified[S]=1; vote consumed; *new* vote pushed at slot S+capacity which masks to S; verifier hasn't run yet so verified[S]=1 from before but now refers to a different vote), the forged vote is accepted. Stake count diverges between validators with different scheduling. Quorum certificate emission depends on stake counts. Two validators emit different certs. Worse: a malicious validator can use this to inflate own stake via cross-round bitmap pollution.

**Affected**: `quasar_wave.metal:1148-1187`.

**Fix**. The vote-verified bitmap must be (a) sized larger than the ring (to avoid mask collisions across in-flight votes), (b) cleared between verifier runs OR the verifier must run after every push, (c) keyed by a content hash of the vote rather than slot index, and (d) the verifier and consumer must be ordered against any new vote arrivals via the same ring's pushed counter.

Cleanest: re-run the verifier inline as part of drain_vote — verify the signature there and skip the bitmap entirely. The bitmap is a premature optimization that introduces a TOCTOU.

**Must-fix pre-launch**: YES — quorum integrity is a chain-safety primitive.

---

### Q3.0-STM-008 — CUDA `verify_signature_stub` is byte-equality (sig == subject); accepts any signature where signature[0..32] == subject [High]

**Description**. CUDA `quasar_wave.cu:811-817`:
```
__device__ __forceinline__ bool verify_signature_stub(const uint8_t* subject, const uint8_t* sig)
{
    for (uint32_t i = 0u; i < 32u; ++i) {
        if (sig[i] != subject[i]) return false;
    }
    return true;
}
```

This accepts any vote where `signature[0..32] == subject[0..32]`. An attacker who knows the subject (it's the block_hash, broadcast to all validators) can construct a "signature" by literally copying subject into the first 32 bytes of the signature field. Result: anyone can forge votes for any validator on the CUDA backend.

The Metal backend uses `quasar_verify_votes_kernel` with HMAC-keccak against a `kQuasarMasterSecret` — also broken (the master secret is hardcoded in the kernel source and is therefore public, see Q3.0-STM-009), but at least it's not a one-line equality check.

**Affected**: `quasar_wave.cu:811-817`.

**Attack scenario**. CUDA validator. Adversary observes block_hash via the network (this is broadcast). Constructs a vote message with `signature[0..32] = block_hash[0..32]`, any garbage in `[32..96]`, any validator_index, any stake_weight. drain_vote accepts the vote, accumulates stake_weight, emits a QuorumCert for that lane at quorum threshold. **Adversary controls all three lanes (BLS / Ringtail / MLDSA) trivially.**

**Fix**. The CUDA verifier must implement the same HMAC-keccak path as Metal (still broken, see next finding). Long-term: real BLS12-381 / Ringtail / ML-DSA verifiers must be CUDA-ported too.

**Must-fix pre-launch**: YES — this is a one-line attack to forge consensus signatures on CUDA validators.

---

### Q3.0-STM-009 — `kQuasarMasterSecret` is a hardcoded constant in the kernel source; HMAC-keccak verifier provides zero security [High]

**Description**. `quasar_wave.metal:1212-1215`:
```
constant uchar kQuasarMasterSecret[32] = {
    0x51,0x55,0x41,0x53,0x41,0x52,0x2D,0x76,0x30,0x33,0x38,0x2D,0x6D,0x61,0x73,0x74,
    0x65,0x72,0x2D,0x73,0x65,0x63,0x72,0x65,0x74,0x2D,0x73,0x68,0x61,0x72,0x65,0x64,
};
```
ASCII: `"QUASAR-v038-master-secret-shared"`.

This constant is in the kernel source, the LP, and presumably the binary. The "verification" `verified[slot_idx] = (HMAC(kQuasarMasterSecret, validator_index||subject||round) == signature)` is therefore:

> "anyone with access to the kernel source can compute the expected signature for any (validator, subject, round)."

The kernel source is open source (Apache-2.0 per the file header). **The signature verifier rejects honest validators who use real BLS signatures and accepts attackers who compute the HMAC-keccak.**

The LP-132 documentation acknowledges this is a placeholder for v0.43+, but the launch is 2025-12-25 and the LP's roadmap shows real BLS at "v0.43" with no commitment to real Ringtail (v0.44) or Groth16 (v0.45) by launch.

**Affected**: `quasar_wave.metal:1212-1290`, `quasar_gpu_engine.mm:430-448` (verify_pso_), `quasar_wave.cu:811-860`.

**Attack scenario**. Adversary clones the repo, reads the master secret, computes valid signatures for every validator, posts votes for every lane → controls all quorums. Cost: zero.

**Fix**. The launch MUST ship real BLS12-381 pairing for the BLS lane (LP-075), real Ringtail share verification for the RT lane (LP-073), and real ML-DSA-65 (LP-070) for the MLDSA lane. Anything less is a ceremonial signature. If real BLS is not ready by 2025-12-25, the launch must NOT enable on-chain quorum aggregation in QuasarGPU — fall back to host-side verification using vetted libraries (`luxfi/crypto`).

**Must-fix pre-launch**: YES — without this, consensus is theater.

---

### Q3.0-STM-010 — Closing-gate `commit_consumed == ingress_pushed` doesn't account for txs in-flight in StateRequest, Decode, Crypto, etc. [Medium]

**Description**. The finalization gate (`quasar_wave.metal:1389-1414`):
```
if (gid == 0u && desc->closing_flag != 0u) {
    const uint ingress_pushed = atomic_load_explicit(&hdrs[0].pushed);
    const uint commit_consumed = atomic_load_explicit(&hdrs[7].consumed);
    if (ingress_pushed == commit_consumed) {
        // ... compute block_hash, set status=1 (finalized) ...
    }
}
```

The gate compares `ingress.pushed` against `commit.consumed`. But a tx that goes Ingress → Decode → StateRequest (cold-state) and is awaiting a host StatePage will have:
- ingress.pushed = N (incremented on push)
- commit.consumed = N-1 (this tx hasn't committed)

This is the intended behavior — the round won't finalize until all txs commit. Good.

However: `drain_decode` increments `fibers_suspended` when routing a tx to StateRequest, and `drain_state_resp` re-injects via `crypto_hdr` (line 1057) — where it re-enters `drain_crypto`. **drain_crypto increments `processed` but NOT `pushed` on Ingress.** So ingress.pushed stays at N (correct — the tx was originally ingressed). But what if `push_txs` is called again *during* a round to add a new tx after closing_flag was set? The host drives `request_close()` setting closing_flag, but `push_txs` is not gated against closing — line 242-298 of `quasar_gpu_engine.mm` doesn't check `closing_flag`. The host can push txs after setting closing_flag, ingress.pushed grows, the gate doesn't fire on the next tick (correct), but tx ordering is now nondeterministic if two validators differ in when their host pushes the late tx.

**Affected**: `quasar_gpu_engine.mm:242-298` (push_txs missing closing_flag guard), `quasar_wave.metal:1389-1414` (gate).

**Attack scenario**. Two validators receive the same block. Validator A's `request_close()` and `push_txs()` happen in order A; validator B's happen in order B with race. The late-pushed tx ends up in different positions in the canonical order across validators. Roots diverge.

**Fix**. `push_txs` must reject pushes after `closing_flag` is set, returning a deterministic error to the host. The host must validate tx_count against the round descriptor's expected count before calling `request_close()`.

**Must-fix pre-launch**: YES (medium-rising-to-high). Fix is two lines.

---

### Q3.0-STM-011 — `state_root` is never written by any drain; `block_hash` includes uninitialized state_root [Medium]

**Description**. The finalization gate computes:
```
block_hash = keccak(round || mode || receipts_root || execution_root || state_root || mode_root)
```
But `state_root` is never written by any drain. The kernel uses `result->state_root[k]` at line 1404 — read-only. Grep for `state_root[` writes: only the line 1404 read.

`begin_round` `memset`s `result_buf` to zero at line 205, so state_root is all-zero on every round. The block_hash on every round includes the constant 32-zero-bytes for state_root, regardless of what state was actually mutated. This is deterministic across runs (good for the determinism test), but it **provides no commitment to the actual MVCC state**. Two distinct executions producing the same receipts/execution traces but different actual state commit to the same block_hash.

This is the definition of a "ceremony hash" — the block_hash binds nothing about state.

**Affected**: `quasar_wave.metal:1404`, all drains (no writer).

**Attack scenario**. Adversary submits block X. Honest validators execute it, producing some MVCC state. Adversary then constructs a block Y that produces the same receipts (same external observations) but different MVCC state. **Both produce the same block_hash.** State machines fork silently on internal state; later txs depending on state diverge between A and B, but block_hash equality means the consensus engine sees no fork.

**Fix**. After the validate-commit pipeline drains, run a `drain_state_root` workgroup (or extend drain_commit) that computes:
```
state_root = keccak(running_state_root || (key_lo || key_hi || version || last_writer_tx)_in_canonical_order)
```
The canonical order MUST be by `(tx_index, incarnation)` of the committing tx — which is exactly what's available in CommitItem. Or: maintain a Merkle-style accumulator over MVCC slot deltas as drain_commit fires.

Note that the LP-010 §"Three-Tier Validation" and §"MVCC Garbage Collection" promise this — it's just not implemented.

**Must-fix pre-launch**: YES (medium). The block_hash without a real state_root is not a usable consensus commitment.

---

### Q3.0-STM-012 — Cold-state suspend/resume race: re-injected fiber may run with stale "loaded sentinel" [Medium]

**Description**. LP-132 §"Async cold-state page faults" describes the loaded sentinel:
> drain_state_resp resumes by re-injecting and stamping the MVCC slot's `last_writer_tx |= 0x80000000` as the "loaded" sentinel.

In code: `drain_state_resp` at `quasar_wave.metal:1041-1065` re-injects via crypto_hdr but does NOT touch the MVCC slot's `last_writer_tx`. The "loaded sentinel" stamping is documented in LP-132 but not implemented. Without it:

1. tx T1 reads cold key K, suspends → StateRequest emitted.
2. Host services StateRequest, posts StatePage.
3. drain_state_resp re-injects T1 via crypto_hdr → drain_crypto → drain_exec.
4. drain_exec calls `mvcc_locate(K)` which finds the slot empty (because no tx has written K yet on the GPU side), claims it via the racy logic in Q3.0-STM-002, reads `version=0`, builds RW set with `version_seen=0`.
5. tx T2 with same K already executed in steps 2-3 (because drain_exec doesn't block on T1), wrote version=1.
6. T1's validate fails (cur=1, version_seen=0), repair, re-exec. **But T1's host page data is gone — it was a one-shot StatePage.**

The kernel will spin on T1: every repair re-exec finds version mismatch, T1 never sees the actual loaded data because the StatePage payload isn't preserved across repairs. Without the loaded sentinel pinning T1's first execution to commit before T2, T1 starves.

Worse: two concurrent host StatePages for the same tx_index (e.g., kernel emitted two StateRequests for two different cold keys for the same tx) — the kernel does not coalesce them. drain_state_resp re-injects on every page received, so a tx that needs two cold pages will be re-injected twice into crypto_hdr → executed twice → double-counted in drain_commit → tx_count over by one.

**Affected**: `quasar_wave.metal:1041-1065` (drain_state_resp), `quasar_wave.metal:891-945` (drain_exec — no per-tx pending state machine), `quasar_gpu_engine.mm:359-390` (push_state_pages allows multiple per tx).

**Attack scenario**. Adversary submits txs that touch multiple cold keys (force multiple StateRequests per tx) AND target hot lanes (for repairs). Validator A's host serves pages in order P1, P2; validator B in order P2, P1. Different re-injection orders → different tx_index ordering at validate → different roots.

**Fix**.
1. Implement the loaded sentinel: in drain_state_resp, before re-injecting, stamp `mvcc_table[K].last_writer_tx |= 0x80000000` (or use a separate per-slot loaded flag with the high bit reserved). drain_validate must respect this sentinel and pin the resumed tx's commit to happen before any other writer of K.
2. Coalesce multiple StatePage arrivals per tx_index into a single re-injection. Track per-tx pending_count in FiberSlot; only re-inject when pending_count reaches zero.
3. Clear the loaded sentinel on commit, never on repair.

**Must-fix pre-launch**: YES (medium-rising-to-high under cold-state-heavy workloads).

---

### Q3.0-STM-013 — `drain_exec`'s synthetic exec_key uses `origin_lo, origin_hi & ~kFlagMask` — adversarial origins force MVCC slot collisions [Medium]

**Description**. `drain_exec` derives the per-tx exec_key from:
```
ulong key_lo = ulong(v.origin_lo);
ulong key_hi = ulong(v.origin_hi & ~kFlagMask);
if (key_lo == 0UL && key_hi == 0UL) key_lo = 1UL;
```

Two issues:
1. Two different origins differing only in the top 2 bits (`kFlagMask = 0xC0000000`) produce **identical** exec_keys. The flag bits are consumed; the rest is the key.
2. The "never empty" remap to `key_lo=1` means every tx with origin=0 collides on the slot for key=(1, 0).

**Affected**: `quasar_wave.metal:902-905`, `quasar_wave.cu:627-629`.

**Attack scenario**. Adversary submits 1024 transactions all with `origin = 0` and `origin_hi = 0xC0000000` (both flag bits set). All have exec_key = (1, 0). All hit the same MVCC slot. Block-STM repair amplification = O(N²). Combined with Q3.0-STM-003 (no repair bound), the round never finalizes.

**Fix**.
1. Hash the origin (full 64 bits, no flag mask) plus tx_index into a real 128-bit key.
2. Reserve a flag region in `last_writer_tx` instead of co-opting origin_hi bits.

**Must-fix pre-launch**: SHOULD be fixed — but if not, must be paired with Q3.0-STM-003's repair bound to prevent DoS.

---

### Q3.0-STM-014 — Repair path discards `er.incarnation` on requeue and resets `tx_index_seq` is not reset between rounds in tests [Medium]

**Description**. `drain_repair` (`quasar_wave.metal:1013-1039`):
```
for (uint i = 0u; i < budget; ++i) {
    ExecResult er;
    if (!ring_try_pop(repair_hdr, repair_items, er)) break;
    VerifiedTx v;
    v.tx_index  = er.tx_index;
    v.admission = 0u;
    v.gas_limit = er.gas_used;
    ...
    if (!ring_try_push(exec_hdr, exec_items, v)) {
```
The incarnation that `drain_validate` bumped (`er.incarnation += 1u` at line 969) is passed to `drain_repair`, but drain_repair packs only `tx_index, admission, gas_limit, origin_lo, origin_hi` into VerifiedTx — **dropping the incarnation**. On the next exec, drain_exec writes `er.incarnation = 0u` (line 909). The incarnation counter resets on every repair cycle.

This means LP-010 §"Repair monotonicity" ("each repair increments incarnation; invalid incarnations cannot commit") cannot be enforced because the kernel doesn't carry incarnation through the round-trip. A validator that wanted to enforce `MAX_TOTAL_REPAIRS` (Q3.0-STM-003) couldn't even count repairs per tx.

**Affected**: `quasar_wave.metal:1023-1029`, `quasar_wave.cu:723-729` (same bug). `drain_exec` line 909 (Metal) / 633 (CUDA) reset incarnation.

**Fix**. VerifiedTx layout needs an `incarnation` field, OR Repair → Exec must travel through a different envelope (RepairTx with full ExecResult including incarnation), OR incarnation must be stored per tx_index in a side table (FiberSlot already has the field but it's unused).

The FiberSlot has incarnation at offset 32 (`uint incarnation` in the FiberSlot struct, line 261 in metal). drain_exec writes 0 there because FiberSlots are never indexed. Use the FiberSlot table: drain_validate increments `fibers[tx_index].incarnation`; drain_exec reads it.

**Must-fix pre-launch**: YES (medium) — without this, Q3.0-STM-003 is unfixable.

---

### Q3.0-STM-015 — `keccak256_thread`/`keccak256_local` final-block padding works at boundaries; verified — but uses LITTLE-ENDIAN lane absorption which differs from Ethereum keccak (which is also little-endian, so this is correct) [Informational]

**Description**. I traced `keccak256` in both backends carefully against FIPS 202 + Ethereum's keccak (the pre-NIST keccak with padding `0x01 ... 0x80` in little-endian byte ordering). Both backends absorb lanes via:
```
s[lane] ^= ulong(data[i]) << (i % 8u * 8u);
```
which is little-endian byte-to-lane mapping. This is the Ethereum convention. Cross-checked against `pyethereum/keccak.py`. This is correct, BUT it must be cross-checked against any CPU reference implementation used elsewhere in luxcpp (e.g., `lib/evm/state/processor.cpp`). If the CPU reference uses the NIST SHA-3 byte-ordering (different padding: `0x06 ... 0x80`), the GPU keccak will diverge from CPU.

The `keccak256` implementations in Metal and CUDA agree byte-for-byte. **No determinism risk between Metal and CUDA from keccak.**

**Affected**: N/A — verified correct.

**Recommendation**. Add a unit test that hashes a fixed input through Metal keccak, CUDA keccak, and the CPU `crypto::keccak256` used by the rest of cevm. Assert byte-identical output.

**Must-fix pre-launch**: NO — but the cross-impl test SHOULD land for confidence.

---

### Q3.0-STM-016 — Ring requeue on push-fail uses `ring_try_push(self_hdr, ...)` which goes to the TAIL; out-of-order ring rotation [Low]

**Description**. When `drain_validate` fails to push to commit (line 1002):
```
(void)ring_try_push(validate_hdr, validate_items, er);
```
This pushes the failed tx to the *tail* of the validate ring. Subsequent pops will see other items first, then this one. This means the `er` whose MVCC was already mutated (Q3.0-STM-001) lands behind newer execrequests in the same tick. The order ExecResult items were popped is NOT preserved.

Combined with Q3.0-STM-001, this means the order of validate pop on the next tick is timing-dependent.

**Affected**: lines 938-940 (drain_exec), 970-972 (drain_validate to repair), 1001-1002 (drain_validate to commit), 1031-1033 (drain_repair), 1056-1059 (drain_state_resp). Same pattern in CUDA backend.

**Fix**. Don't requeue to tail. Either:
1. Stop popping when downstream is full (already partially done — `break` on push fail). The pop'd item is then lost. Need to NOT pop until downstream has space.
2. Use a peek-first-then-pop pattern: query the downstream ring's free space, only pop if there's space.

The cleanest approach: peek tail-vs-head before popping. Standard SPSC ring pattern.

**Must-fix pre-launch**: NO (low). Doesn't directly cause divergence (the tx is still in the ring), but interacts badly with Q3.0-STM-001 and adds confusion.

---

## Cross-Cutting Architectural Concerns

### LP-vs-Implementation Gap
LP-010 specifies a 3-tier validation pipeline (lane clocks, MVCC, semantic reducers), commit horizons, lane refraction, deterministic contention manager, hard livelock limits, and multi-GPU sharding. **None of these are implemented.** The kernel ships flat MVCC + repair-only + finalization-on-empty. Calling this Block-STM 3.0 in production by 2025-12-25 is misleading.

The LP itself blurs this — §"Implementation Plan" lists 3.0 features at v0.42-v0.49, with v0.49 being "Formal CPU reference (4.0)". Per the LP, this is post-launch work. **But the LP's "Correctness Invariants" §1-7 are stated as MUST hold for 3.0.** They cannot hold without the implementation.

**Recommendation**: Either rename the launch artifact to "QuasarSTM 2.5 / GPU Block-STM" and ship it honestly, OR delay launch until v0.45+. Don't ship v0.40 calling itself 3.0.

### Forbidden Patterns Audit
LP-010 §"Forbidden Patterns" says QuasarSTM must not use:
- one global STM clock — N/A (not used)
- one global version map lock — N/A
- retry-until-success GPU loops — VIOLATED at `ring_try_pop` (Metal line 298-311, CUDA line 268-281). The CAS loop is unbounded in principle. In practice it terminates because there are finitely many concurrent threads, but the pattern is exactly what the LP forbids.
- nondeterministic conflict victim choice — VIOLATED via Q3.0-STM-001 (timing decides who repairs)
- opcode-level STM — N/A (it's tx-level, correct)
- CPU conflict manager — partially violated via host's `max_epochs` choice (Q3.0-STM-003)
- host-side repair scheduler — N/A
- per-version `malloc` — N/A (uses arena)
- global hot-key spinlocks — N/A

**Two of nine forbidden patterns are present** in the v0.40 kernel.

---

## Blue Handoff

### What Blue got right
- The LP architecture (3-tier validation, lane refraction, commit horizons, semantic reducers) is solid and reflects current research. The mistake is shipping before implementing it.
- Wave-tick scheduler with bounded budgets — correct anti-livelock approach at the dispatch layer (kernel exits, GPU yields).
- `RingHeader` layout and the relaxed-atomic + `mem_device` fence pattern is correct *if applied with proper memory ordering* (it isn't — see Q3.0-STM-005).
- Inline keccak verified correct, byte-identical between Metal and CUDA.
- `static_assert` on layout sizes catches host/device drift.
- Basic determinism test (`test_root_determinism`) exists and passes for the trivial 16-tx case.

### What Blue missed
- No cross-backend determinism test harness.
- No CPU reference for differential fuzzing (LP-010 v0.49 promises this; not landed).
- No adversarial workload tests (1024 same-key txs, hash-collision keys, multi-cold-page txs, push-during-close).
- No real signature verification on the consensus path — both backends ship placeholder verifiers that are trivially forgeable.
- No state_root computation — block_hash is uncorrelated with state.
- No anti-livelock enforcement despite the LP marking it "mandatory on GPU."

### Fix priority for Blue (ordered)
1. **Q3.0-STM-008** — CUDA verify_signature_stub. One-line forgery. Replace with the same HMAC-keccak path as Metal, OR (preferred) gate the round-finalization on host-side signature verification using `luxfi/crypto`.
2. **Q3.0-STM-009** — hardcoded master secret. Rip out the HMAC-keccak verifier entirely; either ship real BLS/Ringtail/MLDSA by 2025-12-25 or defer GPU vote aggregation and run host-side signature verification.
3. **Q3.0-STM-001** — commit-ring backpressure. Refactor `drain_validate` so the MVCC mutation is contingent on commit-push success.
4. **Q3.0-STM-002** — non-atomic key claim in mvcc_locate. Use atomic CAS on a sentinel field with proper memory ordering.
5. **Q3.0-STM-004** — port v0.40 DAG to CUDA; build cross-backend test harness; add CPU reference.
6. **Q3.0-STM-003** + **Q3.0-STM-014** — implement repair monotonicity (incarnation in FiberSlot) and enforce MAX_TOTAL_REPAIRS with deterministic abort.
7. **Q3.0-STM-005** — fix memory-order on DAG state atomics (release/acquire instead of relaxed).
8. **Q3.0-STM-006** — move tx_index_seq increment after decode-push success.
9. **Q3.0-STM-007** — eliminate the vote_verified bitmap; verify inline in drain_vote.
10. **Q3.0-STM-011** — implement state_root accumulation.
11. **Q3.0-STM-010** — gate push_txs on closing_flag.
12. **Q3.0-STM-012** — implement loaded sentinel; coalesce multi-page suspends.
13. **Q3.0-STM-013** — replace synthetic exec_key derivation with hash of full origin.
14. **Q3.0-STM-016** — peek-then-pop ring pattern.
15. **Q3.0-STM-015** — add cross-impl keccak test (informational).

### Re-review scope
Re-test required after fixes for:
- Cross-backend determinism harness (Metal vs CUDA vs CPU reference) — full 19-binary GPU test surface plus new adversarial workloads (1024 same-key, FNV-collision keys, multi-cold-page, push-during-close, race-during-DAG).
- Repair-bounded-abort behavior (1024 same-key + bounded MAX_TOTAL_REPAIRS = deterministic block rejection).
- State_root accumulation produces stable digest under reordered execution within Block-STM constraints.
- Real signature verifiers in all three lanes — must use `luxfi/crypto` and reject the test suite's HMAC-keccak forgeries.

---

## Recommendation

**do-not-ship** as Block-STM 3.0 by 2025-12-25.

The v0.40 substrate can ship as **QuasarSTM 2.5 / GPU Block-STM** (honest naming) once the must-fix-pre-launch items above are addressed. The LP-010 3.0 features (lanes, three-tier validation, commit horizons, deterministic contention manager) are real engineering work — months, not weeks — and shipping a kernel that lacks them while claiming the 3.0 invariants is a credibility risk and an attack surface.

Critical & high findings (Q3.0-STM-001, 002, 003, 004, 005, 006, 007, 008, 009) **MUST land before any mainnet round.** They are all bounded local fixes; none requires the 3.0 rewrite. Estimated total work: 2-3 weeks if focused, plus one week for cross-backend test harness and one week for differential fuzzing against a CPU reference.

If those land and pass cross-backend determinism on the adversarial workload suite, this can ship — but as 2.5, not 3.0.

---

RED COMPLETE. Findings recorded.
Total: 4 critical, 5 high, 4 medium, 3 low/informational

Top 3 for Blue to fix:
1. Q3.0-STM-008 — CUDA byte-equality "verifier" forges any signature trivially
2. Q3.0-STM-001 — commit-ring backpressure produces nondeterministic repair counts → root divergence
3. Q3.0-STM-002 — non-atomic MVCC key claim allows torn reads + double-claim → root divergence

Re-review needed: yes — cross-backend determinism harness + adversarial workload suite + real signature verifiers
Recommendation: do-not-ship as 3.0; ship as 2.5 after the 9 critical+high items land
