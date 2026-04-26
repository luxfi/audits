# Quasar 3.0 Cert-Lane — Red-Team Adversarial Review

| Field | Value |
|---|---|
| Reviewer | Red (Adversarial Security Researcher) |
| Date | 2026-04-26 |
| Target version | LP-020 v3.0 (2026-04-26) + LP-132 v0.38 substrate + LP-134 v3.1 chain topology |
| Activation height | 2025-12-25 chain activation (the production cutover) |
| Threat model | Network adversary, can replay/splice, cannot break BLS12-381 / Module-LWE / Module-SIS, controls `< τ = 2/3` of `pchain_validator_root` stake |

## Executive summary

The 3.0 spec is sound on paper — the P/Q/Z root-binding cert subject is a real cross-epoch / cross-chain replay defense, and the lane indirection is forwards-extensible without breaking ABI. **The implementation, however, does not match the spec yet.** The v0.38 substrate that the 2025-12-25 chain activation will run is built on:

1. A symmetric `keccak256(secret || subject || round)` MAC with a **publicly-checked-in master secret** (`kQuasarMasterSecret = "QUASAR-v038-master-secret-shared"`).
2. The old 2.0 `VoteIngress` (96-byte inline sig, no offset/len indirection).
3. A `subject` constructed from `block_hash || receipts_root || execution_root || state_root || mode_root` only — **no `chain_id`, no `epoch`, no P/Q/Z roots.**
4. A 32-bit `quorum_stake_*` counter on `QuasarRoundResult`, fed by `atomic_fetch_add` of host-supplied `stake_weight` with no per-validator dedup.

These four facts together make every cert-lane defense the LP claims **fail in practice**. Shipping the v0.38 substrate to the 2025-12-25 mainnet activation is a do-not-ship event regardless of the LP text.

| Severity | Count |
|---|---|
| Critical | 6 |
| High | 7 |
| Medium | 6 |
| Low | 4 |
| Informational | 3 |
| **Total** | **26** |

**Must-fix-pre-launch** (block 2025-12-25):
- Q3.0-CERT-001 — master secret in source tree
- Q3.0-CERT-002 — universal forgery via kQuasarMasterSecret
- Q3.0-CERT-003 — cross-epoch / cross-round subject under-binding
- Q3.0-CERT-004 — no per-validator dedup → single validator drives quorum
- Q3.0-CERT-007 — `quorum_stake_*` is uint32 with overflow→quorum risk
- Q3.0-CERT-008 — `head + tid` overflow / OOB read in verify kernel
- Q3.0-CERT-009 — `verified[slot_idx]` indexed by slot, indexed back by `tid` in `drain_vote` — desync admits unverified votes
- Q3.0-CERT-010 — descriptor missing `chain_id` from subject and `epoch` field entirely

The remaining findings include cross-lane replay (the test in LP-132 demonstrates that flipping `sig_kind` after MAC binding rejects, but the MAC itself uses `chain_id` instead of `epoch+chain_id`, and lane-tag is only bound via the secret derivation — see Q3.0-CERT-005), payload-arena out-of-bounds (Q3.0-CERT-014, indirection not yet implemented but spec leaves the bounds check unspecified), Q-Chain ceremony stalling (Q3.0-CERT-018), A-Chain attestation root unverified-trust-root (Q3.0-CERT-021), and validator-subset stake concentration on M/F-Chains (Q3.0-CERT-022).

---

## Architectural concern: HMAC-keccak placeholder vs real verifiers

LP-132 §drain_cert_lane v0.38 ships HMAC-keccak with `kQuasarMasterSecret` as a placeholder for BLS pairing / Ringtail / Groth16. The roadmap promises real cryptographic verifiers in v0.43..v0.45.

**This is unacceptable for the 2025-12-25 activation.** The placeholder differs from the real schemes in three load-bearing ways:

1. **Symmetric, not asymmetric.** A symmetric MAC means every node that can verify can also forge. There is no notion of a validator-specific signing key — every validator's "signature" is a deterministic function of `(sig_kind, chain_id, validator_index)` and the shared master secret. Anyone holding the master secret (i.e. anyone running `luxd`) can sign any vote as any validator.
2. **Master secret is in source.** `kQuasarMasterSecret[32] = ASCII("QUASAR-v038-master-secret-shared")`. The bytes are literally the ASCII of that phrase. This is in `quasar_wave.metal:1212-1215` and `quasar_sig.hpp:45-48`. There is no derivation, no per-deployment salt, no IAM/KMS provisioning. Cloning the public repo provides full forgery capability.
3. **No epoch / chain-id replay binding in the verified message.** The HMAC binds `(domain, chain_id, validator_index, master_secret) → secret`, then `(secret, subject, round) → sig`. `subject` here is the GPU-computed block hash — it does NOT contain epoch, P/Q/Z chain roots, or any of the protections LP-020 §3.0 promises.

If the LP text protections matter — and they do; cross-epoch replay is a real attack on BFT consensus — then the implementation must land before activation. Otherwise the chain ships with the LP's threat model violated by construction.

**Recommendation: shipping the 2025-12-25 chain activation requires either (a) real BLS/Ringtail/Groth16 verifiers (v0.43+v0.44+v0.45 collapsed into v0.38a), or (b) a substrate that hard-rejects all cert-lane traffic and runs only the BLS classical lane via the existing luxfi/consensus Go path.** Option (b) is achievable in days; option (a) is the proper fix and what the LP claims is the launch state.

---

## Detailed findings

### Q3.0-CERT-001 — Master-secret committed to public source tree

**Severity**: Critical
**Affected files**:
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1212-1215`
- `cevm/lib/consensus/quasar/gpu/quasar_sig.hpp:45-48`

**Description**: The substrate computes per-validator "secret" keys from a 32-byte constant `kQuasarMasterSecret`. The bytes ASCII-decode to `"QUASAR-v038-master-secret-shared"`. The file is checked into `~/work/luxcpp` and visible to anyone with read access to the repository. There is no override path, no environment variable, no KMS provisioning hook.

**Attack scenario**:
1. Adversary clones `luxcpp` (or reads the published LP-132 reference implementation).
2. Adversary extracts the 32-byte `kQuasarMasterSecret` constant from `quasar_wave.metal:1212`.
3. For any target `(sig_kind, chain_id, validator_index, round, subject)`, adversary computes `secret = keccak256(domain[16] || chain_id_le8 || validator_le4 || master_secret_le32)` then `sig[0..32] = keccak256(secret || subject[32] || round_le4)`. This is exactly the verifier's expected output.
4. Adversary submits this as a `HostVote` from any validator they choose — including ones whose actual stake exceeds 1/3.

**Impact**: Universal forgery of any validator's vote on any lane. With 2/3+1 forged stake the adversary finalizes any block they choose. This is the entire chain.

**Fix**: Delete the master-secret path entirely and ship real BLS / Ringtail / Groth16 verifiers (LP-132 v0.43..v0.45). If a placeholder is unavoidable for testnet, the master secret must be (a) per-validator, (b) provisioned via KMS only, (c) gated by a `LUX_DEV_MODE=1` environment guard that is rejected on mainnet.

**Must-fix pre-launch**: Yes, blocks 2025-12-25.

---

### Q3.0-CERT-002 — Symmetric MAC where asymmetric signature is required

**Severity**: Critical
**Affected files**:
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1217-1290` (`quasar_derive_secret`, `quasar_expected_sig`, `quasar_verify_votes_kernel`)
- `cevm/lib/consensus/quasar/gpu/quasar_sig.hpp:60-95` (`derive_secret`, `sign`)

**Description**: The verifier and the signer share the same key material. A "signature" is `keccak256(secret_i || subject || round)` where `secret_i = keccak256(domain || chain_id || validator_i || master)`. This is a symmetric MAC. Every node that can verify can also sign. The LP claims this is "real cryptographic verification (one-way with a master secret; cross-lane domain tags reject replay)" — that is incorrect: one-wayness of keccak protects the master secret only, not against forgery by anyone holding the master secret.

**Attack scenario**: same as CERT-001.

**Impact**: There is no validator authentication. The LP's claim that an adversary "must break ALL THREE assumptions simultaneously" (BLS DLOG + Module-LWE + Module-SIS) is false in v0.38 — the adversary needs to break zero of them.

**Fix**: Replace `quasar_verify_votes_kernel` with a real BLS aggregate verifier (LP-075). The metal kernel `lib/evm/gpu/metal/shaders/crypto/bls12_381.metal` is referenced as the future home. If real BLS isn't ready by activation, the GPU vote path must be disabled entirely and consensus must run from the Go implementation in `luxfi/consensus/protocol/quasar/`.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-003 — `subject` excludes chain_id, epoch, P/Q/Z roots

**Severity**: Critical
**Affected files**:
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1389-1414` (block_hash construction)
- `cevm/lib/consensus/quasar/gpu/quasar_gpu_layout.hpp:333-350` (`QuasarRoundDescriptor`)

**Description**: LP-020 §"Cert Subject — The Replay-Proof Binding" specifies:
```
certificate_subject = keccak(
    chain_id || epoch || round || mode ||
    pchain_validator_root || qchain_ceremony_root || zchain_vk_root ||
    parent_block_hash || parent_state_root || parent_execution_root ||
    gas_limit || base_fee )
```

The substrate `quasar_wave_kernel` computes `block_hash` (used as the `subject` material the verifier consumes) as:
```c
header = round_le8 || mode_le4 || receipts_root || execution_root || state_root || mode_root
block_hash = keccak256(header)
```

`chain_id` is NOT in the digest. `epoch` is NOT a field on `QuasarRoundDescriptor` at all. `pchain_validator_root`, `qchain_ceremony_root`, `zchain_vk_root`, `parent_*` are NOT present in the descriptor (it has `parent_block_hash`, `parent_state_root`, `parent_execution_root` only — none are folded into the subject digest).

The verifier independently rebuilds `subject` via `quasar_expected_sig(secret, subj, round)` which uses the host-supplied `subject[32]` from the `VoteIngress`. The host can supply ANY 32 bytes in `v.subject` because the verifier never re-derives the descriptor's binding.

**Attack scenario** (cross-epoch replay):
1. Adversary observes a valid quorum on chain `lux-mainnet`, round 1000, that finalized block hash `B`.
2. Forks fail (e.g., a stale leader). Round 1001 needs a new block. Same chain id. New round.
3. Adversary submits the quorum's votes verbatim with `v.round = 1001` (without changing the secret-key material) — the validators' MACs would not match because `round` is bound. Fine — that path is closed.
4. **But** adversary observes a future round from epoch e1, then waits until epoch e2 has the same `(round, validator_index, chain_id, subject)` tuple. Because the subject does not bind `epoch`, and the substrate has no `epoch` field, votes from epoch e1 satisfy the verifier in epoch e2 if rounds happen to coincide modulo the round counter.
5. With BLS-only mode (hot-path), the verifier accepts the replay, advancing quorum on the wrong block.

**Attack scenario** (cross-chain replay):
1. Adversary controls a vanity test chain with `chain_id = 1` (the same as `desc.chain_id = 1u` in `test_quasar_quorum_round_trip`).
2. Validators on production chain (call it `chain_id = 7777`) are tricked into running `desc.chain_id = 1u` via mis-provisioning (config typo), or the adversary simply replays test-chain votes against a misconfigured validator.
3. Because `subject` excludes `chain_id`, and the secret-derivation includes `chain_id` but the host can write any `chain_id` to the descriptor, cross-chain forgery becomes a configuration-error exploit class.

**Impact**: Both attacks succeed under v0.38. The "structurally impossible cross-epoch / cross-chain replay" claim in LP-020 §"Security properties" is false until the descriptor is extended and the substrate computes `subject` per the LP recipe.

**Fix**:
1. Add `epoch: uint64`, `pchain_validator_root: [32]u8`, `qchain_ceremony_root: [32]u8`, `zchain_vk_root: [32]u8`, `gas_limit: uint64`, `base_fee: uint64`, `parent_block_hash: [32]u8`, `parent_state_root: [32]u8`, `parent_execution_root: [32]u8` to `QuasarRoundDescriptor`.
2. Compute `certificate_subject` in the descriptor on the host (single source of truth), pass it to the GPU.
3. The GPU verifier MUST recompute `certificate_subject` from the descriptor and compare against `VoteIngress::subject` byte-for-byte before accepting any sig.
4. Document that `epoch` rolls over only on validator-set change.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-004 — No per-validator dedup; one vote credited multiple times

**Severity**: Critical
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1139-1187` (`drain_vote`)

**Description**: `drain_vote` reads `VoteIngress::stake_weight` and accumulates via `atomic_fetch_add(stake_acc, v.stake_weight)`. There is no check that `validator_index` has not voted before in this round. The substrate carries `validator_index` on the ingress envelope but never indexes it.

**Attack scenario**:
1. Adversary submits N copies of a single valid vote (or tampers with `stake_weight` only — the MAC binds subject and round, NOT stake_weight).
2. Each copy passes verification; each adds `stake_weight` to the lane counter.
3. With `stake_weight = 1` and 1000 copies of a vote from a single 0.1%-stake validator, the adversary contributes 100% of stake on the BLS lane — triggering the 2/3 quorum gate.

**Impact**: Single low-stake validator (or even a malicious node with ~0% stake plus the master secret from CERT-001) finalizes blocks of their choice.

**Fix**:
- Add a per-round `validator_voted_bitmap: device atomic_uint*` indexed by `validator_index` on each lane.
- Before crediting stake, atomically test-and-set the bit; if already set, skip without crediting.
- The bitmap must persist across wave ticks within one round and reset per round.
- The MAC must bind `stake_weight` so an attacker can't legitimately re-sign the same vote with different stake amounts.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-005 — Cross-lane replay protection inadequate against tampered `sig_kind`

**Severity**: High
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1217-1289`

**Description**: The lane-domain-tag defense works ONLY because the verifier passes `v.sig_kind` into `quasar_derive_secret`. So a vote signed for BLS lane will fail verification when re-tagged as Ringtail (correct, the LP-132 test `bad_bls.signature[0] ^= 0xFF` and the `replay.sig_kind = 2` reassignment exercises this).

However, the test in `test_quasar_quorum_round_trip` (line 391-398) shows exactly one cross-lane attempt: a vote signed as BLS, retagged as MLDSA. The test asserts this is rejected. **It works only because the secret-derivation includes sig_kind.**

This is brittle: any new lane (LP-134 added 7 more lanes — A-Chain, B-Chain, M-Chain×3, F-Chain×2) needs its own domain tag in the host signer, the GPU verifier, and the lookup table `quasar_pick_domain`. The current `quasar_pick_domain` only handles `sig_kind ∈ {0, 1, 2}` — sig_kind=3 (AChainAttest) falls through to `kMLDSADomain`. A vote for AChainAttest would silently verify against an MLDSA-tagged secret.

**Attack scenario**:
1. Once LP-134 lands enum values 3..9 but the kernel still has only the 3-way switch in `quasar_pick_domain`, an attacker with an MLDSA-tagged vote can submit it tagged as AChainAttest (sig_kind=3) and have the verifier accept it.
2. The attestation lane stake counter increments, even though the vote was issued for an entirely different purpose.

**Impact**: Cross-lane replay between the LP-134 chains. Once A-Chain attests to a TEE quote on the basis of a forged MLDSA-tagged vote, the chain's downstream consumers (every chain that reads `achain_attestation_root`) ingest fabricated trust roots.

**Fix**:
- Extend `quasar_pick_domain` to dispatch by full enum range; reject unknown `sig_kind` values explicitly (`verified[tid] = 0`).
- Add a `static_assert`-equivalent on the host that the lane domain-tag table covers every active `QuasarCertLane`.
- Domain tags should embed the lane name AND a version marker that bumps when verifier semantics change.

**Must-fix pre-launch**: Yes if LP-134 lanes are activated 2025-12-25; deferrable to v0.50 (LP-134 implementation) otherwise.

---

### Q3.0-CERT-006 — Subject not bound by stake_weight; tamper attack

**Severity**: High
**Affected files**:
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1241-1251` (`quasar_expected_sig`)
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1163` (`atomic_fetch_add(stake_acc, v.stake_weight)`)

**Description**: `quasar_expected_sig(secret, subject, round) → 32 bytes`. `stake_weight` is NOT in the MAC's input. So an attacker who legitimately holds a vote (or forged one via CERT-002) can mutate `v.stake_weight` to any value and the verifier still accepts.

**Attack scenario**:
1. Adversary intercepts a valid vote with `stake_weight = 10`.
2. Mutates `stake_weight` to `2^31 - 1`.
3. Verifier still accepts (MAC didn't sign over stake_weight).
4. `drain_vote` adds 2^31-1 to the lane counter, triggering quorum on 1 vote.

**Impact**: Any valid vote can be amplified to 2^31 stake. Combined with CERT-007's 32-bit overflow, this becomes a quorum-on-zero-stake attack.

**Fix**: Either (a) include `stake_weight` in the MAC's input, or (b) — the right answer — read `stake_weight` from the trusted descriptor's `pchain_validator_root` lookup, never from the network-supplied vote envelope.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-007 — `quorum_stake_*` is uint32; trivial overflow → false quorum

**Severity**: Critical
**Affected files**:
- `cevm/lib/consensus/quasar/gpu/quasar_gpu_layout.hpp:373-375` (`quorum_stake_bls/mldsa/rt: uint32`)
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:241-243` (kernel-side atomic_uint)

**Description**: The accumulator is a single 32-bit atomic. `prev_stake = atomic_fetch_add(stake_acc, v.stake_weight)`. There is no overflow check and no 64-bit wide accumulator. Native LUX has 1B circulating supply at 1e9 nLux precision = 10^18 lowest-units. This trivially exceeds 2^32 = 4.29e9.

The threshold check is:
```c
uint threshold = uint((desc->base_fee * 2UL) / 3UL);
if (prev_stake < threshold && new_stake >= threshold) { /* emit QC */ }
```

Note that `threshold` is also uint32, so the *threshold itself* is bounded by 4.29e9. For real LUX stake amounts the descriptor's `base_fee` (repurposed as total-stake-unit per the comment at line 1167) would have to be quantized down — and even then, the accumulator is one fetch_add away from wrapping.

The LP-020 spec mandates `cert_stake_*_lo/hi` (uint64-split) for exactly this reason. The substrate ignores the spec.

**Attack scenario** (overflow-to-quorum):
1. `desc->base_fee = 0xC000_0000` → `threshold = 0x8000_0000`.
2. Adversary submits a vote with `stake_weight = 0xFFFF_FFFF - 0x7FFF_FFFE = 0x8000_0001`. Counter wraps from `0x7FFF_FFFE` (just below threshold) to `0xFFFF_FFFF` then `0x80000000` after wrap — past threshold. QC emits with one valid (or forged) vote.
2'. Even simpler: adversary picks `stake_weight = 0x8000_0001`; `prev_stake = 0` so `prev_stake < threshold`; `new_stake = 0x8000_0001 >= threshold`. QC emits with one vote at fabricated stake.

**Impact**: Combined with CERT-006, any single forged vote drives quorum on any lane.

**Fix**:
- Extend `quorum_stake_*` to `uint64` (split into `_lo/_hi` per LP-020 spec).
- Use 64-bit atomic adds (Metal: Apple A14+, Apple Silicon M1+; CUDA: native).
- The `cert_stake_*_lo/hi` split on `QuasarRoundResult` is not yet wired through to the metal kernel — wire it.
- Move the threshold check to use trusted total-stake from `pchain_validator_root`, not `desc->base_fee`.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-008 — `head + tid >= tail` overflow / aliasing in verify kernel

**Severity**: Critical
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1264-1274`

**Description**: The verify kernel computes:
```c
uint head = atomic_load(&vote_hdr->head);
uint tail = atomic_load(&vote_hdr->tail);
if (head + tid >= tail) { verified[tid] = 0u; return; }
uint slot_idx = (head + tid) & mask;
VoteIngress v = items[slot_idx];
```

`head + tid` is `uint32` — wraps at 2^32. After enough rounds the producer `tail` and consumer `head` can be anywhere in the 32-bit range; the check `head + tid >= tail` is wrong when the ring has wrapped.

A more immediate problem: between the kernel sampling `head/tail` and the wave-tick scheduler advancing them in `drain_vote`, the slot can be popped and overwritten. The verifier then verifies a vote that has already been consumed (or is mid-overwrite), writes `verified[slot_idx] = 1`, and `drain_vote` later reads `verified[head_pre & mask]` which corresponds to a different vote.

**Attack scenario** (verified-aliasing):
1. Adversary submits 16 votes; 8 valid, 8 forged.
2. The verify kernel runs first, marking valid slots `verified[k] = 1`.
3. `drain_vote` pops votes one-by-one: `head_pre = atomic_load(head)`, then `pop`, then read `verified[head_pre & mask]`.
4. Race: between `drain_vote`'s `head_pre` snapshot and the verify kernel's snapshot, `head` advances. The verify result indexed at slot `H+k` is consumed at slot `H+k+1`, and so on.
5. With careful submission ordering, the adversary places a forged vote at the "consumed" slot of a verified one — the forged vote is treated as verified and credited to stake.

**Impact**: Forged votes admitted without verification.

**Fix**:
- Verify kernel must lock the ring snapshot: copy `head`/`tail` once into a per-round field, run all verifications against that snapshot, and `drain_vote` must read from the same snapshot.
- Use `(uint64_t)head + (uint64_t)tid` to avoid the 32-bit add overflow on the bounds check.
- The verified-bit array should be keyed by an immutable `(round, validator_index, sig_kind)` tuple, not by ring slot index.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-009 — `verified[]` write key mismatches `drain_vote` read key

**Severity**: Critical
**Affected files**:
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1289` (write: `verified[slot_idx]`)
- `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1153-1154` (read: `verified[head_pre & mask]`)

**Description**: `quasar_verify_votes_kernel` writes `verified[slot_idx] = (diff == 0u) ? 1u : 0u` where `slot_idx = (head + tid) & mask` — the slot in the ring corresponding to `head + tid`. `drain_vote` reads `verified[vidx]` where `vidx = head_pre & (vote_verified_capacity - 1u)` — the slot corresponding to the *single* item it just popped.

These index spaces match only if `vote_verified_capacity == vote_hdr->capacity` AND `vote_hdr->mask == vote_verified_capacity - 1`. They are two separately-sized buffers (`vote_verified_capacity` is buffer(10), `vote_hdr->mask` is data-driven). If they differ — and there is no `static_assert` enforcing equality — the lookup is wrong.

Even when equal, there is still a one-shot consume order: if `drain_vote` runs before the verify kernel, `head_pre` is stale and `verified[head_pre & mask]` returns whatever was there from the *previous* round, possibly 1 (if the slot was last verified-OK).

**Attack scenario**:
1. Round R-1 finishes; ring `verified[k] = 1` for k where votes were valid.
2. Round R starts; the substrate does NOT zero out `verified[]` between rounds (no `clear_verified` step exists).
3. Adversary submits unsigned (zero-byte) votes in round R. They land at slots `k` where `verified[k] = 1` from round R-1.
4. If verify kernel runs second, it overwrites `verified[k] = 0` for these — fine.
5. But there is NO ordering guarantee that verify runs before `drain_vote`. The kernel issues services concurrently via `gid`. If `gid=10` (drain_vote) consumes votes before `gid=K` (verify kernel — actually a separate kernel, but) — wait, the verify is its own kernel `quasar_verify_votes_kernel` separate from `quasar_wave_kernel`. The host must dispatch verify first. **Is this enforced?** Looking at the LP-132 wording, it isn't documented. If the host driver dispatches `quasar_wave_kernel` (which contains `drain_vote`) before `quasar_verify_votes_kernel`, the check fails open.

**Impact**: Unverified votes admitted (forged stake credited).

**Fix**:
- Combine verify and drain_vote into a single kernel pass, OR
- Have the host enforce strict ordering: `quasar_verify_votes_kernel` MUST commit before `quasar_wave_kernel`, AND the verified buffer MUST be zeroed at round-start by `begin_round`.
- Add `static_assert(vote_verified_capacity == vote_hdr->capacity)` and document the contract.
- The verified buffer should be a per-(round, validator, sig_kind) tuple, not a ring-slot lookup, to eliminate the index aliasing.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-010 — `QuasarRoundDescriptor` missing `epoch`, `chain_id` not in subject

**Severity**: High (composite; Critical when combined with CERT-003)
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_gpu_layout.hpp:333-350`

**Description**: LP-020 §3.0 mandates an `epoch` field. The substrate has `round` only. Validator-set changes happen on epoch boundaries, but with no epoch in the descriptor, the ceremony / VK / validator-set roots cannot be epoch-bound on the device.

`chain_id` is in the descriptor (`uint64_t chain_id` at offset 0) but is not folded into the subject digest (CERT-003).

**Attack scenario**: see CERT-003.

**Impact**: cross-epoch and cross-chain replay (per CERT-003).

**Fix**:
1. Add `uint64 epoch` to `QuasarRoundDescriptor`.
2. Recompute `certificate_subject` per LP-020 spec; include in the descriptor as a host-precomputed digest.
3. Verifier kernel reads `desc->certificate_subject[32]` and compares against `v.subject[32]` byte-for-byte.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-011 — Z-Chain Groth16 freshness: subject doesn't bind unpredictable fields

**Severity**: High
**Affected files**: LP-020 §"Cert Lane: MLDSAGroth16", `quasar_wave.metal` (no implementation yet)

**Description**: The MLDSAGroth16 lane verifies a 192-byte Groth16 proof against `zchain_vk_root`. Public inputs include `subject + validator set root`. Per LP-020 §"Cert Subject", `subject` includes `parent_block_hash`, `parent_state_root`, `parent_execution_root`. **However**, in v0.38 the substrate's `parent_*` fields are present in the descriptor but never folded into the subject (CERT-003). With v0.38 subject = `(round, mode, receipts_root, execution_root, state_root, mode_root)`, **all of these are computable by the proposer in advance** — receipts_root depends on tx ordering (proposer-controlled), state_root depends on execution result (proposer-knowable), mode_root same.

So a proposer can:
1. Choose a desired tx ordering and predict the subject `S_future` for round 1000 in advance.
2. Run the Z-Chain Groth16 prover on `S_future`, getting proof `π`.
3. At round 1000, produce votes — but the proposer-controlled tx ordering means they always get to produce a block whose subject is S_future.
4. Submit `π` and pass MLDSAGroth16 verification.

This is "harmless" if the proposer is honest, but it gives a malicious proposer a way to **pre-commit** to a specific block's identity — useful for MEV attacks (specifically for grinding attacks where a proposer searches for a `S_future` that maximizes their MEV).

**Fix**:
- Per LP-020 §"Cert Subject", fold in unpredictable fields: `pchain_validator_root` (changes with stake delegations), `qchain_ceremony_root` (changes with DKG ceremonies), and ideally a VRF output.
- Once CERT-003 is fixed, this is mostly mitigated since `pchain_validator_root` is unpredictable to adversaries who don't control validator set changes.
- Add a per-round VRF beacon (committed via P-Chain or similar) into the subject digest for stronger unpredictability.

**Must-fix pre-launch**: Partially (depends on CERT-003 fix).

---

### Q3.0-CERT-012 — Indirect-payload attack: `(artifact_offset, artifact_len)` not bounds-checked

**Severity**: High
**Affected files**: LP-020 §"QuasarCertIngress" (spec only; substrate not yet implemented)

**Description**: LP-020 specifies `cert_artifact_arena` indexed by `(offset, len)` for variable-size lane artifacts. The spec does not document:
- How the verifier validates `offset + len <= arena_size`.
- Whether overlapping `(offset, len)` ranges are permitted across two ingress entries.
- Whether two entries with the same `(offset, len)` for the same lane are deduped.

These are **must-specify** items because the indirection is the wire-side ABI surface for variable-size PQ schemes (Ringtail, Falcon, SLH-DSA all have variable-size signatures).

**Attack scenario** (out-of-bounds read):
1. Adversary submits `QuasarCertIngress { artifact_offset = arena_size - 4, artifact_len = 1024 }`.
2. Verifier reads `arena[offset .. offset+len]` extending past the arena. On GPU this reads adjacent buffer memory — possibly the descriptor, possibly host-bridge state. On CPU host-side composition this is a heap OOB read.
3. The result either: (a) crashes the verifier (DoS), or (b) reads attacker-controllable state and treats it as a valid sig (when combined with a controllable adjacent buffer).

**Attack scenario** (overlapping payload):
1. Adversary submits 100 ingress entries all with `artifact_offset = 0, artifact_len = 96` for the BLS lane.
2. All 100 entries reference the same 96 bytes (one valid BLS aggregate).
3. The verifier accepts each independently, accumulating stake 100 times for a single signature.

**Attack scenario** (1-byte rotation reuse):
1. Adversary submits two ingress entries with `(offset=0, len=96)` and `(offset=1, len=96)` (overlapping by 95 bytes).
2. The verifier accepts both as distinct signatures even though they share 95 bytes of payload.
3. With the right wire-format, this allows reusing aggregate signature material across multiple "votes".

**Impact**: Each attack independently breaks quorum integrity.

**Fix**:
- LP-020 must specify: `offset >= 0 && len >= 0 && offset + len <= arena_size && len <= MAX_LANE_ARTIFACT_SIZE_BY_LANE[lane]`.
- The verifier must dedup by `(lane, validator_index, hash(arena[offset..offset+len]))` — same hash from same validator on same lane = one credit.
- The verifier must reject overlapping ranges by maintaining a per-round byte-bitmap of "claimed" arena bytes; an entry's bytes must be unclaimed.
- Better: per-validator per-round per-lane = one entry. Drop the overlap concern by construction.

**Must-fix pre-launch**: Yes (when the indirection lands; the spec text alone does not protect).

---

### Q3.0-CERT-013 — Q-Chain ceremony stalling forces fallback ceremony root

**Severity**: High
**Affected files**: LP-020 §"Cert Lane: Ringtail", LP-134 §"Q-Chain"

**Description**: The Ringtail cert lane verifies against `qchain_ceremony_root`. The spec says "Q-Chain runs the Ringtail 2-round DKG ceremony for the active epoch and commits the result to `qchain_ceremony_root` in the next QuasarRoundDescriptor". What happens if the ceremony fails to commit by deadline?

- If the substrate falls back to a previous epoch's `qchain_ceremony_root`, then a current-epoch adversary with archived round-1 share data from the previous epoch can produce a valid Ringtail share against the stale key.
- If the substrate halts, the chain stalls (liveness loss) — but a livenness-loss DoS is a known PQ-threshold problem.
- If the substrate proceeds with the BLS-only lane (no Ringtail), the chain effectively downgrades to single-lane consensus — the spec's "must break ALL THREE assumptions simultaneously" claim breaks because Ringtail is now optional.

**Attack scenario** (stall-then-stale-root):
1. Adversary controls > 1/2 of the t-of-n Ringtail DKG participants for one epoch (this is < 1/3 of total stake but enough to abort the ceremony).
2. Adversary aborts round 2 of the DKG. Ceremony fails to commit a new `qchain_ceremony_root`.
3. Substrate falls back to the previous epoch's root.
4. Adversary, who archived previous-epoch share data and know the previous-epoch threshold key, signs round-1 shares with the stale key. They verify against the stale `qchain_ceremony_root`.
5. Combined with BLS forgery (CERT-002), full quorum is forged on the now-static Ringtail key.

**Impact**: Ringtail lane integrity loss (until DKG retries succeed). More importantly: the liveness-vs-safety tradeoff on Q-Chain ceremony failure is unspecified.

**Fix**:
- Specify the ceremony failure handling: the LP must declare halt-on-ceremony-failure for Ringtail.
- `qchain_ceremony_root` must include an epoch counter that the verifier checks against `desc->epoch`.
- A stall window (e.g., 1 round) is permissible, after which the chain refuses to advance unless a fresh root commits.

**Must-fix pre-launch**: Yes (specification fix; the substrate's behavior must be deterministic).

---

### Q3.0-CERT-014 — `cert_artifact_arena` indirection unimplemented at activation

**Severity**: High
**Affected files**: spec gap — `quasar_gpu_layout.hpp` has `VoteIngress` (96-byte inline sig), no `QuasarCertIngress` with offset/len

**Description**: The LP-020 §3.0 wire format relies on `(artifact_offset, artifact_len)` indirection. The substrate at v0.38 still uses the v2.0 inline-sig `VoteIngress`. Either (a) the activation must ship with the new ingress format (in which case CERT-012 applies) or (b) the activation ships with the old format, and LP-020 §3.0 lies about the wire format the chain uses.

**Impact**: Specification/implementation drift at activation. Future upgrade to real PQ schemes (which need variable-size artifacts) will require a wire-format break — which LP-020 explicitly promises will never happen.

**Fix**: Implement `QuasarCertIngress` per LP-020 spec before 2025-12-25. Or update LP-020 to reflect what 2025-12-25 actually ships and version-bump to 3.1 when the indirection lands.

**Must-fix pre-launch**: Yes (one of the two paths).

---

### Q3.0-CERT-015 — A-Chain attestation root: TEE quote chain-of-trust unspecified

**Severity**: High
**Affected files**: LP-134 §"A-Chain (Attestation, NEW)"

**Description**: LP-134 introduces A-Chain with attestation roots from SGX/SEV-SNP/TDX TEE quotes. The spec does not specify:
- What attestation chain (root cert) the verifier trusts.
- How root cert revocation is handled (Intel's PCS, AMD's KDS).
- What the per-quote freshness binding is (a TEE quote signed once is replayable forever without a freshness nonce).
- Who can submit a TEE attestation to A-Chain — any node, validators only, specific TEE-equipped validators only?
- How `achain_attestation_root` is verified by chains that consume it.

**Attack scenario** (forged TEE quote):
1. Adversary observes a valid validator TEE quote from epoch e1.
2. Submits the same quote to A-Chain in epoch e2. Without a freshness binding, the verifier accepts the quote.
3. A-Chain commits the (stale) attestation into `achain_attestation_root`.
4. Downstream chains that consume the root trust the (stale) TEE state, even though that validator's TEE may have been compromised between e1 and e2.

**Attack scenario** (rogue intermediate cert):
1. Without a pinned root cert, adversary forges a quote signed by an attacker-controlled CA pretending to be Intel PCS.
2. A-Chain accepts the quote.
3. Trust chains consuming `achain_attestation_root` are compromised.

**Impact**: A-Chain attestation root contains untrusted data; downstream chains relying on it operate on falsified TEE attestations.

**Fix**:
- Pin the trusted root certs (Intel PCS, AMD KDS) via P-Chain governance (cannot be changed without a stake-weighted vote).
- Every TEE quote must include a freshness nonce bound to `(round, epoch, validator_index, achain_attestation_root_prev)`.
- Specify revocation: a quote whose intermediate cert appears in a revoked-CA list (PCS revocation list, etc.) must be rejected by `drain_attest`.
- Restrict TEE quote submission to validators with attested hardware (chicken-and-egg; bootstrap via P-Chain governance vote on initial set).

**Must-fix pre-launch**: Yes if A-Chain activates 2025-12-25; deferrable to v0.51 (LP-134 implementation) otherwise.

---

### Q3.0-CERT-016 — M-Chain / F-Chain validator-subset stake concentration

**Severity**: High
**Affected files**: LP-134 §"M-Chain", §"F-Chain"

**Description**: LP-134 introduces M/F-Chains as smaller validator subsets carved from P-Chain. The spec does not specify how the subset is selected. Two natural options:
- (a) Top-k by stake → adversary with concentrated stake on M/F-Chain controls > 1/3 of the subset even if they're < 1/3 on P-Chain overall.
- (b) Random subset weighted by stake → unbiased but requires VRF beacon (which LP-134 doesn't define for chain-validator-set selection).

If the M-Chain subset has, say, 7 validators chosen from the top-7 P-Chain stake, an adversary with 14% of P-Chain stake (well below the 33% Byzantine bound) but who concentrates that 14% in the top-7 can be > 33% of the M-Chain subset.

**Attack scenario**:
1. Adversary delegates 14% of total stake to one of their validators.
2. M-Chain selection picks the top-7 stakeholders. Adversary's validator is in the top-7 with > 1/7 ≈ 14.3% of subset stake.
3. With one or two more colluding validators in the top-7, adversary controls > 33% of M-Chain.
4. M-Chain MPC ceremonies (CGGMP21, FROST, Ringtail-general) are compromised — the threshold is broken.
5. F-Chain TFHE key shares similarly compromised.

**Impact**: Cross-chain trust violation. P-Chain stake distribution that's safe for the main chain is unsafe for M/F-Chain operations (custody, cross-chain bridges, etc.).

**Fix**:
- M/F-Chain subset selection must use stake-weighted random sampling with a VRF beacon (not top-k).
- Alternatively: M/F-Chain operations require the FULL P-Chain validator set's threshold — no carve-out.
- Document the security analysis: "for an adversary at A% of P-Chain stake, the probability they control >1/3 of an N-validator subset is..."

**Must-fix pre-launch**: Yes if M/F-Chains activate 2025-12-25; deferrable to v0.53/v0.54 otherwise.

---

### Q3.0-CERT-017 — `verified[]` not zeroed across rounds

**Severity**: High
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal` (no `clear_verified`), `quasar_gpu_engine.mm:begin_round`

**Description**: The `vote_verified` buffer is sized once, indexed by ring slot. Between rounds, the buffer's contents are NOT zeroed. The substrate's `begin_round` initializes ring headers but not verifier output buffers.

**Attack scenario**: see CERT-009.

**Impact**: Stale `verified[k] = 1` from round R-1 is observed by `drain_vote` in round R for any vote that didn't get re-verified before being consumed.

**Fix**: `begin_round` must zero `vote_verified[0..capacity]`. Add a test: round R-1 ends with `verified[5] = 1`; round R submits an unsigned vote at slot 5; assert `drain_vote` does not credit it.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-018 — Domain-tag table only handles 3 lanes

**Severity**: Medium
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1217-1226` (`quasar_pick_domain`)

**Description**: `quasar_pick_domain` switches on `sig_kind ∈ {0, 1, default→MLDSA}`. LP-134 introduces enum values 3..9 for the 7 new lanes. Any sig_kind > 1 currently falls through to MLDSA's domain tag. A fresh assertion / range check is missing.

**Attack scenario**: see CERT-005.

**Fix**: Switch over the full enum; default branch returns nullptr / sets `verified=0`. Add `static_assert` per lane.

**Must-fix pre-launch**: Yes if LP-134 lanes ship 2025-12-25.

---

### Q3.0-CERT-019 — Master-secret derivation includes `validator_index` but not validator pubkey

**Severity**: Medium
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1228-1239`

**Description**: Even ignoring CERT-001 (publicly-leaked master secret), the secret derivation `secret_i = keccak256(domain || chain_id || validator_index || master)` binds validator identity through their *index* — a 4-byte integer. If validator indices are reassigned across epochs (e.g., a validator leaves, another takes index 5), the secret is invariant per-index, not per-validator.

A validator at index 5 in epoch e1 who leaves the set; a different validator at index 5 in epoch e2 — both share the same `secret_5` because `master_secret` is global. A valid epoch-e1 vote from validator-A becomes a valid epoch-e2 vote from validator-B without modification.

**Attack scenario**:
1. Validator A occupies index 5 in epoch e1, signs vote `v_A`.
2. Validator A leaves; validator B takes index 5 in epoch e2.
3. Adversary replays `v_A` in epoch e2 (same `validator_index = 5`, same `chain_id`, same `subject` if subject doesn't bind epoch — see CERT-003).
4. Verifier accepts; B's stake is credited.

**Impact**: validator-set-rotation replay attack; combined with CERT-003, this is a real cross-epoch replay.

**Fix**:
- Bind validator pubkey or BLS-public-key in the secret derivation, not just the index.
- Once real BLS lands (v0.43), the issue resolves naturally — BLS sigs bind to the pubkey.

**Must-fix pre-launch**: Yes (composite with CERT-003).

---

### Q3.0-CERT-020 — `desc->base_fee` reused as `total_stake_unit`

**Severity**: Medium
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1167-1168`

**Description**: The kernel comment says "Hosts pass total stake via base_fee for now". This conflates two semantically different quantities. A future descriptor change that disambiguates `base_fee` from `total_stake` will break verification at deployment boundary unless coordinated.

**Attack scenario**: A validator is misconfigured to send `base_fee = real_base_fee` (small, reasonable EIP-1559 number) instead of `base_fee = total_stake`. The threshold becomes `(small * 2 / 3)` — trivially exceeded by a single vote. Quorum forms on one vote.

**Impact**: Configuration error → quorum-on-zero-stake. Combined with CERT-002, no attack capability needed.

**Fix**: Add a dedicated `total_stake: uint64` field to `QuasarRoundDescriptor`. Remove the base_fee reuse.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-021 — Round number is uint64 in descriptor but uint32 on the wire

**Severity**: Medium
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_gpu_layout.hpp:294-299` (`VoteIngress::round: uint32`), `quasar_gpu_layout.hpp:335` (`QuasarRoundDescriptor::round: uint64`)

**Description**: `QuasarRoundDescriptor::round` is `uint64_t`. `VoteIngress::round` is `uint32_t`. The verifier's MAC binds 4 bytes of round (`round_le4`). After 2^32 rounds (~136 years at 1s/round, but just 4 years at 1ms/round on a high-TPS chain), the round wraps; replay across the wraparound is permitted.

More immediately, if the chain reaches round `2^32 + k`, the descriptor sees round `2^32 + k` but the vote's `v.round` field can only hold `k`. Verification still works because the MAC binds `v.round`, but the same `v.round = k` is also valid for round `k` (the original). Replay of all old votes once the round counter wraps.

**Attack scenario**: Run the chain for 4 years at 1ms blocks. Replay archived votes from year 0 against round 2^32+0. Verifier accepts.

**Fix**: Widen `VoteIngress::round` to `uint64_t`. Bind `desc->round` (full 64 bits) in the MAC; the substrate currently only binds 4 bytes (line 1249).

**Must-fix pre-launch**: Yes (at modern block rates the wraparound happens within a deployment lifetime).

---

### Q3.0-CERT-022 — `subject` re-derivation guard absent in `drain_vote`

**Severity**: Medium
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1139-1187` (`drain_vote`)

**Description**: `drain_vote` reads `v.subject` (host-provided) but never checks it matches the descriptor's `block_hash` (or future `certificate_subject`). The verify kernel runs the MAC against `v.subject`, but if all votes carry `v.subject = adversary_choice`, they pass MAC verification (the MAC just checks the secret, subject, round triple).

The LP says (§"Cert Subject"): "every cert-lane artifact MUST bind this same `certificate_subject`". The substrate's `drain_vote` doesn't enforce this.

**Attack scenario**: Adversary submits 2/3+1 forged votes (per CERT-002) all with `v.subject = adversary_block_hash`. Verifier accepts each MAC; quorum forms on `adversary_block_hash` — even though the block actually computed by execution has a different hash.

**Impact**: Quorum on a block that wasn't actually executed.

**Fix**: `drain_vote` (and the verify kernel) MUST check `v.subject == result->block_hash` (current substrate) or `v.subject == desc->certificate_subject` (post-CERT-003 fix). Reject votes whose subject doesn't match.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-023 — `validator_index` not bounds-checked

**Severity**: Medium
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1281` (`v.validator_index` used in `quasar_derive_secret`)

**Description**: `validator_index` is `uint32_t`. The host-supplied vote can have `validator_index = 0xFFFFFFFE`. The verifier doesn't bound-check it against `pchain_validator_root`'s validator count.

A vote from "validator 4 billion" computes a unique `secret_i` (because the master secret is global; each index produces a distinct secret), passes the MAC, and is credited stake.

**Attack scenario**: Combined with CERT-002, adversary submits 4 billion forged votes from validators 0..2^32-1. Each is unique, each passes the MAC (via the leaked master secret), each is credited stake. Even with proper dedup (CERT-004), there are too many slots.

**Impact**: Stake counter overflows (CERT-007); also attempts to deduce a per-validator set bound. Without a bound, the bitmap defense in CERT-004 needs 2^32 bits = 512 MB.

**Fix**: Add `desc->validator_count: uint32`. Verifier rejects votes with `validator_index >= validator_count`. The bitmap in CERT-004 is sized to `validator_count`.

**Must-fix pre-launch**: Yes.

---

### Q3.0-CERT-024 — `qchain_ceremony_root` selection for round R: which ceremony epoch?

**Severity**: Medium
**Affected files**: LP-020 §"Cert Lane: Ringtail"

**Description**: LP-020 says "Q-Chain commits the public key for round R via `qchain_ceremony_root[R]`" but the descriptor only carries one `qchain_ceremony_root`. Is it indexed by round? Epoch? Per-epoch with per-round binding? Spec is ambiguous.

If a round's `qchain_ceremony_root` is selected from a sequence committed by Q-Chain, the selection function must be specified. Otherwise the verifier and the prover may disagree on which key to use (especially during epoch transitions).

**Attack scenario**: Selection ambiguity → during an epoch transition, validator A's verifier picks the new key but validator B's verifier picks the old key. They diverge on which votes verify. The chain forks.

**Impact**: Liveness loss (fork) at every epoch transition.

**Fix**: Specify: `qchain_ceremony_root` is the Q-Chain commitment as of the epoch containing round R, indexed by `epoch(R) = floor(R / EPOCH_LEN)`. The descriptor's `epoch` field is the authority.

**Must-fix pre-launch**: Yes (spec fix).

---

### Q3.0-CERT-025 — `RingHeader::head` / `tail` are uint32 (drains 4G items per round)

**Severity**: Low
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_gpu_layout.hpp:68-81`

**Description**: After 2^32 / capacity ring-wraps, `head` and `tail` mathematics fail. With `capacity = 8192` and 1ms-rate ingress, this is ~50 days. Within a long-running round (which doesn't end), this matters less, but the `pushed` and `consumed` 32-bit counters wrap independently and the close-gate `ingress_pushed == commit_consumed` becomes false-positive after 2^32 transactions.

**Attack scenario**: Run a high-TPS test until `pushed = 2^32`. The close-gate triggers prematurely (or never, depending on tail/head rate).

**Fix**: Widen counters to `uint64_t`. Modern GPUs (Apple A14+, NVIDIA SM_70+) support 64-bit atomics.

**Must-fix pre-launch**: No — deferrable to v0.50.

---

### Q3.0-CERT-026 — Lane indirection enables a dedup-scope confusion

**Severity**: Low
**Affected files**: LP-020 §"QuasarCertIngress"

**Description**: Each `QuasarCertIngress` carries `(validator_index, cert_lane, artifact_offset, artifact_len, subject)`. If dedup is per-`(validator_index, cert_lane)`, an attacker can submit two ingress entries with `(v=5, lane=BLS, offset=0, len=96)` and `(v=5, lane=Ringtail, offset=0, len=96)` — the second cross-credits stake to the Ringtail lane.

The MAC catches this if domain tags are correct (CERT-005), but the dedup key must include lane, validator, and round.

**Fix**: Dedup key = `(round, epoch, validator_index, cert_lane)`. Enforce in the verifier.

**Must-fix pre-launch**: When indirection lands; deferrable.

---

### Q3.0-CERT-027 — `kQuasarMasterSecret` ASCII content increases discoverability

**Severity**: Informational
**Affected files**: `cevm/lib/consensus/quasar/gpu/quasar_wave.metal:1212-1215`

**Description**: The bytes `0x51,0x55,0x41,0x53,...` decode to ASCII `"QUASAR-v038-master-secret-shared"`. This is a self-describing secret; an attacker grepping logs, memory dumps, or string-table extracts in deployed binaries finds it immediately. Random-looking secret bytes (`/dev/urandom`) make discovery slightly harder.

**Fix**: This is moot — see CERT-001 (delete the path entirely). Informational only as a code-smell flag.

---

### Q3.0-CERT-028 — Wave-tick budget unbounded; DoS by ring-fill

**Severity**: Informational
**Affected files**: `quasar_wave.metal:1323` (`budget = max(uint(64), desc->wave_tick_budget)`)

**Description**: `wave_tick_budget` is host-controlled. A misconfigured or malicious host can pass a huge budget; the kernel will drain that many items per tick. This is a per-validator local DoS — not a remote attack — but worth flagging as the substrate's only safeguard is `max(64, ...)` (no upper bound).

**Fix**: Cap `budget = min(budget, MAX_BUDGET = 16384)`.

**Must-fix pre-launch**: No.

---

### Q3.0-CERT-029 — Block-STM `mvcc_apply_writes` runs before commit; allows uncommitted state visible to other tx

**Severity**: Low (out-of-scope for cert-lane review but flagged for completeness)
**Affected files**: `quasar_wave.metal:978-979` (drain_validate applies writes BEFORE pushing CommitItem)

**Description**: `drain_validate` runs `mvcc_apply_writes` to bump version, then `ring_try_push(commit_hdr, ...)`. If commit ring is full, the version bump is NOT rolled back (the kernel comment acknowledges this: line 997-1001). Other txs concurrently validating against the bumped version read a "committed" state that hasn't actually committed.

This is an STM-correctness concern, not a cert-lane attack. Logged for completeness.

**Fix**: out of cert-lane scope; see LP-010 review.

---

## Summary by attack surface

| Attack surface (per task brief) | Primary findings |
|---|---|
| 1. Cross-epoch replay | CERT-003, CERT-010, CERT-019, CERT-021 |
| 2. Cross-chain replay | CERT-003, CERT-010 |
| 3. Lane-tag confusion | CERT-005, CERT-018 |
| 4. Indirect-payload attack | CERT-012, CERT-014, CERT-026 |
| 5. Stake-wrap / overflow | CERT-007, CERT-020 |
| 6. Z-Chain Groth16 freshness | CERT-011 |
| 7. Q-Chain ceremony root attack | CERT-013, CERT-024 |
| 8. A-Chain attestation injection | CERT-015 |
| 9. HMAC-keccak placeholder | CERT-001, CERT-002, CERT-019, CERT-027 |
| 10. Validator-subset isolation | CERT-016 |

The HMAC-keccak placeholder is not a cryptographic primitive — it is a debug stub. The 2025-12-25 chain activation **must not ship with the placeholder enabled** in any cert lane. Real BLS aggregation (v0.43) is the minimum viable launch state for the BLS classical lane; the Ringtail and Groth16 lanes can be feature-flagged off until v0.44/v0.45 land if necessary, downgrading to BLS-only consensus until then.

## Recommendation

**Do-not-ship 2025-12-25 with v0.38 substrate.** One of:

- **Path A (preferred)**: Land v0.43 (real BLS) before 2025-12-25; feature-flag Ringtail and MLDSAGroth16 lanes off until their real verifiers land. Fix CERT-001..CERT-010 and CERT-021..CERT-024.
- **Path B (fallback)**: Disable the GPU cert-lane entirely. Run consensus from `luxfi/consensus/protocol/quasar/` (Go implementation) with real BLS / Ringtail / ML-DSA verifiers. The GPU substrate runs only execution (Block-STM, EVM fibers) with no role in vote aggregation.

Either path requires CERT-003 (subject binds chain_id, epoch, P/Q/Z roots) and CERT-007 (uint64 stake counter) to be fixed in the descriptor regardless of which crypto verifier ships.
