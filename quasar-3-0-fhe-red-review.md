# Quasar 3.0 — F-Chain / FHE Red Review

**Scope**: LP-013 v2 (F-Chain), LP-066 (TFHE), LP-067 (Confidential ERC-20),
LP-068 (Private Teleport), LP-019 (Threshold MPC for keygen), LP-134 (chain
topology), and the corresponding Go reference (`lux/precompile/fhe`,
`lux/fhe`).

**Threat model (as stated)**: adversary controls one F-Chain validator with
full GPU memory visibility, can submit chosen ciphertexts, can replay/splice
messages, cannot break TFHE/Module-LWE. Goal: leak plaintext or forge state
transitions.

**Reviewer**: Red (adversarial security researcher).
**Date**: 2026-04-26.
**Target launch**: 2025-12-25 (Quasar 3.0 production).
**Verdict**: **DO-NOT-SHIP**. The deterministic-keygen, the unauthenticated
`decrypt` precompile, the lack of FChainTFHE/FChainBootstrap real verifiers,
and the absence of any actual GPU TFHE kernel mean F-Chain currently
provides **no confidentiality** and **no soundness**. Several findings are
showstoppers individually; together they trivially break every confidential
ERC-20 balance and every private teleport.

Numbering: `Q3.0-FHE-NNN`. Severity: Critical / High / Medium / Low / Info.

---

## Executive summary

| # | Title | Severity |
|---|---|---|
| Q3.0-FHE-001 | Deterministic keygen → secret key derivable from a public string | **Critical** |
| Q3.0-FHE-002 | `handleDecrypt` has no caller authorization → any handle decryptable by any contract | **Critical** |
| Q3.0-FHE-003 | F-Chain cert lanes (`FChainTFHE`, `FChainBootstrap`) have no real verifier — they will inherit HMAC-keccak placeholder semantics | **Critical** |
| Q3.0-FHE-004 | None of the GPU TFHE kernels in LP-013 (§Kernels v0.54) exist on disk | **Critical** |
| Q3.0-FHE-005 | `tfheVerify` accepts any byte string that deserialises — no input proof, no range check, no type binding | **Critical** |
| Q3.0-FHE-006 | `performFHESealOutput` is a stub: concatenates pk\|ct, returns plaintext-equivalent | **Critical** |
| Q3.0-FHE-007 | Block-STM treats ciphertexts as opaque bytes → ciphertext malleability inside an MVCC arena | **High** |
| Q3.0-FHE-008 | Key-rotation race: two-phase rotation across `fchain_fhe_root` epochs has no fence; bisecting valid/invalid ciphertexts leaks the rotation boundary | **High** |
| Q3.0-FHE-009 | M-Chain → F-Chain bootstrap-key handoff has no published correctness proof; `mchain_ceremony_root` only commits the share, not the equivalence to the new `fchain_fhe_root` | **High** |
| Q3.0-FHE-010 | F-Chain validator subset → 1/3 corruption halts F-Chain at lower stake than 1/3 of total Lux | **High** |
| Q3.0-FHE-011 | `fhe.decrypt(ciphertext, callbackAddress)` (LP-066) has no nonce: same handle returns same plaintext on repeated calls — replay/oracle attacks | **High** |
| Q3.0-FHE-012 | LP-067 §`transfer`: no encrypted-amount range proof tied to caller; underflow-revert leaks the comparison result of `amount > balance` | **High** |
| Q3.0-FHE-013 | LP-067 transfer pattern (sender, receiver, gas) leaks even when amount is encrypted; no decoy injection | **High** |
| Q3.0-FHE-014 | Apple M1/M2 share L2 between SM groups: TFHE bootstrap timing observable from a co-resident GPU workload | **Medium** |
| Q3.0-FHE-015 | Three `external_product` variants (RGSW × RLWE) listed without byte-identical correctness gate — non-deterministic state root if validators pick different variants | **Medium** |
| Q3.0-FHE-016 | TLWE noise budget is not tracked anywhere; an adversary can chain operations to exhaust noise → decryption-error oracle | **Medium** |
| Q3.0-FHE-017 | Oblivious branching (`JUMPI` on encrypted condition) on `evm256` is not specified to evaluate both branches in constant SIMT time — likely leaks branch-taken via warp divergence and L1 access pattern | **Medium** |
| Q3.0-FHE-018 | LP-068 cross-chain replay protection uses `nullifier = Poseidon2(commitment ∥ spending_key ∥ sourceChainID)` — destination chain ID is **not** in the nullifier; bridge-loop replay is feasible | **Medium** |
| Q3.0-FHE-019 | LP-067 storage layout: `_balance[address] = ciphertext` per-account encrypted slot leaks first-time-write vs. update via SSTORE refund pattern (gas timing oracle) | **Medium** |
| Q3.0-FHE-020 | Ciphertext handle is `keccak256(ct_bytes)` — bit-identical ciphertexts collide (two encryptions under the same key reuse handles in a deterministic-encryption scenario, common with deterministic seed) | **Low** |
| Q3.0-FHE-021 | `tfheRandom` is keyed by user-supplied `seed uint64` → caller can predict every "random" ciphertext | **Low** |
| Q3.0-FHE-022 | `tfheTrivialEncrypt` uses the encryptor instead of trivial encryption — wastes noise budget and confuses the threat model (LP-013 says trivial constants are noiseless) | **Info** |
| Q3.0-FHE-023 | LP-067 says transfer reverts when `sufficient` is false via underflow — relies on observable revert, leaking `amount > balance` | (folded into 012) |
| Q3.0-FHE-024 | No PASS evidence anywhere of the 21 GPU kernels claimed in LP-013 v1; CUDA mirror in v0.55 is also empty | **Info** |
| Q3.0-FHE-025 | `evm256` interpreter does not exist in the tree; LP-013 §"Encrypted EVM (`evm256.metal`)" is design-only | **Info** |

Severity totals: **6 Critical, 7 High, 6 Medium, 2 Low, 4 Info** (25 unique findings).

---

## Findings

### Q3.0-FHE-001 — Deterministic keygen leaks the secret key to anyone with source access

**Severity**: Critical.

**Files**:
- `lux/precompile/fhe/fhe_ops.go:29-60`
- `lux/fhe/CLAUDE.md` (advertises this fix)

**Scenario**:
```go
var fheKeygenSeed = sha256.Sum256([]byte("LUX_FHE_KEYGEN_v1"))
kg, _ := fhe.NewKeyGeneratorFromSeed(params, fheKeygenSeed[:])
secretKey, publicKey = kg.GenKeyPair()
bsk := kg.GenBootstrapKey(secretKey)
```
The seed is a public constant. Every node that runs the precompile derives
the same `(sk, pk, bsk)`. **The "secret" key is universally derivable**,
including by the public, not just by validators. This violates the LP-066
§Security claim "global secret key never exists in a single location" and
the LP-013 §Security claim "only TEE-protected key holders can decrypt".

**Attack**: an external observer reads any LP-067 confidential balance by
running `decryptor.DecryptUint64(ct)` against the public-constant secret
key. There is no attack — there is no defence.

**Genesis of the bug**: the prior red swarm (2026-04-13, finding C-03)
flagged a different bug — `crypto/rand` keygen made each validator's keys
diverge. The fix turned the security parameter into a public constant
instead of using a real ceremony output.

**Detectability**: zero — there is no anomaly to monitor. Compromise is
silent and total.

**Crypto note**: this is not "FHE under a shared key with TEE custody"; it
is "FHE under a key written in the source tree". The IND-CPA reduction
fails immediately: $\Pr[\mathcal{A}\text{ wins IND-CPA}] = 1$ for any
$\mathcal{A}$ that can read the constant.

**Fix hint**: keys must come from a real ceremony. Either (a) M-Chain DKG
output written into `fchain_fhe_root`, then validators load shares into
TEE on boot and the public key is derived during the ceremony; or (b)
HSM-backed thresholded keygen with KMS-stored shares (LP-019 §LSS
resharing). The seed approach must be deleted, not parameterised.

---

### Q3.0-FHE-002 — `handleDecrypt` is unauthenticated; any contract can decrypt any handle

**Severity**: Critical.

**Files**:
- `lux/precompile/fhe/contract.go:873-886, 1294-1302`

**Scenario**:
```go
func (c *FHEContract) handleDecrypt(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) (..., error) {
    handle := common.BytesToHash(data[:32])
    result := performFHEDecrypt(state.GetStateDB(), handle, caller)
    return result.Bytes(), gas - GasDecryptRequest, nil
}

func performFHEDecrypt(stateDB contract.StateDB, handle common.Hash, caller common.Address) *big.Int {
    ct, ctType, ok := getCiphertext(stateDB, handle)
    if !ok { return big.NewInt(0) }
    return tfheDecrypt(ct, ctType)   // no ACL, no permit, no callback gating
}
```
The `caller` argument is accepted but never consulted. Any EOA/contract
that knows the handle (handles are observable in calldata, in events, and
in state inspection) can call `decrypt` and get the plaintext returned in
EVM return data. LP-066 §Decryption Protocol describes a t-of-n threshold
decryption with TEE round-trips; the implementation does single-key
decryption synchronously.

**Attack**:
1. Observe a confidential ERC-20 transfer's resulting `_balance[victim]`
   handle from the SSTORE trace.
2. Craft a contract that calls `IFHE.decrypt(handle)`.
3. Read victim's balance.

**Combined with Q3.0-FHE-001**, the precompile isn't even needed — the
caller can decrypt off-chain. But the precompile makes the leak callable
from any other contract for free.

**Fix hint**: enforce the FheOS ACL pattern (`0x0200...0081`) before
decryption. The decryption interface should be split: (a) `requestDecrypt`
emits an event, (b) off-chain threshold decryptors pick it up, (c)
threshold-signed callback writes the plaintext into the requestor's
state slot via permit, (d) plaintext never appears in EVM return data.

---

### Q3.0-FHE-003 — F-Chain cert lanes (`FChainTFHE`, `FChainBootstrap`) inherit HMAC-keccak placeholder verification

**Severity**: Critical.

**Files**:
- `LP-132` §`drain_cert_lane` v0.38 (lines 204-214 of `LP-132-quasar-gpu-execution-adapter.md`)
- `LP-013` §"Cert lanes" (lines 162-168)
- `LP-134` §`QuasarCertLane` registry (lines 114-130) defines lanes 8 and 9

**Scenario**: LP-132 v0.38 explicitly admits that `verify_bls_aggregate`,
`verify_ringtail_share`, and `verify_mldsa_groth16` are HMAC-keccak with a
master secret. LP-132 roadmap promises real verifiers at v0.43, v0.44,
v0.45. **No entry exists for FChainTFHE / FChainBootstrap real
verifiers**. By the LP-013 v0.54 timeline (this LP), F-Chain ships with a
"verifier" that has never been specified. The LP-132 statement "structured
so the swap to real BLS / Ring-LWE / Groth16 is a single function pointer"
does not even consider TFHE attestation, which is fundamentally a different
proof system (proof-of-correct-bootstrap, e.g., zk-SNARK over a TFHE
circuit).

**Attack**: a single F-Chain validator submits a `FChainTFHE` artifact with
arbitrary `circuit_dag_root` and arbitrary plaintext; the HMAC-keccak
verifier accepts it because the validator knows the master secret. The
`fchain_fhe_root` no longer commits to a circuit anyone can verify.
Other validators accept the cert because the round descriptor binds the
artifact's `(artifact_offset, artifact_len)` indirection — not the
semantic content.

**Detectability**: the LP-013 §Security claim "Replay protection:
`fchain_fhe_root` binds every cert artifact to the exact circuit DAG +
evaluation-key state" is **false** under HMAC-keccak: the verifier never
inspects the circuit DAG, only the HMAC tag.

**Fix hint**: this is the hardest finding. Real F-Chain attestation
requires a SNARK over the TFHE circuit (e.g., verifiable FHE; Lux already
has the `verifiable-fhe` research scaffold). For Dec 25, the only viable
options are:
- (a) Run F-Chain inside a TEE with attestation through A-Chain
  (`AChainAttest` lane), constraining trust to TEE compromise; or
- (b) Restrict F-Chain to a permissioned validator set whose stake bond is
  high enough to insure the entire confidential supply (and accept that
  this is a non-cryptographic security argument).
Option (a) ducks the FHE soundness question by externalising it to TEE.
Option (b) ducks it by making the attack non-economic. Real verifiable
FHE is a 6-12 month research integration, not a v0.54 patch.

---

### Q3.0-FHE-004 — None of the LP-013 v0.54 GPU TFHE kernels exist on disk

**Severity**: Critical.

**Files**:
- LP-013 §"Kernels (current as of v0.54)" lists 9 kernels:
  `tfhe_bootstrap`, `blind_rotate`, `blind_rotate_fused`,
  `external_product` ×3, `bsk_prefetch`, `fhe_gate`, `dag_executor`,
  `evm256`, `tfhe_keygen`, `tfhe_keyswitch`.
- Searches across `~/work/lux/cevm`, `~/work/lux/fhe`, `~/work/lux/precompile/fhe`,
  `~/work/lux/luxcpp` (does not exist), and the broader tree return **no
  matches** for `tfhe_bootstrap*`, `blind_rotate*`, `external_product*`,
  `drain_fhe*`, `fchain_fhe*`, `evm256*`. The only `.metal` files on disk
  are vendored React Native SVG filters in `node_modules`.

**Implication**: LP-013 v2 is design-only. The Go TFHE reference in
`lux/fhe` (CPU, ~108 ms / bootstrap on M1) is the entirety of the FHE
implementation. The 200 tx/s/GPU on H100 number in §"Performance targets"
is purely aspirational.

**Attack**: not an attack per se, but a deployment fraud risk: validators
running v0.54 will fall back to CPU TFHE (the LP says GPU is required for
the 500 ms block budget) — block production halts under load. The
2026-04-12 fheCRDT audit benchmarked the Go reference at **0.24 LWW
merges/sec** — 1,375× slower than what LP-013 promises.

**Fix hint**: either ship the kernels (months of work — porting OpenFHE's
`bootstrap` to Metal is non-trivial and the `cuFHE` reference is GPL) or
remove the v0.54 milestone and admit F-Chain is CPU-bound until real GPU
kernels land. **Do not** advertise GPU performance numbers in production
docs until a kernel exists.

---

### Q3.0-FHE-005 — `tfheVerify` is a deserialiser, not a verifier

**Severity**: Critical.

**Files**:
- `lux/precompile/fhe/fhe_ops.go:565-568`
- LP-067 §Transfer step 1: "Caller submits an encrypted amount with a ZK
  proof that the ciphertext encrypts a valid uint64."

**Scenario**:
```go
func tfheVerify(ct []byte, fheType uint8) bool {
    // Basic validation - check ciphertext can be deserialized
    return deserializeBitCiphertext(ct) != nil
}
```
There is no proof verification. There is no check that the ciphertext was
created with the network public key. There is no check that the encrypted
value lies in the claimed range (e.g., `[0, 2^64)` for `euint64`). There
is no binding between ciphertext and caller (otherwise an adversary could
re-submit someone else's ciphertext as their own).

**Attack chain (LP-067)**:
1. Adversary submits an encrypted transfer where the "amount" ciphertext
   claims to encrypt 5 (small) but actually encrypts $2^{64}-1$ (giant).
2. `tfheVerify` accepts because deserialisation succeeds.
3. Contract computes `enc_balance_sender − enc_amount` homomorphically.
4. Adversary's balance underflows to ~$2^{64}$, granting near-infinite
   confidential token balance.
5. Contract computes `enc_balance_receiver + enc_amount` → recipient's
   balance also wraps; adversary collaborates with a confederate
   recipient to launder the wrap-around value.

LP-067 names `inputProof` in the function signature but the contract
trivially passes whatever is supplied to `tfheVerify`, which discards it.

**Fix hint**: implement an actual zero-knowledge range proof
(`R1CS` over the LWE encryption circuit, or simpler: a Sigma protocol
proving the LWE sample's plaintext is in $[0, 2^{n})$). Bind the proof
to caller via Fiat-Shamir over `(caller, ct, range, public_key)`.
Reject without proof.

---

### Q3.0-FHE-006 — `performFHESealOutput` is a stub

**Severity**: Critical.

**Files**: `lux/precompile/fhe/fhe_ops.go:596-606`.

**Scenario**:
```go
func tfheSealOutput(ct, pk []byte, fheType uint8) []byte {
    // Seal output for a specific public key
    // In production, this would re-encrypt under the given public key
    // For now, just return the ciphertext with a header
    result := make([]byte, len(ct)+len(pk)+8)
    binary.BigEndian.PutUint32(result[0:4], uint32(len(pk)))
    binary.BigEndian.PutUint32(result[4:8], uint32(len(ct)))
    copy(result[8:8+len(pk)], pk)
    copy(result[8+len(pk):], ct)
    return result
}
```
The comment admits it. The "sealed" output is the original ciphertext
plus the requested public key. Under Q3.0-FHE-001 the network secret key
is public so the ciphertext is plaintext-equivalent; under any future
key-ceremony fix, the "seal" is still pointless because no
key-encapsulation has happened — the recipient gets a ciphertext under
the **network** key, not their own.

**Attack**: trivial — read the bytes after the header.

**Fix hint**: implement HPKE (`0x0703` already exists in the precompile
registry) over the recipient's public key, encapsulating a fresh AES key
that wraps a re-encryption of the plaintext. Or use proxy re-encryption.
Either way: do not ship the stub.

---

### Q3.0-FHE-007 — Block-STM reads ciphertexts as opaque bytes; concurrent fiber overwrites are not detected by the homomorphic circuit

**Severity**: High.

**Files**:
- LP-013 §"Wave-tick co-residency" (lines 128-143)
- LP-010 (QuasarSTM, MVCC arena)

**Scenario**: LP-013 explicitly says "Block-STM sees ciphertext as opaque
bytes for serializability." The MVCC arena's RW-set entry records a slot
and a version. If two concurrent fibers both target the same encrypted
slot:
- Fiber A: `SLOAD slot s → ct_old`; computes `ct_new = fhe.add(ct_old, x)`;
  writes back. Read entry: `(s, v_k)`. Write entry: `(s, v_{k+1})`.
- Fiber B (interleaved, before A's write commits): `SSTORE slot s ← ct_evil`
  (where `ct_evil` is a chosen-ciphertext crafted by an adversary).
- Fiber A's write is detected as a conflict (Block-STM repair) and re-runs
  with `ct_evil` as `ct_old`. The homomorphic circuit happily computes
  `fhe.add(ct_evil, x)` → state slot now contains `ct_evil + x`.

The homomorphic gate has no way to detect that `ct_evil` is malformed
(see Q3.0-FHE-005). Block-STM only enforces *serialisability* of writes,
not *semantic validity* of ciphertexts.

**Attack**: classic confidential ERC-20 "front-run with a rogue
ciphertext" — adversary submits a tx that writes `ct_evil` (a ciphertext
of a giant value crafted to cause a specific underflow when added to the
victim's balance). Block-STM serialises it before the victim's transfer.
Victim's transfer then operates on `ct_evil`, propagating the corruption
into the victim's balance.

**Fix hint**: every encrypted SSTORE must validate the ciphertext via the
range-proof gate from Q3.0-FHE-005 *before* the MVCC slot accepts the
write. The range proof must be tied to the writing caller, not the reader.

---

### Q3.0-FHE-008 — Key-rotation race across `fchain_fhe_root` epochs has no fence

**Severity**: High.

**Files**:
- LP-013 §"Key management" (lines 171-184)

**Scenario**: LP-013 says "key rotation is an M-Chain ceremony that emits
a new `fchain_fhe_root`; F-Chain finalizes by accepting a Quasar round
whose descriptor cites the new root." The spec does not define:
- The atomicity boundary (a single Quasar round, or a window?)
- Whether txs in flight at rotation use old key or new key
- What happens to ciphertexts under the old key after rotation
  (re-encryption? grandfathering? deletion?)

**Attack (rotation oracle)**: an adversary submits two near-identical
transfer ciphertexts $ct_0$ (under old key) and $ct_1$ (under new key)
back-to-back. Whichever succeeds tells the adversary the rotation epoch
boundary precisely. By repeating across many slots, the adversary builds
a time series of rotation events — useful for correlating off-chain TEE
maintenance windows, validator restart patterns, and KMS rotation
schedules.

**Attack (split-brain)**: if some fibers in the same wave-tick use the
old `fchain_fhe_root` and some use the new (because the descriptor was
swapped mid-tick by a malicious miner submitting two competing
descriptors), the resulting state root is non-deterministic across
validators. Either a `repair` round restores consistency (liveness loss)
or validators sign different roots (safety loss).

**Fix hint**: the ceremony must produce two outputs: (1) the new
`fchain_fhe_root`, (2) a signed cross-key re-encryption proof that maps
every active ciphertext slot to its new-key equivalent. Rotation lands
atomically as a Quasar round whose descriptor binds both. Until the
re-encryption is committed, the new key cannot decrypt and the old key
must not be deleted. Block this as a `HotLaneMode` to serialise.

---

### Q3.0-FHE-009 — M-Chain → F-Chain handoff lacks correctness binding

**Severity**: High.

**Files**:
- LP-013 §"Key management" (line 174)
- LP-019 §CGGMP21 / FROST (general MPC, no TFHE-specific path)
- LP-066 §"Key Generation" (mentions TEE mesh DKG but no LP for it)

**Scenario**: LP-013 says "TFHE keys (bootstrap key, key-switch key) are
generated via M-Chain MPC ceremony (LP-019 §TFHE keygen, LP-076)." LP-019
has no §TFHE keygen. LP-066 says "global FHE public key is generated via
a distributed key generation ceremony among TEE mesh participants (LP-065)"
— a different ceremony, not in scope of M-Chain.

The chain `M → F` of trust is therefore unspecified:
- Who runs the TFHE DKG? CGGMP21 produces ECDSA shares, not TFHE shares.
  TFHE thresholding requires a different DKG (e.g., TFHE Threshold from
  Mouchet, ASIACRYPT'22).
- What does `mchain_ceremony_root` commit to? If it commits to a CGGMP21
  group public key, that does not constrain a TFHE bootstrap key.
- The `MChainCGGMP21` cert lane only proves a CGGMP21 share is valid; it
  does not prove that a downstream TFHE key was constructed honestly
  from it.

**Attack**: a malicious M-Chain coordinator forges a `mchain_ceremony_root`
that commits to a TFHE bootstrap key generated by them alone (not via
DKG). They send the malicious key to F-Chain, which has no way to verify
that the key is the output of a t-of-n ceremony — `fchain_fhe_root`
just hashes whatever F-Chain accepts. Now the malicious party knows the
secret key for all confidential ERC-20 balances.

**Fix hint**: define an explicit TFHE DKG (LP-019 needs a §TFHE-DKG
section). The DKG must produce a verifiable transcript; F-Chain must
accept the new `fchain_fhe_root` only when the transcript hash is bound
to `mchain_ceremony_root` and the transcript is publicly auditable. Use
an existing scheme (Mouchet et al., or Boneh-Gentry-Halevi-Wang). Do not
ship without this LP.

---

### Q3.0-FHE-010 — F-Chain validator subset reduces 1/3-stake threshold

**Severity**: High.

**Files**:
- LP-134 §F-Chain (lines 276-288)
- LP-134 §"VM identifiers" (`F = lux:fhe`)

**Scenario**: F-Chain has its own validator set carved from P-Chain. The
spec is silent on the size of the F-Chain validator set relative to the
total Lux validator set. Quasar BFT tolerance is 1/3 of *that subset's*
stake, not of total Lux stake.

**Attack**:
- If F-Chain runs with, say, 21 validators carved from a 100-validator
  Lux mainnet, an adversary needs ≥ 8 of 21 = ~38% of F-Chain stake to
  halt F-Chain. That may be only ~8% of total Lux stake. **The cost of
  attacking F-Chain is 4× lower than the cost of attacking the rest of
  the network.**
- For confidentiality (Q3.0-FHE-009), if the F-Chain validator set is
  also the M-Chain TFHE-DKG ceremony set, the same adversary can corrupt
  the DKG with ≥ 1/3 of F-Chain stake (regardless of Quasar 2/3 BFT,
  because DKG only requires t honest parties out of n).

**Fix hint**: either (a) require F-Chain validators to be a strict
super-set of P-Chain top-stake validators (e.g., top 67% by stake), so
F-Chain compromise implies network compromise; (b) require F-Chain
validators to post additional bond proportional to total confidential
supply on the chain; (c) explicitly publish the F-Chain set and its
stake distribution and let dApps decide whether to trust it.

---

### Q3.0-FHE-011 — Synchronous decrypt is a deterministic oracle

**Severity**: High.

**Files**:
- LP-066 §"Decryption Protocol": "When t partial decryptions are
  collected, the result is aggregated and delivered to the callback.
  Decryption latency: ~2 seconds."
- `lux/precompile/fhe/contract.go:873-886` — implementation is **synchronous**,
  no callback.

**Scenario**: LP-066 specifies async threshold decryption. The
implementation does single-key sync decryption, returning the plaintext in
EVM return data with no nonce, no timestamp, no caller binding. Repeated
calls on the same handle return the same plaintext (deterministic). This
is a textbook decryption oracle.

**Attack (with Q3.0-FHE-002)**:
1. Adversary calls `decrypt(handle_v)` and gets victim's plaintext value.
2. If victim later updates the slot with a different ciphertext under the
   same key (e.g., same plaintext but fresh randomness), the adversary
   can correlate the new handle to the old plaintext via known-plaintext
   arithmetic: `decrypt(fhe.sub(new_handle, old_handle)) = delta`.
3. The chain of deltas reveals the entire balance trajectory.

**Fix hint**: remove the sync `decrypt` precompile entirely. Implement
`requestDecrypt(handle) → (requestId, event)`; off-chain threshold
decryptors deliver via signed callback; permit-bound delivery into a
caller-only state slot.

---

### Q3.0-FHE-012 — LP-067 underflow-revert pattern leaks comparison result

**Severity**: High.

**Files**:
- LP-067 §Transfer step 5: "If `sufficient` is false, the subtraction
  underflows and the transaction reverts."

**Scenario**: the contract intentionally lets underflow signal
insufficient balance via a revert. Whether the tx reverts is publicly
observable on-chain. **Therefore the comparison
`amount > balance(sender)` is publicly observable** — even though both
operands are encrypted. This trivially leaks bits about the sender's
balance.

**Attack**:
1. Adversary controls a faucet contract that lets them submit a transfer
   with a chosen plaintext amount $a$.
2. Adversary issues transfers of amount $a_1, a_2, \ldots$ to a probe
   address, observing which revert and which succeed.
3. Binary search recovers victim's balance to arbitrary precision in
   $O(\log_2 \text{balance})$ transfers.

**Fix hint**: the pattern must be `cmux` over the comparison. If
`sufficient = FHE.le(amount, balance)`, then:
- `new_sender = FHE.sub(balance, FHE.cmux(sufficient, amount, 0))`
- `new_recv   = FHE.add(recv,    FHE.cmux(sufficient, amount, 0))`

Tx never reverts due to balance; instead it commits a no-op when
insufficient. Then the *fact* of insufficiency is itself encrypted (the
recipient simply does not receive anything — observable but cleartext-
indistinguishable from a legitimate zero-amount transfer if the caller
issues such transfers as decoys). Combined with batched transfers and
nonce-gated visibility, the comparison oracle closes.

---

### Q3.0-FHE-013 — LP-067 leaks transfer graph (sender, receiver, gas)

**Severity**: High.

**Files**:
- LP-067 §"Security Considerations" item 3 already admits "metadata
  leakage: sender, receiver, and timing are still visible".

**Scenario**: even with perfect amount confidentiality, transfer-graph
analysis reveals account clusters, employer–employee relationships, DEX
arbitrage flows, etc. LP-067 punts to LP-068, but LP-068 only addresses
*cross-chain* private transfers, not *intra-chain*. There is no privacy
mixer for confidential ERC-20 in scope.

**Additional gas leak**: TFHE operations cost gas proportional to the
number of bootstraps, which depends on the bit-width and the operation.
Different ciphertext sizes (e.g., euint8 vs. euint64) reveal the *type*
of transfer. Even within euint64, the gas usage for the first SSTORE
into a fresh slot is higher than an update SSTORE — this distinguishes
"first incoming transfer to a wallet" from "subsequent transfer".

**Attack**: passive on-chain analysis. Standard graph-mining tools (used
on Bitcoin / Ethereum) work unchanged because the FHE only encrypts
amounts, not addresses or gas.

**Fix hint**:
- Combine LP-067 with a privacy mixer (LP-064 ShieldedPool) so that
  amounts AND addresses are confidential. LP-067 alone is not a privacy
  primitive; it is a confidentiality primitive.
- Pad SSTORE gas to a constant cost regardless of slot freshness (use a
  dedicated FHE storage subspace where every slot is pre-initialised
  with an encrypted zero at deploy time).

---

### Q3.0-FHE-014 — Apple M1/M2 GPU L2 cache shared between SM groups

**Severity**: Medium.

**Files**: LP-013 §"Performance targets" (Apple M1 Max numbers).

**Scenario**: Apple Silicon GPUs share L2 cache between SM groups (each
SM has its own L1 but contends for L2). TFHE bootstrap operates on the
RGSW × RLWE external product, which hits L2 hard for the BSK. A
co-resident GPU workload (e.g., a malicious WebGPU page running in
Safari, or another Metal compute task on a multi-tenant macOS validator)
can:
- Probe L2 latency (PRIME+PROBE) to learn which BSK rows are hot in a
  given bootstrap.
- Correlate hot rows across many bootstraps to recover the secret-key
  decomposition (BSK = bit-decomposed encryption of secret key under
  RGSW; cache hits leak the secret-key bits).

This is not science fiction: similar attacks against AES (Bernstein),
RSA (FLUSH+RELOAD), and AES-NI on Intel are well-established. Apple has
no documented L2 partitioning primitive.

**Attack complexity**: high (requires co-residency on a validator GPU)
but feasible if a validator runs other GPU workloads (LLM inference,
gaming, browser GPU, HPL) on the same M1 Max alongside `drain_fhe`.

**Fix hint**: F-Chain validators must run on dedicated GPUs with no
other workload. Document this as a hard requirement. Better: use H100
with MIG partitioning, where L2 is partitioned by hardware. On Apple
Silicon, validators must dedicate the entire GPU to `drain_fhe` and
disable Safari/Metal preemption. Until LP-013 specifies this, treat
Apple Silicon F-Chain validators as best-effort (testnet only).

---

### Q3.0-FHE-015 — Three `external_product` variants without correctness gate

**Severity**: Medium.

**Files**: LP-013 §"Kernels" — `external_product (×3 variants)`.

**Scenario**: the spec lists three variants of RGSW × RLWE external
product but does not specify a byte-equality requirement on outputs.
Variants typically differ in NTT layout, decomposition base, or BSK
prefetch strategy. If two variants produce *equivalent* but not
*byte-identical* RLWE samples (e.g., differing in noise term while
decrypting to the same plaintext), then validators using different
variants will produce different `state_root` values — fork.

**Attack**: a malicious miner crafts a tx that exercises a code path
where Variant A and Variant B diverge. Validators with Variant A produce
state root $r_A$; validators with Variant B produce $r_B$. The chain
forks. The miner times the attack to a low-quorum window to maximise
chain instability.

**Fix hint**: pick one variant. Period. The three-variant flexibility is
a performance optimisation that contradicts deterministic execution.
LP-013 must specify *the* variant (with parameters) and ban the others
on the cert path. If a variant is dropped later, gate it behind a hard
fork.

---

### Q3.0-FHE-016 — TLWE noise budget is not tracked anywhere

**Severity**: Medium.

**Files**:
- `lux/fhe/evaluator.go` (no noise tracking)
- LP-013 §Security: "TFHE gates run in constant time per bootstrap" (true
  but unrelated)
- 2026-04-12 fhecrdt-audit §"No noise budget monitoring" (already flagged)

**Scenario**: TFHE bootstrap resets noise to a known level *if applied
correctly*. But:
- The Go reference uses `eval.bootstrap` inside every gate, which is fine
  for boolean gates. For arithmetic ops (Add, Mul) over `BitCiphertext`
  (multi-bit), the bootstrap is applied per-bit. If a downstream caller
  treats a `BitCiphertext` as a unit and chains operations without
  bootstrap (e.g., scalar multiplication followed by addition), noise can
  accumulate.
- The chain of `fhe.add(fhe.add(fhe.add(...)))` in confidential ERC-20 —
  each `Add` does internal bootstrap, so this *should* be safe. But
  unverified.
- An adversary can construct a tx that intentionally exhausts noise via
  an unbootstrapped chain (if any exists), causing decryption to flip
  bits with attacker-chosen probability — a key-recovery oracle (Loftus-
  May-Smart-Vercauteren).

**Attack**: locate any unbootstrapped chain in the gate library; submit a
contract that drives it; observe the decryption-error pattern via the
Q3.0-FHE-002 oracle; recover the secret key (if Q3.0-FHE-001 weren't
already trivial).

**Fix hint**: add a property test that asserts every public TFHE op
(`Add`, `Sub`, `Mul`, `Div`, `Rem`, `Lt`, `Le`, `Eq`, `Cmux`, `Min`,
`Max`) leaves the output noise at exactly the post-bootstrap level. Run
in CI on every commit. Reject ops that fail the property.

---

### Q3.0-FHE-017 — Oblivious branching not specified in `evm256`

**Severity**: Medium.

**Files**: LP-013 §"Encrypted EVM (`evm256.metal`)" — "Branching (JUMPI on
encrypted condition) via fully oblivious evaluation of both branches,
then ciphertext-mux."

**Scenario**: "fully oblivious" requires:
1. Both branches execute regardless of condition.
2. Both branches consume the **same** number of gates / cycles / cache
   lines / memory accesses.
3. The mux is applied as a homomorphic gate, not a CPU select.

In SIMT (Apple Metal, NVIDIA CUDA), warp divergence on an encrypted
condition is not directly possible (the condition is a ciphertext bit,
not a hardware predicate), but **memory access patterns** can still
diverge if the two branches touch different state slots. The Block-STM
read set will differ, leaking which branch was "taken" via the RW set.

**Attack**: an adversary writes a contract:
```solidity
ebool cond = FHE.lt(victim_balance, threshold);
if (cond) sstore(slot_A, ...);
else      sstore(slot_B, ...);
```
After tx execution, the read/write set in the round descriptor reveals
whether `slot_A` or `slot_B` was written, leaking `victim_balance < threshold`.

**Fix hint**: the contract compiler must lower encrypted JUMPI to:
```solidity
v_A = compute_branch_A();
v_B = compute_branch_B();
sstore(slot_A, FHE.cmux(cond, v_A, sload(slot_A)));
sstore(slot_B, FHE.cmux(cond, sload(slot_B), v_B));
```
i.e., always read+write both slots, mux the result. The RW set then
includes both slots regardless of condition. This is expensive (~2× gas)
but is the only correct path for oblivious branching at the EVM level.

---

### Q3.0-FHE-018 — LP-068 cross-chain replay protection

**Severity**: Medium.

**Files**:
- LP-068 §"Cross-Chain Nullifier Sync" (line 56):
  `nullifier = Poseidon2(commitment ∥ spending_key ∥ sourceChainID)`

**Scenario**: the destination chain ID is **not** part of the nullifier.
A user deposits on chain `S`, withdraws on chain `D1`. The nullifier is
$N = H(\text{commitment} \| sk \| S)$, registered on $D1$. Now the
warp message also reaches $D2$ (or an attacker re-routes it). $D2$ has
not seen $N$, so the withdrawal succeeds again. The attacker drains
liquidity on $D2$.

LP-068 §Security item 4 claims "Cross-chain replay is prevented by
including the source chain ID in the nullifier" — but this prevents
*source-side* replay, not *destination-side* replay. The destination
chain ID being absent from the nullifier means the nullifier is the
same on every destination chain. A relayer can re-broadcast the same
warp message to multiple destinations.

**Fix hint**: include destination in the nullifier:
$N = H(\text{commitment} \| sk \| S \| D \| \text{sequence})$. Nullifier
is then unique per source-destination pair. Maintain a global nullifier
registry (B-Chain) that aggregates nullifiers across all chains; reject
any nullifier already seen on any destination.

---

### Q3.0-FHE-019 — SSTORE refund pattern leaks first-write vs. update

**Severity**: Medium.

**Files**: `lux/precompile/fhe/contract.go:920-994` (storeCiphertext
loop).

**Scenario**: the `storeCiphertext` function writes the ciphertext as a
sequence of 32-byte chunks via `stateDB.SetState`. EVM SSTORE has
different gas costs for fresh slots (20 000 gas) vs. update slots (5 000
gas) vs. zero-clear (refund 15 000 gas). The total gas for a confidential
ERC-20 transfer therefore reveals:
- Whether the sender's balance slot already existed (existing user vs.
  new user).
- Whether the recipient's balance slot already existed.
- The size class of the ciphertext (uint8 = 8 KB = 256 chunks vs.
  uint256 = 32 KB = 1024 chunks).

**Attack**: passive gas analysis. Surveillance is straightforward.

**Fix hint**: pre-allocate maximum-size slots at deployment time;
overwrite in place. Pad ciphertexts to a fixed size class (e.g., always
32 KB). Use SSTORE patterns that have constant gas cost (write 32 KB of
zeros first, then overwrite with ciphertext — accept the extra gas as the
cost of confidentiality).

---

### Q3.0-FHE-020 — Handle = `keccak256(ct)` collides on bit-identical ciphertexts

**Severity**: Low.

**Files**: `lux/precompile/fhe/contract.go:935-936`.

**Scenario**: `handle = keccak256(ct)`. Two ciphertexts with identical
bytes produce the same handle. Under randomised LWE encryption, identical
ciphertexts are negligible probability; but with the deterministic seed
in Q3.0-FHE-001, a deterministic-encryption mode (e.g.,
`tfheTrivialEncrypt(constant)`) collides for identical plaintexts. Two
separate users encrypting "10" trivially get the same handle; the second
user's encryption silently aliases to the first's slot.

**Fix hint**: handle should include caller and a sequence:
$H = \text{keccak256}(caller \| nonce \| ct)$.

---

### Q3.0-FHE-021 — `tfheRandom` is keyed by user-supplied seed

**Severity**: Low.

**Files**: `lux/precompile/fhe/fhe_ops.go:608-619` (called via
`handleRand`).

**Scenario**:
```go
func tfheRandom(fheType uint8, seed uint64) []byte {
    seedBytes := make([]byte, 32)
    binary.BigEndian.PutUint64(seedBytes[24:], seed)
    rng := fhe.NewFheRNG(params, secretKey, seedBytes)
    // ...
}
```
The caller supplies the seed. There is no entropy beyond the caller's
input. Two callers supplying the same seed produce the same encrypted
"random" value. A confidential gambling contract that reads `fhe.rand` is
trivially predictable.

Worse: the function uses `secretKey` (Q3.0-FHE-001 → public) plus the
caller's seed → the "random" output is deterministically computable
off-chain by anyone.

**Fix hint**: derive the seed from `(blockhash, tx_hash, salt)` and HKDF
through the threshold key. Or use a VRF (LP-019 already has FROST-VRF).
Never accept caller-controlled seeds for on-chain randomness.

---

### Q3.0-FHE-022 — `tfheTrivialEncrypt` is not trivial encryption

**Severity**: Info.

**Files**: `lux/precompile/fhe/fhe_ops.go:584-594`.

**Scenario**:
```go
func tfheTrivialEncrypt(plaintext *big.Int, toType uint8) []byte {
    ...
    ct := encryptor.EncryptUint64(plaintext.Uint64(), targetType)
    return serializeBitCiphertext(ct)
}
```
Comment says "Use encryptor for now (trivial encryption would be
noiseless)". Trivial encryption in TFHE is "embed the plaintext
directly with zero noise" — which would be safe for public constants.
The current code uses real encryption with real noise, wasting the noise
budget for what should be a freebie. Not a security bug, but a
correctness debt.

**Fix hint**: implement actual trivial encryption (noiseless RLWE sample
with the plaintext in the constant term). Document that trivial
encryption MUST NOT be used for secret data.

---

### Q3.0-FHE-024 — LP-013 v1's "21 GPU kernels" never had passing tests in v0.54 timeline

**Severity**: Info.

**Files**: LP-013 v1 (2025-10-01), LP-013 v2 (this LP). LP-013 v2 says
"v1.0 — 21 GPU TFHE kernels." No PASS evidence on Apple M1 Max for any
of the 21. The CUDA mirror in v0.55 ("same kernel signatures, different
SM indexing") is also empty.

This is a documentation truthfulness issue, not an exploit. Flagging so
ops/marketing does not repeat the 200 tx/s/GPU-on-H100 claim on the
production landing page on Dec 25.

---

### Q3.0-FHE-025 — `evm256` interpreter does not exist

**Severity**: Info.

**Files**: LP-013 §"Encrypted EVM (`evm256.metal`)". No file by that
name in the tree.

**Implication**: the LP-067 contract template that calls `fhe.add` and
`fhe.sub` resolves to the precompile-fhe Go path, not to an `evm256`
interpreter. The opcode-level encrypted EVM is design-only. LP-013 v0.56
(full opcode coverage including CALL family, LOGn) is unimplemented.

---

## Architectural concerns for FHE-on-Quasar

1. **TFHE soundness has no on-chain verification.** Quasar 3.0's cert
   pipeline is structured around verifying signatures (BLS, Ringtail,
   ML-DSA-Groth16) and `KnownTotalOrder`. An FHE attestation is a
   *different* class of statement: "this circuit was evaluated correctly
   on this ciphertext under this evaluation key, producing this output
   ciphertext". This requires verifiable FHE (a SNARK over a FHE circuit)
   or a TEE attestation (LP-065). The current design pretends a HMAC
   over a hash of (circuit, input, output, BSK_id) is enough — it isn't.

2. **F-Chain is the most centralised chain in the topology.** Because
   the secret key is held by the threshold (LP-066) or, currently,
   universally derivable (Q3.0-FHE-001), the security perimeter for
   confidentiality is the M-Chain DKG ceremony. A breach of the
   ceremony breaks every confidential balance ever encrypted. There is
   no per-tx forward secrecy; rotating the bootstrap key (Q3.0-FHE-008)
   does not re-protect old ciphertexts.

3. **Performance targets and reality differ by 1000× to 1.4 million×.**
   The fheCRDT audit measured 0.24 LWW-Register merges/sec on M1 Max.
   LP-013 promises 200 tx/s/GPU on H100 and ~5 tx/s on M1 Max. There is
   no kernel that delivers either number; the Go reference is 1,000×
   slower than the M1 Max claim. **This LP cannot be production-ready
   for Dec 25.**

4. **Quasar 3.0's "one GPU process for consensus, DEX, EVM, and FHE in
   lockstep" is incompatible with Q3.0-FHE-014.** GPU side-channel
   isolation requires *not* sharing the GPU between FHE and other
   workloads. Co-residency of `drain_fhe` with `drain_exec` on the same
   GPU (LP-013 §"Wave-tick co-residency") makes side-channel attacks
   possible from inside the EVM workload itself: an adversary's plaintext
   contract can probe the L2 cache while a victim's encrypted contract
   bootstraps. Either F-Chain runs on dedicated FHE-only GPUs, or the
   "lockstep" claim is incompatible with FHE security.

5. **The HMAC-keccak placeholder (LP-132 v0.38) is unsuitable for
   F-Chain at any version.** For BLS/Ringtail/ML-DSA, the placeholder
   is a temporary stand-in until v0.43–v0.45. For F-Chain, there is no
   "real verifier swap" planned, because verifiable FHE is not in any
   roadmap. **F-Chain cannot share the placeholder strategy.**

---

## Must-fix-pre-launch (Dec 25, 2025) — ordered

1. **Q3.0-FHE-001** — Replace deterministic-seed keygen with a real
   ceremony. *Blocker.* Without this, FHE provides zero confidentiality.
2. **Q3.0-FHE-002** — Remove the synchronous `decrypt` precompile;
   replace with permit-gated async threshold decryption.
3. **Q3.0-FHE-005** — Implement real input ZK proof in `tfheVerify`;
   bind to caller; reject ciphertexts without proof.
4. **Q3.0-FHE-006** — Implement `tfheSealOutput` with HPKE under the
   recipient's public key (or remove the API).
5. **Q3.0-FHE-009** — Define LP-019 §TFHE-DKG; bind `mchain_ceremony_root`
   to the TFHE bootstrap key transcript; F-Chain must verify the
   transcript before accepting a new `fchain_fhe_root`.
6. **Q3.0-FHE-003** — Either run F-Chain inside TEEs with attestation via
   A-Chain, OR restrict to a permissioned validator set with explicit
   bond-vs-confidential-supply ratio. Pure HMAC-keccak F-Chain attestation
   must not ship.
7. **Q3.0-FHE-012** — Replace underflow-revert in LP-067 transfer with
   `cmux`-based no-op-on-insufficient.
8. **Q3.0-FHE-015** — Pick one `external_product` variant; ban the other
   two on the cert path.
9. **Q3.0-FHE-018** — Include destination chain ID in LP-068 nullifier.
10. **Q3.0-FHE-007** — Validate every encrypted SSTORE through the input
    proof gate before MVCC slot accepts; do not let Block-STM commit
    unverified ciphertexts.

If any of {001, 002, 003, 005, 009} cannot land before Dec 25, **F-Chain
must be marked testnet-only and confidential ERC-20 / private teleport
must not be activated on mainnet.**

## Should-fix-post-launch (within 90 days)

11. Q3.0-FHE-004 — Ship at least the Apple Metal kernels, even if not
    optimal, so block-time targets are met.
12. Q3.0-FHE-008 — Atomic key rotation with cross-key re-encryption.
13. Q3.0-FHE-010 — Publish F-Chain validator set composition and bond.
14. Q3.0-FHE-011 — Async decryption with nonce/permit binding.
15. Q3.0-FHE-013 — Compose LP-067 with LP-064 (privacy mixer) for graph
    privacy.
16. Q3.0-FHE-014 — Document GPU dedication requirement for F-Chain
    validators.
17. Q3.0-FHE-016 — Property test for noise budget invariants.
18. Q3.0-FHE-017 — Compiler lowering for oblivious branching.
19. Q3.0-FHE-019 — Pad SSTORE gas to constant cost.

## Lower priority

20–25. Q3.0-FHE-020 through 025.

---

## References

- LP-013 v2 (this scope): `lux/lps/LP-013-fhe-gpu.md`
- LP-066: `lux/lps/LP-066-tfhe.md`
- LP-067: `lux/lps/LP-067-confidential-erc20.md`
- LP-068: `lux/lps/LP-068-private-teleport.md`
- LP-019: `lux/lps/LP-019-threshold-mpc.md`
- LP-134: `lux/lps/LP-134-lux-chain-topology.md`
- LP-132 (cert lanes, HMAC placeholder): `lux/lps/LP-132-quasar-gpu-execution-adapter.md` lines 204-214
- Go reference TFHE: `lux/fhe/`
- Precompile FHE: `lux/precompile/fhe/`
- Prior fhecrdt audit (corroborates noise/Solidity findings):
  `lux/audits/2026-04-12-fhecrdt-audit.tex`
- Prior red-swarm audit (C-03 keygen divergence, M-03 unauth decrypt):
  `lux/audits/2026-04-13-final-red-swarm.md` lines 57-76, 196-213.

---

Copyright (C) 2026, Lux Partners Limited. All rights reserved.
