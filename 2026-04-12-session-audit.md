# Red Team Session Audit — 2026-04-12

**Auditor**: Red Team (adversarial security review)
**Scope**: Commits 2fb2cc7, 06e1fc3, VRF (recent), plus indexer/graph/explorer changes
**Method**: Static analysis, attack construction, crypto lens, systems lens

---

## Executive Summary

Reviewed 9 distinct change areas across precompile, indexer, graph, and explorer.
Found **1 critical**, **2 high**, **3 medium**, **2 low**, **3 info** findings.

The critical finding is a consensus-safety violation in the attestation precompile.
The high findings are a cache poisoning vector in FROST and an unbounded query amplification in graph resolvers.

---

## Findings

### [CRITICAL] Attestation precompile uses time.Now() — consensus-unsafe non-determinism

**File**: `/Users/z/work/lux/precompile/attestation/attestation.go:115,201,366,397,417`
**Adversary**: Any validator operator observing state divergence
**Attack**: The attestation precompile calls `time.Now()` at lines 115, 201, 366, 397, and 417. Each validator processes the same transaction at different wall-clock times. The `Timestamp` field in `GPUAttestation` and `AttestationQuote` structs, and the `expiresAt` calculation at line 417, all produce different values per validator.

Concrete scenario:
1. User calls `CreateAttestation` (selector 0x04000000)
2. Validator A processes at T=1712937600, computes `expiresAt=1712941200`
3. Validator B processes at T=1712937601, computes `expiresAt=1712941201`
4. Output bytes differ -> state root diverges -> chain split

This is the same class of bug as the ECIES/ML-KEM non-determinism (C-03/M-11) that was fixed in commit 617c285 for `pqcrypto` and 18e0a95 for `hpke`. The attestation precompile was not covered by that fix sweep.

**Impact**: Chain split. Any validator processing an attestation transaction at a different millisecond produces a different state root. This is exploitable by simply sending any attestation transaction.
**Fix**: Replace all `time.Now()` calls with `accessibleState.GetBlockContext().Timestamp()` to use the deterministic block timestamp. The `Run` method in `module.go` receives `accessibleState` but never passes it to the attestation functions. Refactor `VerifyNVTrust`, `VerifyTPM`, `VerifyCompute`, `CreateAttestation` to accept a `blockTimestamp uint64` parameter.
**Status**: Open

---

### [HIGH] FROST LiftX cache unbounded under concurrent load — cache poisoning via eviction

**File**: `/Users/z/work/lux/precompile/frost/contract.go:147-179`
**Adversary**: Attacker with transaction submission capability
**Attack**: The `liftXCache` is a `map[[32]byte]curve.Point` with a hard cap at 1024 entries (line 175: `if len(liftXCache) < 1024`). Once the cache is full, no new entries are added, but existing entries are never evicted.

Attack scenario:
1. Attacker sends 1024 FROST verify transactions with 1024 distinct public keys (cost: 1024 * ~55,000 gas = ~56M gas, feasible in a single block with 100M gas limit)
2. Cache is now permanently full with attacker-chosen keys
3. Legitimate validator public keys can never enter the cache
4. All subsequent legitimate FROST verifications pay the full LiftX cost (80% of verify)
5. This is a targeted DoS: attacker pays once, defenders pay forever

The cache also has a TOCTOU between `RLock` check and `Lock` write (lines 164-178): two goroutines can both see `cached=false`, both proceed to `Lock`, and both write the same key. While not exploitable for corruption (last-write-wins is fine for a cache), it causes unnecessary duplicate computation under contention.

**Impact**: Permanent performance degradation of FROST verification for all legitimate users. In a block with many FROST verifications (every block from validators), this forces worst-case execution time.
**Fix**: Use an LRU cache with bounded size instead of a grow-only map. The `golang.org/x/exp/maps` or a simple LRU ring suffices. Evict on LRU policy, not refuse-to-insert.
**Status**: Open

---

### [HIGH] Graph resolvers — unbounded pagination allows memory exhaustion

**File**: All 29 resolver packages under `/Users/z/work/lux/graph/resolvers/*/`
**Adversary**: Any GraphQL query submitter (unauthenticated)
**Attack**: Every resolver's `pl()` function parses the `first` argument via `fmt.Sscanf(fmt.Sprint(l), "%d", &limit)`. There is no upper bound on `limit`. A query like `{ utxos(first: 999999999) { ... } }` passes `limit=999999999` to `s.ListByType("UTXO", 999999999)`.

If the storage backend returns all matching records up to the limit, this causes:
1. Massive memory allocation for serializing 999M records
2. CPU exhaustion in JSON marshaling
3. Network saturation sending the response

The default `limit=100` is fine, but the override path has no cap. This is present in all 29 resolver packages identically (copy-paste pattern).

**Impact**: Remote DoS of the graph engine. A single unauthenticated GraphQL query can OOM the graph server.
**Fix**: Cap `limit` to a sane maximum (e.g., 1000) in the `pl()` function: `if limit > 1000 { limit = 1000 }`. Apply across all 29 resolver packages.
**Status**: Open

---

### [MEDIUM] pqcrypto deterministic seed — seed reuse produces identical ciphertext (by design, but no documentation of caller responsibility)

**File**: `/Users/z/work/lux/precompile/pqcrypto/contract.go:331-392`
**Adversary**: Contract developer who reuses seeds
**Attack**: The ML-KEM encapsulate function accepts a caller-provided 32-byte seed for deterministic randomness. This is correct for consensus safety. However, if a caller reuses the same seed with the same public key, the output ciphertext and shared secret are identical.

This is IND-CPA insecure when seeds are reused: an observer who sees two identical ciphertexts knows the same plaintext was encrypted. For ML-KEM specifically, seed reuse does not leak the private key (unlike ECDSA nonce reuse), but it does break ciphertext indistinguishability.

The gas cost is appropriate (6,000-10,000 depending on mode). The seed parameter itself is correctly extracted and bounded.

**Impact**: Privacy violation for callers who reuse seeds. Not a chain-split or fund-loss issue, but violates IND-CPA security for the affected transactions.
**Fix**: Add a check that the seed has not been used before (e.g., via state storage), or document prominently that callers MUST use unique seeds. A revert on duplicate seed would be the safest approach.
**Status**: Open (documentation issue at minimum)

---

### [MEDIUM] HPKE seal — GPU path computes Kyber encap then discards result

**File**: `/Users/z/work/lux/precompile/hpke/contract.go:407-454`
**Adversary**: N/A (waste, not exploitable)
**Attack**: The `singleShotSealGPU` function calls `lattice.KyberEncaps()` on the GPU (lines 441-447), synchronizes (line 449), then falls through to `singleShotSealCPU(params)` which repeats the entire HPKE pipeline including KEM encapsulation on CPU (line 453).

The GPU result (`ctTensor`, `ssTensor`) is never read back or used. The function allocates GPU memory, performs the KEM, syncs, then discards everything and runs the CPU path. This doubles the computation time when GPU is available.

This is not a security vulnerability but a gas accounting concern: the user pays gas for one encapsulation but the node performs two. On nodes with GPUs, this wastes compute resources and slows block processing.

**Impact**: Wasted computation (2x KEM operations). No consensus issue since both paths are deterministic and the CPU path produces the final result.
**Fix**: Either (a) extract the GPU KEM result and use it in the HPKE key schedule, or (b) remove the GPU path entirely until it can produce the full HPKE output, or (c) use GPU only for batch acceleration in the parallel block executor.
**Status**: Open

---

### [MEDIUM] Attestation module.go — Run() does not check readOnly for state-mutating operations

**File**: `/Users/z/work/lux/precompile/attestation/module.go:79-102`
**Adversary**: Smart contract calling attestation precompile via STATICCALL
**Attack**: The `Run()` method in `attestationPrecompile` dispatches to `CreateAttestation` (selector 0x04000000) and `VerifyCompute` (selector 0x03000000), both of which mutate global state (the verifier's device registry and job history). However, the `readOnly` parameter is never checked.

In a STATICCALL context (readOnly=true), the EVM expects the precompile to not modify state. While the attestation precompile's mutations are to in-memory Go state (not EVM storage), the principle is violated. If the verifier's state is later serialized or if the precompile is upgraded to write to EVM state, this becomes a consensus bug.

More concretely: `VerifyCompute` at line 313 calls `globalVerifier.RecordJobCompletion()` which modifies the global verifier even in a `readOnly` call. This means a `STATICCALL` to VerifyCompute has a side effect, which is incorrect.

**Impact**: State pollution from read-only calls. Could cause incorrect device status reports after STATICCALL-invoked verifications.
**Fix**: Check `readOnly` in the dispatch switch. For selectors 0x03000000 (VerifyCompute) and 0x04000000 (CreateAttestation), return error if `readOnly == true`.
**Status**: Open

---

### [LOW] VRF hashToCurveELL2 — variable-time loop leaks alpha length via timing

**File**: `/Users/z/work/lux/precompile/vrf/contract.go:242-277`
**Adversary**: Co-located process measuring precompile execution time
**Attack**: The `hashToCurveELL2` function uses try-and-increment: it iterates `ctr` from 0 to 254, attempting to decompress a hash output as an Edwards point. The number of iterations before success depends on the input `alpha`. A co-located attacker measuring execution time can determine how many iterations were needed, leaking information about `alpha`.

For VRF verification this is low severity because `alpha` is typically public (it's the VRF input). However, if this function is used in a privacy-preserving context where `alpha` should be hidden, the timing channel is exploitable.

The gas cost is fixed at `GasVerify = 20,000` regardless of iteration count, which means the attacker cannot observe the timing via gas metering. They would need wall-clock observation.

**Impact**: Minor timing side channel. Exploitable only with co-located measurement and only leaks information about public VRF inputs.
**Fix**: Use constant-time Elligator2 mapping (CFRG hash-to-curve spec, section 6.8.2) instead of try-and-increment. The Edwards25519 library supports `HashToCurve` directly.
**Status**: Open

---

### [LOW] Indexer WebSocket — no authentication on subscription

**File**: `/Users/z/work/lux/indexer/multichain/platform_indexer.go:184-243`
**Adversary**: Network attacker with access to the WS endpoint
**Attack**: The `runRealtimeLoop` function connects to the chain's WebSocket endpoint and subscribes to block notifications. There is no authentication header, no API key, and no TLS certificate verification on the WebSocket connection.

If the chain's WS endpoint is internal (expected), this is low risk. If the WS endpoint is exposed publicly, an attacker could:
1. Connect and subscribe to the same feed (information leak of block data, which is public anyway)
2. Cannot inject blocks because the indexer only reads
3. MITM the connection if not using WSS (inject fake block notifications)

The `Dialer` at line 190 uses default TLS settings which will verify certificates for WSS URLs.

**Impact**: If WS URLs use `ws://` (not `wss://`), block data could be MITM'd. The indexer would process attacker-controlled block data.
**Fix**: Enforce `wss://` for all non-localhost WS endpoints. Add a check in `runRealtimeLoop` that rejects `ws://` unless the host is `localhost` or `127.0.0.1`.
**Status**: Open

---

### [INFO] Explorer ChainSwitcher — dangerouslySetInnerHTML for SVG logos

**File**: `/Users/z/work/lux/explore/ui/snippets/topBar/ChainSwitcher.tsx:89,183`
**Adversary**: Admin who controls chain registry config
**Attack**: The ChainSwitcher renders SVG logos using `dangerouslySetInnerHTML={{ __html: current.branding.logoContent }}`. If `logoContent` contained `<script>` or event handlers (`onload`), this would be XSS.

However, after reviewing the chain registry (`configs/app/chainRegistry.ts`), all `logoContent` values are hardcoded SVG path strings in the source code (lines 145-220 of the registry). They are not derived from user input, API responses, or URL parameters.

The `explorerUrl` values are also hardcoded strings (lines 242-391) or built from `NEXT_PUBLIC_APP_HOST` env var (line 428). The `window.location.href = this.targetUrl` assignment at line 23 only navigates to these hardcoded URLs, so there is no open redirect vector.

The `highlightText` function used in search results correctly sanitizes via the `xss` library (confirmed at `lib/highlightText.ts:7`).

**Impact**: No current vulnerability. The dangerouslySetInnerHTML is safe because the content is developer-controlled. However, if the chain registry is ever populated from an API or database, this becomes a stored XSS vector.
**Fix**: No fix needed now. Add a comment noting that `logoContent` must remain developer-controlled. Consider using a sanitizer if the registry source changes.
**Status**: Verified-safe (with caveat)

---

### [INFO] SLH-DSA 12-mode tests — timing side channels not tested

**File**: `/Users/z/work/lux/precompile/slhdsa/modes_test.go` (from commit 2fb2cc7)
**Adversary**: N/A (test coverage gap)
**Attack**: The SLH-DSA precompile supports 12 parameter sets (6 SHA2 + 6 SHAKE). The modes test verifies that all 12 modes produce correct verification results. However, it does not measure execution time variance across modes or inputs.

SLH-DSA verification is hash-based with many internal hash evaluations (WOTS+ chains, Merkle tree traversal). The number of hash evaluations is data-dependent for some parameter sets. A timing test would measure whether verification time varies with signature content.

However, since the gas cost is fixed per mode (not per-signature-content), and the EVM does not expose wall-clock time to callers, exploiting this requires co-located measurement. The test gap is informational only.

**Impact**: None currently. Test coverage improvement opportunity.
**Fix**: Add benchmark tests (`go test -bench`) for each mode with varying message sizes to document performance characteristics.
**Status**: Verified-safe (gas model prevents EVM-visible timing)

---

### [INFO] Adapter rename (achain->ai etc) — no RPC method names in logs

**File**: `/Users/z/work/lux/indexer/multichain/platform_indexer.go`
**Adversary**: Log scraper
**Attack**: The adapter rename changed chain type names (e.g., `native` to `platform`, `achain` to `ai`). The RPC method names are constructed from the chain type (e.g., `ai.getLatestBlock`, `mpc.getLatestBlock`).

After reviewing the indexer code, RPC method names appear in error messages (via `fmt.Errorf`) but not in `log.Printf` calls. The log messages at lines 77 and 208 use `idx.config.ID` and `idx.config.Name`, not the RPC method string.

If the RPC method names leak (e.g., in error responses returned to API callers), they reveal internal chain architecture. However, the method names (`ai.getLatestBlock`, `bridge.getLatestBlock`) are not sensitive — they describe public chain functionality.

**Impact**: None. RPC method names are not sensitive and are not logged.
**Fix**: No fix needed.
**Status**: Verified-safe

---

### [INFO] FROST real-sig test — coverage assessment

**File**: `/Users/z/work/lux/precompile/frost/real_sig_test.go`
**Adversary**: N/A (test quality review)
**Attack**: The new test suite (`real_sig_test.go`, 243 lines) replaces the prior security-theater test that used sequential byte patterns as signatures. The new tests:

1. `TestFROSTVerify_RealValidSignature` — generates real Schnorr sig, asserts `result[31]==1` (line 127)
2. `TestFROSTVerify_RealCorruptedSignature` — flips bytes in R and z, asserts `result[31]==0` (lines 148-162)
3. `TestFROSTVerify_RealWrongMessage` — correct sig, different message hash (line 175)
4. `TestFROSTVerify_RealWrongPublicKey` — correct sig, different public key (line 188)
5. `TestFROSTVerify_Determinism` — 100 iterations produce identical output (line 208)
6. `TestFROSTVerify_ConcurrentSafety` — 100 goroutines (line 227)

Coverage gaps identified:
- No test for `threshold > totalSigners` (invalid threshold rejection)
- No test for `totalSigners = 0` edge case
- No test for `threshold = 0` edge case (covered by contract.go:111 but not tested from `real_sig_test.go`)
- No test for gas exhaustion (suppliedGas < requiredGas)
- The concurrent test at line 233 checks `result[31] != 1` but sends the result to the error channel even when `err == nil` — this means a "valid but result[31]==0" concurrent race is reported as `nil` error, which `require.NoError` will pass. The test should assert `result[31] == 1` inside the goroutine.

These are test quality issues, not security vulnerabilities.

**Impact**: The test is vastly better than the prior security-theater version. The identified gaps are edge cases that are handled correctly in the contract code but lack test coverage.
**Fix**: Add threshold/gas edge case tests. Fix the concurrent test to assert `result[31]==1`.
**Status**: Verified-safe (test quality improvement recommended)

---

### gas=0 Sentinel Migration Assessment

**Scope**: 8 packages added `gas_zero_test.go` files in commit 2fb2cc7.

I verified the gas=0 handling across all precompiles that were part of the migration. The pattern is:

```
RequiredGas returns 0 for invalid/short input
 -> Run checks suppliedGas < requiredGas
 -> When requiredGas == 0, the check passes (0 < 0 is false)
 -> Run proceeds with remainingGas = suppliedGas - 0 = suppliedGas
 -> Run returns error for invalid input, preserving gas
```

This is correct behavior: gas=0 from RequiredGas is a sentinel meaning "I cannot determine the cost because the input is malformed." The Run method then validates the input and returns an error. The caller's gas is preserved (not consumed).

The precompiles that were NOT part of this migration but follow the same pattern:
- `math/contract.go` — uses its own `ErrOutOfGas` (line 35), not `contract.ErrOutOfGas`. This is a minor inconsistency but functionally equivalent.
- `bls12381/contract.go` — uses EIP-2537 gas formula, returns 0 for < 2 pairs. Correct.

No precompile was found that returns a local error string instead of `contract.ErrOutOfGas`. The migration is complete.

**Status**: Verified-safe

---

## Summary

| Severity | Count | Findings |
|----------|-------|----------|
| CRITICAL | 1 | Attestation time.Now() consensus non-determinism |
| HIGH | 2 | FROST cache poisoning, Graph resolver unbounded pagination |
| MEDIUM | 3 | ML-KEM seed reuse, HPKE GPU waste, Attestation readOnly violation |
| LOW | 2 | VRF timing side channel, Indexer WS no auth |
| INFO | 3 | ChainSwitcher SVG (safe), SLH-DSA timing tests, FROST test gaps |

**Recommendation**: **fix-then-ship** -- the CRITICAL attestation `time.Now()` must be fixed before any chain that enables the attestation precompile. The FROST cache and Graph pagination should be fixed before production deployment.
