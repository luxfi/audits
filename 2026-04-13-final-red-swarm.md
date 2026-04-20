# Final Red Team Audit: luxfi/precompile

**Date**: 2026-04-13
**Scope**: 33 canonical precompiles across all 11 layers
**Commits**: c81f2b3 (red-flagged fixes), a0f33ee (anchor collision fix), c02cbe1 (VRF), be53b08 (coverage), 06e1fc3 (PRIMER.md)
**Methodology**: Manual code review + static analysis of all precompile `Run()` paths, `RequiredGas()`, state access, and cryptographic operations.

**Summary**: 3 CRITICAL, 3 HIGH, 4 MEDIUM, 3 LOW, 3 INFO

---

## CRITICAL FINDINGS

### [CRITICAL] C-01: ML-KEM Encapsulate uses crypto/rand -- consensus split

**File**: `mlkem/contract.go:201`
**Class**: consensus
**Adversary capability**: Any EOA sending a transaction
**Exploit scenario**:

1. User calls ML-KEM precompile at `0x0200...07` with `OpEncapsulate` (0x01), mode 0x01 (ML-KEM-768), and a valid public key.
2. `encapsulate()` at line 201 calls `pk.Encapsulate()` with no seed parameter.
3. `luxfi/crypto/mlkem.PublicKey.Encapsulate()` internally uses `crypto/rand.Reader` to generate the encapsulation randomness.
4. Each validator generates different randomness, producing different (ciphertext, shared_secret) pairs.
5. Validators disagree on the EVM return value. Consensus split.

This was partially fixed for HPKE (commit c81f2b3 added `deriveEffectiveSeed` + `deterministicReader`) but the same fix was NOT applied to the ML-KEM precompile. The HPKE precompile correctly requires a caller-supplied 32-byte seed. ML-KEM does not.

**Impact**: Chain split on any ML-KEM encapsulate call. Every node produces a different output. Immediate liveness failure.
**PoC**: `cast call 0x0200...07 0x01 0x01 <1184_bytes_valid_pk>` -- each node returns different 1120 bytes.
**Fix**: Add mandatory 32-byte seed parameter to ML-KEM encapsulate input format (identical pattern to HPKE). Use `deriveEffectiveSeed(caller, seed)` and feed the result into `mlkem.EncapsulateDeterministic(pk, derivedSeed)`. If `luxfi/crypto/mlkem` does not expose a deterministic variant, add one.
**Verified by**: Direct code trace. `pk.Encapsulate()` has no seed parameter; the underlying Kyber implementation samples from `crypto/rand`.

---

### [CRITICAL] C-02: X-Wing Encapsulate uses crypto/rand -- consensus split

**File**: `xwing/contract.go:93`
**Class**: consensus
**Adversary capability**: Any EOA sending a transaction
**Exploit scenario**:

1. User calls X-Wing precompile at `0x2221` with `OpEncapsulate` (0x02) and a valid public key.
2. Line 93: `ct, ss, err := scheme.Encapsulate(pk)` calls `circl/kem/xwing.Scheme().Encapsulate()`.
3. circl's `Encapsulate` internally uses `crypto/rand` for both the X25519 ephemeral key and the ML-KEM-768 encapsulation randomness.
4. Each validator generates different `(ct, ss)`. Consensus split.

Same class as C-01 but on a different precompile. The X-Wing precompile was not touched in commit c81f2b3.

**Impact**: Chain split on any X-Wing encapsulate call.
**PoC**: `cast call 0x2221 0x02 <xwing_pk_bytes>` -- different output per node.
**Fix**: Add mandatory 32-byte seed. Use `scheme.EncapsulateDeterministic(pk, deterministicReader(deriveEffectiveSeed(caller, seed)))` or equivalent. circl supports `EncapsulateDeterministic` with an `io.Reader`.
**Verified by**: Direct code trace. `scheme.Encapsulate(pk)` passes nil randomness reader, defaulting to `crypto/rand`.

---

### [CRITICAL] C-03: FHE initTFHE generates keys from crypto/rand -- consensus divergence

**File**: `fhe/fhe_ops.go:31-53`
**Class**: consensus
**Adversary capability**: Any EOA sending the first FHE operation after node restart
**Exploit scenario**:

1. `initTFHE()` runs via `sync.Once` on the first FHE call after process start.
2. Line 42: `kg.GenKeyPair()` generates `secretKey` and `publicKey` using `crypto/rand`.
3. Every validator generates different FHE keys at startup.
4. All subsequent FHE operations (encrypt, add, mul, etc.) produce ciphertexts under different keys.
5. FHE ciphertext handles (stored as `common.Hash` of ciphertext bytes) differ across validators.
6. Any transaction that calls `fhe.add(handle1, handle2)` returns different results on each node.

Additionally, line 628 in `tfheGetNetworkPublicKey()` has a fallback that calls `rand.Read(result)` if `publicKey.MarshalBinary()` fails -- another consensus divergence path.

**Impact**: Complete consensus failure for all FHE operations. Every FHE ciphertext is node-specific.
**PoC**: Any FHE `asEuint64(42)` call returns a different handle on each node because the encryption key differs.
**Fix**: FHE keys MUST be derived from a deterministic seed committed on-chain (e.g., genesis config or a key-ceremony output stored in chain state). `initTFHE()` must accept a `[32]byte` master seed and derive all keys from it using HKDF. The `rand.Read` fallback in `tfheGetNetworkPublicKey` must be removed entirely (return an error instead).
**Verified by**: Direct code trace. `fhe.NewKeyGenerator(params)` followed by `GenKeyPair()` with no seed.

---

## HIGH FINDINGS

### [HIGH] H-01: bridge/gateway.go and dex/perpetuals.go use time.Now() in state-modifying paths

**File**: `bridge/gateway.go:164,194,215,247,293,378,453`; `dex/perpetuals.go:73,82,393`; `dex/teleport.go:143,161,435,514`; `attestation/attestation.go:115,201,366,397,417`
**Class**: consensus
**Adversary capability**: Any EOA interacting with bridge, perpetuals, or attestation precompiles
**Exploit scenario**:

1. `InitiateBridge()` at gateway.go:164 sets `CreatedAt: uint64(time.Now().Unix())`.
2. Two validators process the same transaction 50ms apart. Validator A sees `time.Now()` = 1744539600, Validator B sees 1744539601.
3. The `CreatedAt` field propagates into the `BridgeRequest` hash (used as request ID in the `Requests` map).
4. If the request ID or any downstream comparison depends on this timestamp, validators disagree on state.

Similarly, `teleport.go:143` uses `time.Now().UnixNano()` in `generateTeleportID()`, making teleport IDs non-deterministic across validators.

The PRIMER.md at line 225 explicitly claims: "timestamps come from block time, not `time.Now()`". This claim is false for these precompiles.

**Impact**: Potential consensus split on bridge, teleport, and perpetuals operations. Severity depends on whether these map values flow into on-chain state (which they do -- they're stored in in-memory maps that affect execution outcomes).
**Fix**: Replace all `time.Now()` calls in precompile execution paths with `accessibleState.GetBlockContext().Timestamp()`. The block timestamp is consensus-agreed.
**Verified by**: grep for `time.Now()` in non-test `.go` files under precompile/.

---

### [HIGH] H-02: FHE ciphertext store is in-memory, not persisted to chain state

**File**: `fhe/contract.go:920-953`
**Class**: state | consensus
**Adversary capability**: Any EOA using FHE precompile
**Exploit scenario**:

1. Contract A calls `fhe.asEuint64(42)`, receiving handle `0xabcd...`.
2. Handle is stored in `ctStore.data` (an in-memory `map[common.Hash][]byte`).
3. Contract A stores `0xabcd...` in EVM storage.
4. Node restarts. `ctStore` is empty. FHE keys are regenerated (see C-03).
5. Contract B reads `0xabcd...` from storage, calls `fhe.add(0xabcd..., 0x1234...)`.
6. `getCiphertext(0xabcd...)` returns `(nil, 0, false)`.
7. `performFHEOperation` returns `common.Hash{}` (zero hash).
8. Silently wrong result: add of two encrypted values returns zero.

This is not just a restart issue. Different nodes joining the network at different times never have the same `ctStore` contents.

**Impact**: FHE precompile is fundamentally broken for multi-node consensus. Ciphertexts exist only in the local process memory of the node that created them.
**Fix**: Ciphertext store must be backed by EVM state (`SetState`/`GetState` on the FHE contract address). Each ciphertext handle maps to a storage slot containing the serialized ciphertext. This is expensive (SSTOREs) but necessary for correctness.
**Verified by**: `ctStore` is a package-level `var` initialized with `make(map[...])`. No persistence mechanism.

---

### [HIGH] H-03: Ring size parsed as uint8 -- gas charged for 255 but ring can trigger O(n) EC mults

**File**: `ring/contract.go:114,173`
**Class**: gas
**Adversary capability**: Any EOA
**Exploit scenario**:

1. `RequiredGas()` at line 114 reads `ringSize` as `int(input[2])`, a single byte. Maximum 255.
2. Gas = `GasVerifyBase + 255 * GasVerifyPerMember` = `4000 + 255 * 2500` = `641,500` gas.
3. The actual ring verify loop (line 238-263) does 2 EC scalar multiplications + 2 EC additions per ring member on secp256k1.
4. For ringSize=255, that is 510 scalar mults + 510 additions, plus 255 hash-to-point (SVDW map, RFC 9380).
5. Each SVDW hash-to-point involves a modular square root (~200us on CPU). 255 of them = ~51ms.
6. The gas cost of 641,500 is far too cheap for 51ms of CPU work. A standard `ecrecover` (one EC operation) costs 3,000 gas.
7. An attacker can fill blocks with ring-sig verifications at below-cost gas, slowing block production.

**Impact**: Gas griefing. Attacker can significantly slow block processing at below-market-rate gas cost.
**Fix**: Increase `GasVerifyPerMember` for secp256k1 LSAG to at least 6,000 (reflecting 2 scalar mults per member at 3,000 each, which matches ecrecover pricing). Consider capping ring size at 64 or 128 in the precompile itself.
**Verified by**: Manual cost analysis. secp256k1 scalar mult benchmark is ~3,000 gas equivalent; LSAG does 2 per member but charges only 2,500.

---

## MEDIUM FINDINGS

### [MEDIUM] M-01: StableSwap Newton iteration with maxIterations=256 -- no gas scaling for iterations

**File**: `stableswap/contract.go:52,288`
**Class**: gas
**Adversary capability**: Any EOA
**Exploit scenario**:

1. StableSwap charges flat `GasBase = 5000` gas for all operations.
2. `computeD()` runs Newton's method with up to 256 iterations (line 288: `for range maxIterations`).
3. Each iteration performs multiple `big.Int` multiplications, divisions, additions on 256-bit numbers across `n` tokens.
4. With adversarial inputs (e.g., `amp` close to zero, highly imbalanced balances, `n=16` tokens), convergence can take many iterations.
5. 256 iterations * 16 tokens * 5 big.Int operations ~= 20,480 big.Int ops for 5,000 gas.
6. For comparison, MODEXP (precompile 0x05) charges gas proportional to modulus size and exponent.

Additionally, `computeY()` (called from `getDy`) runs its own Newton loop of up to 256 iterations, so a `getDy` call can trigger 512 total iterations for 5,000 gas.

**Impact**: Gas griefing on StableSwap. Attacker crafts pathological inputs that maximize iterations while paying minimal gas.
**Fix**: Gas should scale with `n` (number of tokens) and include a per-iteration component, or cap `n` at a small value (e.g., 4) and increase base gas to cover worst-case 256 iterations.
**Verified by**: Code inspection of `computeD` and `computeY` loops; both iterate up to 256 times.

---

### [MEDIUM] M-02: HPKE RequiredGas returns 0 for unknown operations -- free gas consumption

**File**: `hpke/contract.go:169`
**Class**: gas
**Adversary capability**: Any EOA
**Exploit scenario**:

1. `RequiredGas()` returns 0 for any operation byte that is not `OpSingleShotSeal` (0x20).
2. `Run()` at line 182 calls `RequiredGas()`, gets 0, deducts 0 gas.
3. `Run()` then hits the `default` case at line 200, returning an error.
4. The error path at line 204 returns `suppliedGas - gasCost` = `suppliedGas - 0` = full gas refund.
5. The call consumes zero net gas despite the EVM needing to dispatch, deserialize, and process the call.

This is a minor gas accounting issue (the error is returned so no state changes), but it violates the principle that failed precompile calls should consume at least the base gas.

The same pattern exists in multiple precompiles: `ring/contract.go:95,111`, `poseidon/contract.go:74`, `curve25519/contract.go:79`, `pasta/contract.go:77`, `babyjubjub/contract.go:100`.

**Impact**: Negligible economic impact (errors are cheap), but violates gas accounting invariant.
**Fix**: All `RequiredGas()` functions should return a minimum base gas (e.g., 100) for any non-empty input, even for invalid operations.
**Verified by**: Code inspection of RequiredGas default branches.

---

### [MEDIUM] M-03: FHE decrypt exposes plaintext in EVM return data -- breaks confidentiality model

**File**: `fhe/contract.go:192` (handleDecrypt selector), `fhe/fhe_ops.go:559-571`
**Class**: crypto
**Adversary capability**: Any contract that holds a ciphertext handle
**Exploit scenario**:

1. Contract A stores an FHE-encrypted balance as handle `H`.
2. Any contract (including malicious contract B) that knows handle `H` can call `fhe.decrypt(H)`.
3. `handleDecrypt` calls `tfheDecrypt(ct, ctType)` which uses the global `decryptor` to decrypt.
4. The plaintext is returned as a `*big.Int` in the EVM return data.
5. Since EVM return data is visible to the caller (and in trace logs), the encrypted value is now public.

There is no access control on which addresses can decrypt which ciphertext handles. The handle hash itself serves as the "capability", but handles are 32-byte keccak hashes that can be read from storage slots by anyone.

**Impact**: Any FHE-encrypted value can be decrypted by any contract that knows the handle, destroying the confidentiality guarantee of FHE.
**Fix**: `handleDecrypt` should be gated: only the original encrypting caller (or a threshold of designated decryptors) should be able to decrypt. Alternatively, remove `decrypt` from the on-chain precompile entirely -- decryption should happen off-chain via a threshold decryption protocol, not via an on-chain precompile that reveals plaintext in calldata.
**Verified by**: Code trace through `handleDecrypt` -> `performFHEDecrypt` -> `tfheDecrypt`. No caller authorization check.

---

### [MEDIUM] M-04: Anchor precompile allows any caller to submit for any appID -- no authorization

**File**: `anchor/contract.go:107-152`
**Class**: state
**Adversary capability**: Any EOA or contract
**Exploit scenario**:

1. Legitimate application registers appID `0xDEAD...` and submits anchor at height 1.
2. Attacker calls `submit(0xDEAD..., 2, 0xFFFF...)` with a garbage root hash.
3. The anchor precompile stores the garbage root at height 2 for appID `0xDEAD...`.
4. The legitimate application can no longer submit at height 2 (already taken) and must use height 3+.
5. Verifiers who query height 2 get a garbage root, believing the application anchored it.

The anchor precompile has no access control. Any address can submit anchors for any appID. The `appID` is a 32-byte hash with no on-chain registration or ownership concept.

**Impact**: Anchor integrity compromised. Attackers can front-run legitimate anchors and insert fake roots, breaking the monotonic trust chain for any CRDT application.
**Fix**: Add an `owner` mapping: the first `submit` for a given `appID` sets `msg.sender` as the owner. Subsequent submits require `caller == owner`. Alternatively, derive `appID` from `caller` address to prevent cross-caller collision.
**Verified by**: Code inspection. `submit()` only checks `readOnly` and height monotonicity, not caller identity.

---

## LOW FINDINGS

### [LOW] L-01: FROST liftXCache is an unbounded-in-practice cache with 1024 cap but no eviction

**File**: `frost/contract.go:148-179`
**Class**: state
**Adversary capability**: Contract calling FROST verify with many distinct public keys
**Exploit scenario**:

1. Attacker sends 1024 FROST verify calls with distinct public keys.
2. Cache fills to capacity (1024 entries).
3. All subsequent FROST verifications with new keys skip the cache (line 175: `if len(liftXCache) < 1024`).
4. The cache becomes useless for new keys while holding potentially stale entries.

This is a performance issue, not a security vulnerability. The cache is bounded and thread-safe.

**Impact**: Performance degradation after cache fills. No correctness impact.
**Fix**: Use an LRU cache instead of a fixed-size map with no eviction.
**Verified by**: Code inspection. Cache has insert-only policy.

---

### [LOW] L-02: Ed25519 verify returns nil on invalid input instead of error

**File**: `ed25519/contract.go:88-89`
**Class**: parsing
**Adversary capability**: None (informational)

When input length != 128, `Run()` returns `(nil, remainingGas, nil)` -- no error. This is the EVM convention for "verification failed" but differs from other precompiles (e.g., MLDSA returns an error for invalid input length). Inconsistent error reporting across precompiles could confuse Solidity developers who expect `revert` on malformed input.

**Impact**: Developer confusion. No consensus or security impact.
**Fix**: Standardize: either all verify precompiles return nil+nil on bad input (current Ed25519 behavior) or all return nil+error. Choose one and apply consistently.
**Verified by**: Comparison of error handling across ed25519, mldsa, frost, slhdsa, cggmp21.

---

### [LOW] L-03: MLDSA batch verify gas is decoupled from per-signature message length

**File**: `mldsa/contract.go:140-147`
**Class**: gas
**Adversary capability**: Contract submitting batch verify with large messages

`requiredGasBatch()` charges `BatchVerifyBaseGas + count * BatchVerifyPerSigGas` (50k + N * 40k). It does not account for per-message length. A batch of 10 signatures where each message is 1MB would cost the same gas as 10 signatures with 32-byte messages, despite vastly more hashing work.

**Impact**: Minor gas undercharging for large-message batch verifications.
**Fix**: Add per-byte gas component to batch verify: iterate the header to sum message lengths and add `totalMsgBytes * MLDSAVerifyPerByteGas`.
**Verified by**: Code inspection of `requiredGasBatch`.

---

## INFO FINDINGS

### [INFO] I-01: PRIMER.md claims "no crypto/rand" but SYMMETRIC_CRYPTO_ANALYSIS.md documents the HPKE bug

PRIMER.md line 344: "No crypto/rand...no non-deterministic library behavior."
SYMMETRIC_CRYPTO_ANALYSIS.md line 199 and 268: Documents the exact HPKE `crypto/rand` consensus bug and its fix.

The fix was applied to HPKE (commit c81f2b3). But the PRIMER claim is still false for ML-KEM (C-01), X-Wing (C-02), and FHE (C-03). Update PRIMER.md to accurately reflect the status.

---

### [INFO] I-02: GPU fast path in HPKE singleShotSealGPU is a no-op

**File**: `hpke/contract.go:431-478`

`singleShotSealGPU()` creates GPU tensors, calls `lattice.KyberEncaps()`, syncs, then... falls through to `singleShotSealCPU(params)` at line 477. The GPU result is computed but discarded. The function always returns the CPU result.

This is not a bug (the CPU path is correct and deterministic), but the GPU path is dead code that wastes GPU cycles when `accel` is available.

**Fix**: Either wire the GPU KEM result into the HPKE key schedule, or remove the GPU fast path until it's properly integrated.

---

### [INFO] I-03: BLS12-381 subgroup checks are correctly implemented

`bls12381/contract.go:101` calls `pt.IsInSubGroup()` for G1 points after `IsOnCurve()`. Line 149 does the same for G2 points. This is correct per EIP-2537 and prevents rogue-key and small-subgroup attacks on pairing inputs. Verified safe.

---

## VERIFICATION OF PRIOR RED FLAGS (commit c81f2b3)

### Flag 1: GPU non-determinism
**Status**: VERIFIED SAFE (with caveat).
GPU and CPU must produce identical mathematical results. The comment in `mldsa/contract.go:222-228` documents this correctly. However, the statement "deterministic across validators built the same way" is a consensus assumption that must be enforced at the operator level (all validators MUST use the same build tags). This is acceptable.

### Flag 2: Garbage keys
**Status**: VERIFIED SAFE.
All signature precompiles (mldsa, slhdsa, frost, cggmp21, ed25519) pass public keys through their respective library's `PublicKeyFromBytes()` or `UnmarshalBinary()` which validates key structure. Invalid keys return errors. Garbage keys do not verify; they do not crash.

### Flag 3: HPKE seed collision
**Status**: FIX VERIFIED.
`deriveEffectiveSeed(caller, raw)` at `hpke/contract.go:384-392` correctly domain-separates with `"HPKE_SEAL_v1" || caller.Bytes() || raw[:]`. Two different callers with the same raw seed produce different effective seeds. Same caller with same seed is deterministic (consensus safe).

**Attempted bypass**: Could an attacker force two contracts to share a caller address? No. The `caller` parameter comes from the EVM execution context (`msg.sender`), which is the direct caller of the precompile. Two different contracts always have different addresses. A delegatecall from proxy A to implementation B would use A's address as caller, which is correct (the proxy is the entity choosing the seed).

### Flag 4: init() double-register
**Status**: FIX VERIFIED.
`modules/registerer.go:219-230` now produces descriptive error messages including both the collision key and address. The fail-fast behavior was already present (returning error); the fix improves diagnostics.

### Flag 5: isLegacyFormat heuristic
**Status**: FIX VERIFIED.
`mldsa/contract.go:425-429` confirms both `isLegacyFormat()` and `RunLegacy()` are deleted. The comment explains the removal. All ML-DSA input now requires an explicit mode byte (0x44, 0x65, or 0x87). No bypass possible -- the dispatch in `Run()` at line 179 only accepts `OpBatchVerify` (0x10) or a valid mode byte.

---

## VERIFIED SAFE

The following components were examined and found to be correctly implemented:

- **BLS12-381 (bls12381/)**: Subgroup checks on G1 and G2 inputs. EIP-2537 compliant. No rogue-key attack surface.
- **Ed25519 (ed25519/)**: Standard library `crypto/ed25519.Verify()` for CPU path. Fixed-size 128-byte input prevents buffer issues.
- **Poseidon (poseidon/)**: gnark-crypto `poseidon2.Hash()` is deterministic. No randomness. Field element validation via `fr.Element.SetBytes()` which reduces modulo the BN254 scalar field order.
- **Pedersen (pedersen/)**: gnark-crypto point operations are deterministic. Commitment binding/hiding properties depend on the DLOG assumption.
- **Blake3 (blake3/)**: zeebo/blake3 is deterministic. Keyed hash and Merkle modes correctly implemented.
- **secp256r1 (secp256r1/)**: EIP-7212 P-256 verify. Standard ECDSA verification. No key generation on-chain.
- **sr25519 (sr25519/)**: Verify-only. ChainSafe go-schnorrkel. Deterministic.
- **VRF (vrf/)**: Verify-only (no proving). RFC 9381 ECVRF-EDWARDS25519-SHA512-ELL2. Correct domain separation tags. Hash-to-curve uses elligator2 (Edwards25519 native, not try-and-increment).
- **KZG4844 (kzg4844/)**: Uses go-kzg-4844 trusted setup. Deterministic polynomial evaluation and proof verification.
- **Anchor (anchor/)**: Deterministic keccak256 storage slot derivation. Monotonic height enforcement correct. (Auth issue flagged as M-04.)
- **CGGMP21 (cggmp21/)**: Verify-only precompile. No threshold signing on-chain.
- **Ringtail (ringtail/)**: Verify-only. Lattice signature verification is deterministic.
- **Pasta (pasta/)**: Pallas/Vesta point operations via gnark-crypto. Deterministic.
- **BabyJubJub (babyjubjub/)**: BN254 twisted Edwards operations. Deterministic.
- **Curve25519 (curve25519/)**: Point operations on Edwards25519 via filippo.io/edwards25519. Deterministic.
- **X25519 (x25519/)**: Diffie-Hellman verify-only (scalar mult). No key generation.
- **Quasar (quasar/)**: BLS aggregate, Verkle, Ringtail, hybrid verification. All deterministic verify-only.
- **Stableswap Newton convergence**: `maxIterations=256` with `|d - prevD| <= 1` termination is deterministic (same inputs always take the same number of iterations with `big.Int` arithmetic). Gas undercharging is M-01 but no consensus risk.

---

## Blue Handoff

**What Blue got right**:
- HPKE domain separation fix (c81f2b3) is cryptographically sound. The `deriveEffectiveSeed` construction is correct.
- Legacy format removal in MLDSA eliminates an ambiguous parsing path.
- BLS12-381 subgroup checks are complete and correct per EIP-2537.
- Anchor collision fix (a0f33ee) correctly separates FHE and anchor address ranges.
- Ring signature hash-to-point uses SVDW (RFC 9380) with proper domain separation tag.
- Module registerer error messages are now diagnostic enough to catch collisions at init time.

**What Blue missed**:
- ML-KEM and X-Wing have the same `crypto/rand` consensus bug that was fixed in HPKE.
- FHE subsystem is fundamentally non-deterministic (keygen from rand, in-memory ciphertext store).
- `time.Now()` in 4 precompile packages (bridge, dex/perpetuals, dex/teleport, attestation).
- No authorization model for anchor or FHE decrypt.
- Ring signature gas undercharging relative to actual EC operation cost.

**Fix priority for Blue**:
1. **C-01 + C-02**: Add deterministic seed to ML-KEM and X-Wing encapsulate (same pattern as HPKE).
2. **C-03 + H-02**: Redesign FHE key management (deterministic keygen from chain state) and ciphertext persistence (EVM state-backed store).
3. **H-01**: Replace all `time.Now()` in precompile execution paths with block timestamp.
4. **H-03**: Increase ring signature per-member gas to match EC operation cost.
5. **M-01**: Add iteration-aware gas to StableSwap.
6. **M-03**: Gate FHE decrypt with caller authorization.
7. **M-04**: Add appID ownership to anchor.

**Re-review scope**: C-01, C-02, C-03, H-01, H-02 after fixes.

---

RED COMPLETE. Findings ready for Blue.
Total: 3 critical, 3 high, 4 medium, 3 low, 3 info
Top 3 for Blue to fix:
1. ML-KEM + X-Wing encapsulate use crypto/rand (consensus split)
2. FHE keygen from crypto/rand + in-memory ciphertext store (consensus split)
3. time.Now() in bridge/perpetuals/teleport/attestation Run paths (consensus split)
Re-review needed: yes -- C-01, C-02, C-03, H-01, H-02
Recommendation: do-not-ship
