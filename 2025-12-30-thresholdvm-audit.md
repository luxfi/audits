# ThresholdVM (T-Chain) Security Audit Report

**Date**: 2025-12-30
**Scope**: `~/work/lux/node/vms/thresholdvm/`
**Auditor**: Claude (Automated Security Review)
**Classification**: Internal Security Assessment

---

## Executive Summary

ThresholdVM implements a threshold FHE (Fully Homomorphic Encryption) and MPC (Multi-Party Computation) chain for the Lux blockchain ecosystem. The implementation supports multiple cryptographic protocols including LSS, CGGMP21/CMP, BLS, FROST, EdDSA, and Ringtail (post-quantum).

### Security Posture: **MODERATE**

The codebase demonstrates sound cryptographic design with proper protocol implementations. However, several areas require attention before production deployment.

| Category | Risk Level | Issues Found |
|----------|------------|--------------|
| FHE Operations | Medium | 3 |
| DKG Protocol | Medium | 2 |
| Threshold Signatures | Low | 1 |
| Secret Sharing | Low | 1 |
| Permit System | Medium | 2 |
| Relayer | High | 3 |

---

## 1. FHE Operations Audit

### 1.1 Scheme Implementation

**Findings**:

The implementation uses CKKS (Cheon-Kim-Kim-Song) scheme exclusively via the lattice library's E2S (Encryption-to-Share) multiparty protocol.

```go
// fhe/integration.go
type ThresholdFHEIntegration struct {
    params    lattice.Parameters
    evaluator e2s.Evaluator
    threshold int  // default: 67
    total     int  // default: 100
}
```

**Observation**: TFHE and BGV schemes mentioned in audit scope are NOT implemented. Only CKKS is present.

**FINDING-FHE-001** (Medium): Missing TFHE/BGV Support
- The audit scope specified TFHE, CKKS, and BGV schemes
- Only CKKS is implemented
- **Risk**: Limited FHE flexibility; TFHE preferred for boolean circuits
- **Recommendation**: Document supported schemes clearly; consider TFHE for binary operations

### 1.2 GPU Acceleration

```go
// fhe/gpu_fhe.go
const (
    gpuMinN        = 8192   // Minimum ring degree for GPU
    gpuBatchThresh = 64     // Minimum polynomials for GPU batching
)
```

**FINDING-FHE-002** (Low): Hardcoded GPU Thresholds
- Batch thresholds are compile-time constants
- Different hardware may have different optimal crossover points
- **Recommendation**: Make thresholds configurable via genesis or runtime config

### 1.3 NTT Implementation

**FINDING-FHE-003** (Medium): NTT Cache Unbounded Growth

```go
// fhe/gpu_fhe.go
type GPUFHEAccelerator struct {
    nttContexts map[uint64]*NTTContext  // Unbounded cache
    mu          sync.RWMutex
}
```

- NTT contexts cached by `(N << 32) | logN` key
- No eviction policy or size limit
- **Risk**: Memory exhaustion with varied parameters
- **Recommendation**: Add LRU eviction or fixed-size cache

---

## 2. DKG Protocol Audit

### 2.1 Protocol Flow

The DKG implements a two-phase commit-share protocol:

```go
// fhe/lifecycle.go
type DKGState struct {
    CeremonyID   [32]byte
    Phase        DKGPhase  // Commit, Share, Complete, Failed
    CommitPhase  time.Time
    SharePhase   time.Time
    Timeout      time.Duration
}
```

**FINDING-DKG-001** (Medium): Timeout Race Condition

```go
// fhe/lifecycle.go - ProcessDKGMessage
if time.Now().After(dkg.SharePhase.Add(dkg.Timeout)) {
    l.failDKG(dkg.CeremonyID, "share phase timeout")
    return fmt.Errorf("share phase timeout")
}
```

- Timeout check is not atomic with state transition
- Concurrent goroutines may process messages after timeout
- **Risk**: Inconsistent DKG state across nodes
- **Recommendation**: Use atomic state transitions with compare-and-swap

### 2.2 Commit Phase Security

**FINDING-DKG-002** (Medium): Missing Commitment Binding Verification

```go
// fhe/lifecycle.go
func (l *LifecycleManager) ProcessDKGCommit(ceremonyID [32]byte,
    participant ids.NodeID, commitment []byte) error {
    // Commitment stored without cryptographic binding verification
    dkg.Commitments[participant] = commitment
}
```

- Commitments are stored without verifying cryptographic binding
- No Pedersen commitment verification present
- **Risk**: Malicious participant could substitute commitment
- **Recommendation**: Implement Feldman VSS or Pedersen commitment verification

---

## 3. Threshold Signatures Audit

### 3.1 Supported Protocols

| Protocol | Implementation | Security Level |
|----------|---------------|----------------|
| LSS (Lux Secret Sharing) | `protocols.go:LSSHandler` | 128-bit |
| CGGMP21/CMP | `protocols.go:CGGMP21Handler` | 128-bit |
| BLS | `protocols.go:BLSHandler` | 128-bit |
| FROST | `executor.go` | 128-bit |
| Ringtail | `protocols.go:RingtailHandler` | Post-quantum |

**FINDING-SIG-001** (Low): Inconsistent Error Handling in Protocol Handlers

```go
// protocols.go
func (h *CGGMP21Handler) Sign(keyShare KeyShare, message []byte) (Signature, error) {
    // Some paths return nil error with empty signature
    if session == nil {
        return nil, nil  // Should return explicit error
    }
}
```

- Some error paths return `(nil, nil)` instead of explicit error
- **Risk**: Silent failures in signing operations
- **Recommendation**: Always return explicit errors on failure

---

## 4. Secret Sharing Audit

### 4.1 Shamir's Secret Sharing

The LSS (Lux Secret Sharing) extends Shamir's scheme:

```go
// protocols.go
type LSSHandler struct {
    threshold int
    total     int
    curve     elliptic.Curve
}
```

**FINDING-SS-001** (Low): Threshold Parameter Validation

```go
// protocols.go
func NewLSSHandler(t, n int) (*LSSHandler, error) {
    if t > n {
        return nil, errors.New("threshold exceeds total")
    }
    // Missing: t > 0, n > 0, t >= 1 checks
}
```

- Edge cases for `t=0` or `n=0` not explicitly validated
- **Risk**: Invalid configuration could produce weak shares
- **Recommendation**: Add explicit bounds validation: `1 <= t <= n`

---

## 5. Permit System Audit

### 5.1 Permit Structure

```go
// fhe/registry.go
type Permit struct {
    Handle    [32]byte      // Ciphertext handle
    Grantee   common.Address
    Ops       uint8         // Bitmask: Decrypt|Reencrypt|Compute|Transfer
    Expiry    uint64        // Block number
    Signature []byte        // Owner signature
}

const (
    PermitOpDecrypt   = 1 << 0
    PermitOpReencrypt = 1 << 1
    PermitOpCompute   = 1 << 2
    PermitOpTransfer  = 1 << 3
)
```

**FINDING-PERMIT-001** (Medium): Permit Revocation Race

```go
// fhe/registry.go
func (r *Registry) RevokePermit(handle [32]byte, grantee common.Address) error {
    key := permitKey(handle, grantee)
    return r.db.Delete(key)
}
```

- No versioning or sequence numbers on permits
- Revocation is immediate deletion
- **Risk**: Race between revocation and in-flight operations using permit
- **Recommendation**: Add permit nonces and check in-flight operations

### 5.2 Replay Attack Surface

**FINDING-PERMIT-002** (Medium): Cross-Chain Permit Replay

```go
// fhe/registry.go
func (r *Registry) VerifyPermit(permit *Permit) error {
    // Verification does not include chain ID
    signer, err := RecoverSigner(permitHash(permit), permit.Signature)
}
```

- Permit signature does not bind to chain ID
- Same permit valid on mainnet and testnet
- **Risk**: Cross-chain replay attacks
- **Recommendation**: Include `chainID` in permit signature domain separator

---

## 6. Relayer Audit

### 6.1 Architecture

```go
// fhe/relayer.go
type Relayer struct {
    requestQueue chan DecryptRequest
    resultChan   chan DecryptResult
    warpSigner   warp.Signer
    decryptor    *ThresholdDecryptor
}
```

**FINDING-RELAY-001** (High): Unbounded Request Queue

```go
// fhe/relayer.go
func NewRelayer(config RelayerConfig) *Relayer {
    return &Relayer{
        requestQueue: make(chan DecryptRequest, 10000),  // Fixed buffer
    }
}
```

- 10,000 request buffer is hardcoded
- No backpressure mechanism to source chains
- **Risk**: Memory exhaustion under load; DoS vector
- **Recommendation**: Implement adaptive backpressure; rate limit by source

### 6.2 Warp Message Signing

**FINDING-RELAY-002** (High): Missing Message Validation Before Signing

```go
// fhe/relayer.go
func (r *Relayer) sendFulfillment(result DecryptResult) error {
    payload := result.Marshal()
    signedMsg, err := r.warpSigner.Sign(payload)
    // Signs without validating result came from valid session
}
```

- Results are signed without verifying originating session validity
- **Risk**: Attacker could inject arbitrary results for signing
- **Recommendation**: Validate session ID and participant set before signing

### 6.3 Cross-Chain Delivery

**FINDING-RELAY-003** (High): No Delivery Confirmation

```go
// fhe/relayer.go
func (r *Relayer) deliverResult(destChain ids.ID, signedMsg []byte) error {
    return r.sender.Send(destChain, signedMsg)
    // No confirmation or retry logic
}
```

- Fire-and-forget delivery without confirmation
- No retry mechanism for failed deliveries
- **Risk**: Lost decryption results; stuck user funds
- **Recommendation**: Implement delivery confirmation with exponential backoff retry

---

## 7. Security Check Results

### 7.1 Key Share Compromise Resistance

**Status**: PARTIAL

| Control | Implemented | Notes |
|---------|-------------|-------|
| Share encryption at rest | Yes | Database-level encryption |
| Share isolation in memory | Partial | Shares cleared after use, but not zeroed |
| Share refresh protocol | Yes | `RefreshKey` operation present |
| Proactive security | No | No automatic refresh scheduling |

**Recommendation**: Implement automatic proactive share refresh every epoch.

### 7.2 Decryption Oracle Attacks

**Status**: ADEQUATE

```go
// fhe/integration.go
type DecryptionSession struct {
    Handle      [32]byte
    Requester   common.Address
    Shares      map[ids.NodeID][]byte
    StartTime   time.Time
    Completed   bool
}
```

- Decryption requires valid permit verification
- Rate limiting via quota system in `vm.go`
- Session binding prevents share reuse

**Remaining Risk**: High-frequency authorized decryptions could leak information via timing analysis.

### 7.3 Side-Channel Leakage in FHE Ops

**Status**: PARTIAL

```go
// fhe/gpu_fhe.go - NTT operations
func (t *GPUNumberTheoreticTransformer) Forward(p ring.Poly, out ring.Poly) {
    // GPU timing may leak polynomial structure
}
```

| Vector | Mitigation | Status |
|--------|------------|--------|
| Timing (CPU) | Constant-time libraries | Yes |
| Timing (GPU) | No | **MISSING** |
| Power analysis | N/A (server) | N/A |
| Cache attacks | No specific mitigation | **MISSING** |

**Recommendation**: Add GPU timing noise injection; use constant-time NTT kernels.

### 7.4 DKG Manipulation

**Status**: PARTIAL

- Commitment phase implemented
- Missing: Zero-knowledge proofs for share correctness
- Missing: Complaint mechanism for invalid shares

**Recommendation**: Implement Feldman VSS with ZK proofs for share verification.

### 7.5 Replay Attacks on Permits

**Status**: NEEDS ATTENTION

| Attack Vector | Mitigation | Status |
|---------------|------------|--------|
| Same-chain replay | Block expiry | Yes |
| Cross-chain replay | Chain ID binding | **MISSING** |
| Time-based replay | Expiry enforcement | Yes |
| Nonce reuse | Permit nonces | **MISSING** |

**Recommendation**: Add chain ID to permit domain separator; implement nonce tracking.

---

## 8. Code Quality Observations

### 8.1 Positive Patterns

1. **Clean Interface Abstraction**: `ProtocolHandler`, `KeyShare`, `Signature` interfaces
2. **Explicit Error Types**: Domain-specific error types for debugging
3. **Mutex Discipline**: Consistent lock ordering in lifecycle manager
4. **Deferred Callbacks**: Avoids mutex deadlock on callbacks

### 8.2 Areas for Improvement

1. **Magic Numbers**: GPU thresholds, timeouts hardcoded
2. **Incomplete Validation**: Edge cases in parameter validation
3. **Missing Metrics**: No observability for security events
4. **Documentation**: Protocol security assumptions not documented

---

## 9. 2025 Recommendations

### Critical (Address Before Mainnet)

| ID | Finding | Effort | Priority |
|----|---------|--------|----------|
| RELAY-001 | Unbounded request queue | Medium | P0 |
| RELAY-002 | Missing message validation | Low | P0 |
| RELAY-003 | No delivery confirmation | Medium | P0 |
| PERMIT-002 | Cross-chain replay | Low | P0 |

### High Priority (Q1 2025)

| ID | Finding | Effort | Priority |
|----|---------|--------|----------|
| DKG-001 | Timeout race condition | Medium | P1 |
| DKG-002 | Missing commitment binding | High | P1 |
| PERMIT-001 | Permit revocation race | Medium | P1 |
| FHE-003 | NTT cache unbounded | Low | P1 |

### Medium Priority (Q2 2025)

| ID | Finding | Effort | Priority |
|----|---------|--------|----------|
| FHE-001 | Missing TFHE/BGV | High | P2 |
| FHE-002 | Hardcoded GPU thresholds | Low | P2 |
| SIG-001 | Inconsistent error handling | Low | P2 |
| SS-001 | Threshold validation | Low | P2 |

### Architectural Recommendations

1. **Proactive Share Refresh**: Implement automatic key share refresh every epoch to limit exposure window from compromised shares.

2. **Observability**: Add metrics for:
   - DKG ceremony success/failure rates
   - Decryption latency percentiles
   - Permit verification failures
   - Relayer queue depth

3. **Rate Limiting**: Implement per-address rate limits for:
   - Decryption requests
   - Permit creation
   - DKG ceremony initiation

4. **Formal Verification**: Consider formal verification of:
   - Secret sharing correctness
   - Threshold signature security proofs
   - FHE parameter selection

5. **Post-Quantum Migration Path**: Document migration strategy from classical to post-quantum threshold schemes using Ringtail.

---

## 10. Files Reviewed

| File | Lines | Coverage |
|------|-------|----------|
| `vm.go` | 1621 | Full |
| `protocols.go` | 591 | Full |
| `executor.go` | 503 | Full |
| `fhe/integration.go` | ~400 | Full |
| `fhe/lifecycle.go` | 1005 | Full |
| `fhe/registry.go` | 612 | Full |
| `fhe/relayer.go` | 708 | Full |
| `fhe/rpc.go` | 758 | Full |
| `fhe/warp_payloads.go` | 605 | Full |
| `fhe/gpu_fhe.go` | 437 | Full |
| `fhe/handler.go` | ~200 | Full |

---

## 11. Conclusion

ThresholdVM demonstrates competent cryptographic engineering with sound protocol choices. The primary concerns are in the relayer subsystem, which requires hardening before production deployment. The permit system needs chain ID binding to prevent cross-chain replay attacks.

**Recommended Actions**:
1. Address all P0 findings before testnet deployment
2. Engage external cryptographic audit for DKG and threshold signature implementations
3. Implement comprehensive observability before mainnet
4. Document security assumptions and threat model

---

*Report generated: 2025-12-30*
*Next review recommended: 2025-03-31 (Q1 2025)*
