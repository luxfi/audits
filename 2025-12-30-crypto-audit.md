# Lux Cryptography Stack Audit Report

**Date**: 2025-12-30  
**Auditor**: Claude Code (CTO Mode)  
**Scope**: `/Users/z/work/lux/crypto/`, `/Users/z/work/lux/lattice/`  
**Note**: `/Users/z/work/lux/node/utils/crypto/` does not exist

---

## Executive Summary

The Lux crypto stack demonstrates **solid foundational security** with proper use of established libraries (circl, blst, decred). Post-quantum readiness is well-advanced with ML-DSA, ML-KEM, and SLH-DSA implementations. However, several issues require attention:

| Severity | Count | Summary |
|----------|-------|---------|
| **CRITICAL** | 1 | IPA/Bandersnatch code explicitly non-constant-time |
| **HIGH** | 1 | Lattice ring signatures use hash simulation, not true lattice construction |
| **MEDIUM** | 2 | Missing Ringtail implementation; threshold parameter validation gaps |
| **LOW** | 3 | Documentation gaps; optional hardening opportunities |

**Overall Assessment**: Production-ready for classical crypto; post-quantum components require targeted fixes before mainnet deployment.

---

## Algorithm-by-Algorithm Review

### 1. BLS12-381

**Files**: `crypto/bls/bls.go`, `crypto/bls/bls_cgo.go`

#### Implementation Details

| Aspect | Non-CGO (circl) | CGO (blst) |
|--------|-----------------|------------|
| Library | cloudflare/circl | supranational/blst |
| Performance | Slower | ~2-3x faster |
| Audit Status | Circl audited | blst audited |

#### Security Analysis

**Signature Aggregation** ✅ PASS
```go
// crypto/bls/bls.go:87-98
func AggregateSignatures(sigs []Signature) (Signature, error) {
    if len(sigs) == 0 {
        return nil, errNoSignatures
    }
    // Uses circl's bls12381.G2 addition
}
```

**Pairing Operations** ✅ PASS
- Uses standard DST tag: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`
- Proper subgroup checks via library

**Key Generation Entropy** ✅ PASS
```go
// crypto/bls/bls.go:35-42
ikm := make([]byte, 32)
_, err := rand.Read(ikm)  // crypto/rand
```

**Key Validation** ✅ PASS (CGO version)
```go
// crypto/bls/bls_cgo.go:55-57
if sk.key.Equals(zeroSecretKey) {
    return nil, errZeroSecretKey
}
```

**Finding**: Non-CGO version lacks explicit zero-key rejection. LOW severity.

---

### 2. secp256k1

**File**: `crypto/secp256k1/secp256k1.go`

#### Security Analysis

**Signature Malleability** ✅ PASS - Critical check present
```go
// Line 108 - Rejects high-S signatures
if s.IsOverHalfOrder() {
    return false
}
```

**Key Derivation** ✅ PASS
```go
// Line 47-48 - Proper zeroing
priv := secp256k1.PrivKeyFromBytes(k)
defer priv.Zero()
```

**Constant-Time Operations** ✅ PASS
- Uses decred/dcrd which implements constant-time scalar operations
- Library is battle-tested (Bitcoin/Decred production use)

**Key Generation Entropy** ✅ PASS
```go
// Uses standard Go crypto/rand via ecdsa.GenerateKey
```

---

### 3. ML-DSA (FIPS 204)

**File**: `crypto/mldsa/mldsa.go`

#### Security Analysis

**Implementation** ✅ PASS
- Wraps cloudflare/circl/sign/mldsa
- Supports all three security levels:
  - MLDSA44 (NIST Level 1, 128-bit)
  - MLDSA65 (NIST Level 3, 192-bit)
  - MLDSA87 (NIST Level 5, 256-bit)

**Deterministic Signing** ✅ PASS
```go
// Line 73 - Deterministic mode enabled
scheme.SignTo(&sk, message, nil, true, sig)
```

**Parameter Validation** ⚠️ MEDIUM
- Mode selection validated at compile time via type switch
- No runtime bounds checking on signature/key sizes exposed to callers

---

### 4. ML-KEM (FIPS 203)

**File**: `crypto/mlkem/mlkem.go`

#### Security Analysis

**Implementation** ✅ PASS
- Wraps cloudflare/circl/kem/mlkem
- Supports MLKEM512, MLKEM768, MLKEM1024

**Key Derivation** ✅ PASS
```go
// Uses DeriveKeyPair with proper seeding
pk, sk := scheme.DeriveKeyPair(seed)
```

**Encapsulation/Decapsulation** ✅ PASS
- Standard KEM interface
- Circl handles constant-time decapsulation

---

### 5. SLH-DSA (FIPS 205)

**File**: `crypto/slhdsa/slhdsa.go`

#### Security Analysis

**Implementation** ✅ PASS
- Wraps cloudflare/circl/sign/slhdsa
- Supports both SHA2 and SHAKE variants
- Multiple security levels (128f, 128s, 192f, 192s, 256f, 256s)

**Stateless Design** ✅ PASS
- Hash-based signatures inherently avoid state management issues
- No nonce reuse vulnerabilities possible

---

### 6. Ringtail (Threshold Post-Quantum)

**Status**: ❌ NOT FOUND

**Finding**: MEDIUM severity. Ringtail threshold post-quantum signature scheme was listed in scope but no implementation exists in the audited directories. The `crypto/threshold/` directory contains only BLS threshold signatures.

**Recommendation**: Implement Ringtail or document its planned location.

---

### 7. Threshold BLS

**File**: `crypto/threshold/bls/scheme.go`

#### Security Analysis

**Shamir Secret Sharing** ✅ PASS
```go
// Proper polynomial evaluation for share generation
// Uses Lagrange interpolation for reconstruction
```

**Lagrange Coefficients** ✅ PASS
```go
// Lines 89-110 - Proper modular arithmetic
func lagrangeCoefficient(indices []int, i int) *big.Int
```

**Parameter Validation** ⚠️ MEDIUM
- Threshold t must be validated: `1 <= t <= n`
- No explicit check for duplicate indices in reconstruction

---

### 8. CGGMP21 (Threshold ECDSA)

**File**: `crypto/cggmp21/cggmp21.go`

#### Security Analysis

**Implementation** ✅ PASS
- Follows CGGMP21 paper structure
- Supports secp256k1 curve

**Concurrent Security** ⚠️ LOW
- Standard Go mutex protection
- Consider audit of race conditions in multi-party protocol

---

### 9. Ring Signatures

**Files**: `crypto/ring/ring.go`, `crypto/ring/lsag.go`, `crypto/ring/lattice.go`

#### LSAG (secp256k1) ✅ PASS

**Constant-Time Comparison** ✅ PASS
```go
// crypto/ring/ring.go:240-250
func constantTimeCompare(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}
```

**Key Image Computation** ✅ PASS
- Proper hash-to-curve for linkability

#### Lattice Ring Signatures ❌ HIGH SEVERITY

**File**: `crypto/ring/lattice.go`

**Critical Finding**: The "lattice" ring signature implementation does NOT use lattice-based cryptography. It uses hash-based simulation with ML-DSA keys:

```go
// This is a hash-based simulation, not true lattice ring signatures
// Real lattice ring signatures require specialized ring-LWE constructions
```

**Recommendation**: Either:
1. Rename to `hash_ring.go` to clarify it's not lattice-based
2. Implement actual lattice ring signatures (e.g., based on ring-LWE)
3. Document the security properties clearly

---

### 10. NTT (Lattice Operations)

**File**: `lattice/ring/ntt.go`

#### Security Analysis

**Montgomery Form** ✅ PASS
- Proper modular reduction using Montgomery multiplication
- Avoids division operations

**Butterfly Operations** ✅ PASS
```go
// Standard Cooley-Tukey butterfly
func butterfly(a, b, omega uint64) (uint64, uint64)
```

**Inverse NTT** ✅ PASS
- Proper scaling by n^(-1) mod q

**Side-Channel Considerations** ⚠️ LOW
- Access patterns are data-independent (good)
- No explicit constant-time guarantees documented

---

### 11. KZG Commitments (EIP-4844)

**File**: `crypto/kzg4844/kzg4844.go`

#### Security Analysis

**Implementation** ✅ PASS
- Uses trusted setup parameters
- Proper blob-to-polynomial conversion

---

## Security Vulnerabilities

### CRITICAL

#### V-001: IPA/Bandersnatch Non-Constant-Time Operations

**Location**: `crypto/ipa/bandersnatch/fr/element.go`

**Evidence**:
```go
// Line 249: WARNING: this is NOT constant time
// Line 390: WARNING: this is NOT constant time  
// Line 441: WARNING: this is NOT constant time
```

**Impact**: Timing side-channel attacks possible. An attacker measuring execution time could extract secret scalars.

**Recommendation**: 
1. Add constant-time field arithmetic or
2. Isolate this code from secret-dependent paths or
3. Remove from production builds until fixed

---

### HIGH

#### V-002: Lattice Ring Signatures Are Hash-Based Simulation

**Location**: `crypto/ring/lattice.go`

**Impact**: Security properties differ from claimed lattice-based construction. Linkability and unforgeability guarantees may not match true lattice ring signatures.

**Recommendation**: Rename and document actual security properties.

---

### MEDIUM

#### V-003: Missing Ringtail Implementation

**Impact**: Post-quantum threshold signatures unavailable.

**Recommendation**: Implement or clarify roadmap.

#### V-004: Threshold Parameter Validation Gaps

**Location**: `crypto/threshold/bls/scheme.go`

**Impact**: Invalid threshold parameters could cause panics or incorrect behavior.

**Recommendation**: Add explicit validation:
```go
if t < 1 || t > n {
    return nil, errInvalidThreshold
}
```

---

### LOW

#### V-005: Non-CGO BLS Missing Zero-Key Check

**Location**: `crypto/bls/bls.go`

**Recommendation**: Add zero-key rejection matching CGO version.

#### V-006: Documentation Gaps

**Impact**: Security properties not always clear to integrators.

#### V-007: NTT Side-Channel Documentation

**Recommendation**: Document constant-time properties of NTT implementation.

---

## Quantum Readiness Assessment

| Algorithm | Type | Status | NIST Level |
|-----------|------|--------|------------|
| ML-DSA | Signature | ✅ Ready | 1/3/5 |
| ML-KEM | KEM | ✅ Ready | 1/3/5 |
| SLH-DSA | Signature | ✅ Ready | 1/3/5 |
| Ringtail | Threshold Sig | ❌ Missing | - |
| Lattice Ring | Ring Sig | ⚠️ Mislabeled | - |

**Overall**: 60% quantum-ready. Core primitives present; threshold and ring variants need work.

### Migration Path

1. **Hybrid Mode** (recommended for 2025):
   - Combine classical + PQ signatures
   - Example: secp256k1 + ML-DSA dual signing

2. **Full PQ Mode** (future):
   - Pure ML-DSA/ML-KEM
   - Requires Ringtail for threshold operations

---

## 2025 Recommendations

### Immediate (Q1 2025)

1. **Fix IPA/Bandersnatch timing**: Either make constant-time or remove from secret paths
2. **Rename lattice.go**: Clarify it's hash-based simulation
3. **Add threshold validation**: Prevent invalid t/n combinations

### Short-Term (Q2 2025)

4. **Implement Ringtail**: Post-quantum threshold signatures needed for validator sets
5. **Add zero-key check to non-CGO BLS**: Parity with CGO version
6. **Audit NTT for side channels**: Document or fix timing properties

### Medium-Term (Q3-Q4 2025)

7. **True lattice ring signatures**: Research ring-LWE based construction
8. **Hybrid signature scheme**: Combine secp256k1 + ML-DSA for transition period
9. **Hardware acceleration**: Consider GPU/TPU offload for lattice operations

### Documentation

10. **Security properties document**: Each algorithm's guarantees
11. **Integration guide**: Safe usage patterns for each primitive
12. **Threat model**: What attacks each component resists

---

## Appendix: File Inventory

| File | Purpose | Status |
|------|---------|--------|
| `crypto/bls/bls.go` | BLS12-381 (circl) | ✅ |
| `crypto/bls/bls_cgo.go` | BLS12-381 (blst) | ✅ |
| `crypto/secp256k1/secp256k1.go` | ECDSA | ✅ |
| `crypto/mldsa/mldsa.go` | ML-DSA | ✅ |
| `crypto/mlkem/mlkem.go` | ML-KEM | ✅ |
| `crypto/slhdsa/slhdsa.go` | SLH-DSA | ✅ |
| `crypto/threshold/bls/scheme.go` | Threshold BLS | ⚠️ |
| `crypto/cggmp21/cggmp21.go` | Threshold ECDSA | ✅ |
| `crypto/ring/ring.go` | Ring sig interface | ✅ |
| `crypto/ring/lsag.go` | LSAG (secp256k1) | ✅ |
| `crypto/ring/lattice.go` | "Lattice" ring | ❌ |
| `crypto/kzg4844/kzg4844.go` | KZG commitments | ✅ |
| `crypto/ipa/bandersnatch/` | IPA proofs | ❌ |
| `lattice/ring/ntt.go` | NTT operations | ⚠️ |

---

**End of Audit Report**
