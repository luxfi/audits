# Lux Secondary VMs Security Audit Report

**Date:** 2025-12-30
**Auditor:** CTO (Automated)
**Scope:** BridgeVM, GraphVM, KeyVM, QuantumVM, ExchangeVM, ThresholdVM, ZKVM, AIVM, DexVM

---

## Executive Summary

This audit covers nine specialized Virtual Machines in the Lux ecosystem beyond the core PlatformVM/C-Chain. These VMs provide unique functionality for cross-chain bridging, graph queries, key management, post-quantum cryptography, UTXO exchange, threshold MPC, zero-knowledge proofs, AI compute, and decentralized exchange operations.

**Overall Assessment:** Mixed maturity levels. Several VMs have strong foundational implementations while others remain in early development with significant gaps.

---

## Status Matrix

| VM | Status | Implementation | Security | Tests | Documentation |
|----|--------|----------------|----------|-------|---------------|
| **BridgeVM (B-Chain)** | Alpha | 75% | Medium Risk | Partial | Good |
| **GraphVM (G-Chain)** | Alpha | 60% | Low Risk | Partial | Minimal |
| **KeyVM (K-Chain)** | Alpha | 65% | High Risk | Partial | Good |
| **QuantumVM (Q-Chain)** | Beta | 80% | Medium Risk | Present | Good |
| **ExchangeVM (X-Chain)** | Production | 95% | Low Risk | Comprehensive | Complete |
| **ThresholdVM (T-Chain)** | Beta | 85% | High Risk | Present | Complete |
| **ZKVM (Z-Chain)** | Alpha | 70% | High Risk | Minimal | Minimal |
| **AIVM (A-Chain)** | Alpha | 55% | Medium Risk | Missing | Minimal |
| **DexVM (D-Chain)** | Beta | 80% | Medium Risk | Present | Good |

---

## Detailed VM Assessments

### 1. BridgeVM (B-Chain) - MPC Cross-Chain Bridge

**Location:** `/vms/bridgevm/`

**Purpose:** MPC-based cross-chain bridge using threshold CMP protocol.

**Implementation Status:**
- [x] Core VM lifecycle (Initialize, Shutdown, handlers)
- [x] LP-333 opt-in signer set management (100 signers max)
- [x] Signer registration and waitlist
- [x] Signer replacement with reshare trigger
- [x] Slashing mechanism for misbehaving signers
- [x] Bridge request/response structures
- [ ] Actual MPC keygen execution (TODO)
- [ ] Actual signing protocol execution (TODO)
- [ ] Cross-chain message verification (TODO)
- [ ] Chain client implementations (placeholder)

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| CRITICAL | **MPC keygen not implemented** - mpcConfig populated during keygen placeholder | vm.go:294 |
| HIGH | **No signature verification** - Cross-chain signatures not validated | vm.go:576-590 |
| HIGH | **Bond amount not enforced** - 100M LUX bond parsed but not verified on-chain | vm.go:643-648 |
| MEDIUM | **Daily limits not enforced** - dailyBridgeLimit in config but no tracking | BridgeConfig |
| MEDIUM | **No warp message verification** - AppRequestFailed takes warp.Error but unused | vm.go:487-489 |
| LOW | **Placeholder chain clients** - No actual chain connectivity | vm.go:305-311 |

**LP-333 Compliance:** Properly implements opt-in signer model with 2/3 threshold. Reshare only triggers on slot replacement.

**Recommendations:**
1. Integrate actual threshold CMP keygen/sign from `github.com/luxfi/threshold`
2. Implement proper bond verification via P-Chain queries
3. Add warp message validation for cross-chain verification
4. Implement rate limiting and daily volume tracking

---

### 2. GraphVM (G-Chain) - Read-Only Graph Database

**Location:** `/vms/graphvm/`

**Purpose:** Cross-chain GraphQL query layer for blockchain data.

**Implementation Status:**
- [x] Core VM lifecycle
- [x] GraphQL query parser (simplified)
- [x] Built-in resolvers (block, tx, account, balance)
- [x] DEX resolvers (Uniswap v2/v3 subgraph compatible)
- [x] Query depth limiting
- [x] Timeout configuration
- [ ] Block building (returns errNotImplemented)
- [ ] Subscription support (structure only)
- [ ] Cross-chain data federation
- [ ] Data indexing pipeline

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| HIGH | **No authentication** - GraphQL endpoint has no auth layer | vm.go:236-244 |
| MEDIUM | **Regex DoS potential** - Query parser uses regex without limits | graphql.go:203 |
| MEDIUM | **Unbounded iteration** - resolveIterate capped at 1000 but still large | graphql.go:539-545 |
| LOW | **Read-only by design** - Mutations rejected (correct behavior) | graphql.go:199 |
| LOW | **JSON injection in args** - Args parsed without sanitization | graphql.go:364-377 |

**Positive:**
- Enforces read-only access (mutations rejected)
- Query depth limiting prevents complexity attacks
- Result size limiting prevents memory exhaustion

**Recommendations:**
1. Add API key or JWT authentication for GraphQL endpoint
2. Implement proper GraphQL parser (use graphql-go library)
3. Add rate limiting per client
4. Implement data indexing background workers

---

### 3. KeyVM (K-Chain) / KMSVM - Post-Quantum Key Management

**Location:** `/vms/kchainvm/` and `/vms/kmsvm/` (duplicates)

**Purpose:** Distributed key management using ML-KEM/ML-DSA post-quantum cryptography.

**Implementation Status:**
- [x] Core VM lifecycle
- [x] ML-KEM key generation (512/768/1024)
- [x] ML-DSA signing support (structure)
- [x] Threshold key sharing structure
- [x] Key metadata management
- [x] Encrypt/encapsulate operations
- [ ] Actual secret sharing (placeholder)
- [ ] Key reconstruction from shares
- [ ] Database persistence (TODO markers)
- [ ] BLS threshold signing (placeholder)

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| CRITICAL | **No actual secret sharing** - Threshold values stored but not used | vm.go:276-284 |
| CRITICAL | **XOR encryption insecure** - Demo encryption uses XOR with repeated key | vm.go:400-407 |
| HIGH | **Private keys in memory** - Keys cached without secure memory | vm.go:250-251 |
| HIGH | **Database persistence not implemented** - saveKeyMetadata is placeholder | vm.go:572-575 |
| MEDIUM | **Validator list from config** - No dynamic validator discovery | vm.go:279 |
| LOW | **Duplicate VMs** - kchainvm and kmsvm are identical copies | files |

**Post-Quantum Status:**
- Uses `github.com/luxfi/crypto/mlkem` for real ML-KEM-768/1024
- Mode selection based on algorithm version
- Key sizes match NIST standards

**Recommendations:**
1. Implement Shamir secret sharing for threshold key distribution
2. Replace XOR demo encryption with AES-GCM using KEM shared secret
3. Use secure memory allocation for private keys (mlock)
4. Consolidate kchainvm and kmsvm into single implementation
5. Implement proper database persistence

---

### 4. QuantumVM (Q-Chain) - Post-Quantum Consensus

**Location:** `/vms/quantumvm/`

**Purpose:** Post-quantum signatures using ML-DSA (Dilithium) for quantum-safe finality.

**Implementation Status:**
- [x] Core VM lifecycle
- [x] ML-DSA signature implementation (MLDSA44/65/87)
- [x] Quantum stamp generation with SHA-512
- [x] Signature verification with CIRCL
- [x] Parallel verification support
- [x] Transaction pool management
- [x] Hybrid P/Q bridge interface
- [x] Block building with quantum signing
- [ ] Height tracking (placeholder)
- [ ] Last accepted persistence (placeholder)
- [ ] Genesis parsing

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| HIGH | **Quantum stamp binding weak** - Only verified through signature | signer.go:234-241 |
| MEDIUM | **Nonce not tracked** - Random noise in stamp but no replay protection | signer.go:220-228 |
| MEDIUM | **Height tracking missing** - getHeight() returns 0 | vm.go:466-468 |
| LOW | **Stamp window configurable** - Could be set too large | signer.go:180 |

**Cryptographic Implementation:**
- Real ML-DSA via `github.com/luxfi/crypto/mldsa`
- Supports NIST security levels 2, 3, 5
- Proper key generation using crypto/rand
- Signature caching with LRU

**Hybrid Bridge:**
- Interface for P-Chain BLS + Q-Chain Ringtail integration
- StampBlock/VerifyStamp for cross-chain finality
- Bridge set by chain manager after initialization

**Recommendations:**
1. Implement proper nonce tracking to prevent replay attacks
2. Add state persistence for last accepted block
3. Strengthen quantum stamp verification
4. Complete hybrid finality integration with P-Chain

---

### 5. ExchangeVM (X-Chain) - UTXO Asset Exchange

**Location:** `/vms/exchangevm/`

**Purpose:** UTXO-based asset creation and exchange (X-Chain XVM).

**Implementation Status:**
- [x] Full VM lifecycle
- [x] UTXO state management
- [x] Asset creation and transfer
- [x] Import/export transactions
- [x] DAG consensus integration
- [x] Network gossip handling
- [x] Wallet service
- [x] Transaction indexing
- [x] Linearization support
- [x] Warp validator integration

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| LOW | **No atomic swaps** - Cross-chain atomicity relies on shared memory | network/atomic.go |
| LOW | **Indexer uses baseDB** - Bypasses versiondb for visibility | vm.go:388-394 |
| INFO | **Feature complete** - Most mature secondary VM | - |

**Assessment:** Production-ready. This is the most mature secondary VM with comprehensive test coverage and proper error handling.

**Recommendations:**
1. Consider atomic swap protocol enhancement
2. Monitor indexer consistency with versiondb

---

### 6. ThresholdVM (T-Chain) - MPC as a Service

**Location:** `/vms/thresholdvm/`

**Purpose:** Threshold MPC services for all Lux chains.

**Implementation Status:**
- [x] Core VM lifecycle
- [x] Multiple protocol support (LSS, CMP, FROST, Ringtail)
- [x] Protocol registry and executor
- [x] Key management with generations
- [x] Signing session management
- [x] Chain authorization/permissions
- [x] Quota tracking per chain
- [x] FHE integration layer
- [x] Warp cross-chain messaging
- [ ] Protocol execution completion (partial)
- [ ] Key rotation automation

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| HIGH | **Signing quotas bypassable** - Daily limits in config but reset tracking unclear | vm.go:125-126 |
| MEDIUM | **Session expiry not enforced** - ExpiresAt stored but cleanup unclear | SigningSession |
| MEDIUM | **Key rotation not automated** - Period configured but no scheduler | ThresholdConfig |
| LOW | **Pre-hash requirement optional** - Can sign raw messages if not required | ChainPermissions |

**Protocol Support:**
- LSS (Lux Secret Sharing)
- CMP (CGGMP21 threshold ECDSA)
- FROST (Schnorr threshold)
- Ringtail (post-quantum threshold)

**Recommendations:**
1. Implement session cleanup goroutine or block-driven expiry
2. Add automated key rotation scheduler
3. Enforce pre-hash requirement by default
4. Add audit logging for all signing operations

---

### 7. ZKVM (Z-Chain) - Zero-Knowledge Privacy

**Location:** `/vms/zkvm/`

**Purpose:** Privacy-preserving UTXO transactions with ZK proofs.

**Implementation Status:**
- [x] Core VM lifecycle
- [x] UTXO database management
- [x] Nullifier tracking (double-spend prevention)
- [x] State tree (Merkle commitments)
- [x] Proof verifier structure
- [x] FHE processor integration
- [x] Address manager for stealth addresses
- [x] Mempool for pending transactions
- [ ] Actual ZK circuit implementation
- [ ] Trusted setup management
- [ ] FHE coprocessor completeness

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| CRITICAL | **ZK circuits not implemented** - ProofVerifier placeholder | proof_verifier.go |
| CRITICAL | **No trusted setup** - Required for Groth16 not present | ZConfig |
| HIGH | **FHE verifier placeholder** - VerifyFHEOperations may not work | vm.go:450-452 |
| MEDIUM | **Nullifier could leak** - Stored in database without encryption | nullifier_db.go |
| LOW | **Proof cache size configurable** - Could be set too small | ZConfig |

**Privacy Features:**
- Confidential transfers (enabled by config)
- Private/stealth addresses
- Multiple proof systems (Groth16, PLONK)
- FHE for encrypted computation

**Recommendations:**
1. Integrate actual ZK circuit library (gnark or similar)
2. Implement trusted setup ceremony tooling
3. Encrypt nullifier database or use secure enclave
4. Complete FHE processor with real operations

---

### 8. AIVM (A-Chain) - AI Compute Attestation

**Location:** `/vms/aivm/`

**Purpose:** AI compute task management with TEE attestation.

**Implementation Status:**
- [x] Core VM lifecycle
- [x] Provider registration
- [x] TEE attestation verification (nvtrust)
- [x] Task submission/results
- [x] Merkle root for Q-Chain anchoring
- [x] Reward claiming structure
- [ ] Block building (not implemented)
- [ ] Block storage (not implemented)
- [ ] Model registry completeness
- [ ] Task matching/scheduling

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| HIGH | **No block consensus** - Blocks defined but not built/verified | Block struct |
| HIGH | **External dependency** - Relies on github.com/luxfi/ai package | vm.go:34-36 |
| MEDIUM | **Trust score threshold** - MinTrustScore of 50 may be too low | DefaultConfig |
| MEDIUM | **GPU attestation optional** - Could register without hardware proof | vm.go:264-274 |
| LOW | **No task verification** - Results accepted without validation | vm.go:308-317 |

**TEE Support:**
- CPU: SGX/SEV-SNP/TDX (planned)
- GPU: nvtrust (local, no cloud dependency)
- Trust score system for providers

**Recommendations:**
1. Implement proper block building and consensus
2. Make TEE attestation mandatory by default
3. Add task result verification (ZK proofs or committee)
4. Increase minimum trust score threshold

---

### 9. DexVM (D-Chain) - Decentralized Exchange

**Location:** `/vms/dexvm/`

**Purpose:** High-performance DEX with CLOB, AMM, and perpetuals.

**Implementation Status:**
- [x] Core VM lifecycle (functional mode)
- [x] Central Limit Order Book (CLOB)
- [x] AMM liquidity pools
- [x] Perpetual futures engine
- [x] Funding rate processing (8-hour)
- [x] Liquidation engine
- [x] MEV protection (commit-reveal)
- [x] Auto-deleveraging (ADL)
- [x] Block-driven deterministic execution
- [ ] Transaction decoding/execution
- [ ] WebSocket handler
- [ ] State root computation

**Security Findings:**

| Severity | Finding | Location |
|----------|---------|----------|
| MEDIUM | **processTx not implemented** - All tx types are TODO | vm.go:332-345 |
| MEDIUM | **State root always empty** - computeStateRoot returns Empty | vm.go:424-431 |
| LOW | **WebSocket not implemented** - Returns 501 | vm.go:487-493 |
| LOW | **Config parsing TODO** - parseConfig empty | vm.go:231-235 |

**Design Strengths:**
- Pure functional architecture (no background goroutines)
- Deterministic block processing
- All state changes within ProcessBlock
- Replay-safe for auditing

**Components:**
- Orderbook with advanced order types
- Stop engine for conditional orders
- Referral system for perpetuals
- Tiered fee structure

**Recommendations:**
1. Complete transaction type implementations
2. Implement proper Merkle state root
3. Add WebSocket for real-time orderbook updates
4. Complete genesis/config parsing

---

## Cross-Cutting Concerns

### 1. Duplicate Code (KeyVM)
`kchainvm` and `kmsvm` are identical implementations. Consolidate to single package.

### 2. Warp Integration
Several VMs define warp.Error handling but don't validate messages. Need consistent cross-chain verification.

### 3. Database Persistence
Multiple VMs have TODO markers for database persistence (KeyVM, QuantumVM, AIVM). Critical for production.

### 4. Test Coverage
| VM | Test Files | Coverage |
|----|------------|----------|
| BridgeVM | 2 (signer, teleport) | Partial |
| GraphVM | 1 (graphql) | Partial |
| KeyVM | 1 (vm) | Minimal |
| QuantumVM | 1 (vm) | Minimal |
| ExchangeVM | 10+ | Comprehensive |
| ThresholdVM | 4 (fhe, lifecycle, protocols) | Good |
| ZKVM | 1 (vm) | Minimal |
| AIVM | 0 | None |
| DexVM | 8+ | Good |

---

## 2025 Implementation Roadmap

### Q1 2025 - Critical Path

1. **BridgeVM MPC Integration**
   - Complete threshold CMP keygen
   - Implement signing protocol
   - Warp message verification
   - Bond verification via P-Chain

2. **ZKVM Circuit Implementation**
   - Integrate gnark or similar
   - Trusted setup tooling
   - Basic transfer circuit

3. **KeyVM Secret Sharing**
   - Implement Shamir SSS
   - Proper AES-GCM encryption
   - Database persistence

### Q2 2025 - Feature Completion

4. **ThresholdVM Production Readiness**
   - Session cleanup automation
   - Key rotation scheduler
   - Comprehensive audit logging

5. **GraphVM Authentication**
   - API key system
   - Rate limiting
   - Proper GraphQL parser

6. **AIVM Block Consensus**
   - Block building implementation
   - Task verification
   - Result consensus

### Q3 2025 - Hardening

7. **QuantumVM Hybrid Finality**
   - Complete P-Chain integration
   - Replay protection
   - State persistence

8. **DexVM Transaction Processing**
   - All transaction types
   - State root computation
   - WebSocket support

### Q4 2025 - Integration Testing

9. **Cross-Chain Integration**
   - Full 11-chain deployment
   - E2E testing suite
   - Security audit (external)

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total VMs Audited | 9 |
| Production Ready | 1 (ExchangeVM) |
| Beta Stage | 3 (QuantumVM, ThresholdVM, DexVM) |
| Alpha Stage | 5 (BridgeVM, GraphVM, KeyVM, ZKVM, AIVM) |
| Critical Findings | 6 |
| High Findings | 10 |
| Medium Findings | 14 |
| Low Findings | 12 |

---

## Appendix: Key File Locations

| VM | Primary Files |
|----|---------------|
| BridgeVM | `vms/bridgevm/vm.go`, `block.go`, `codec.go`, `rpc.go` |
| GraphVM | `vms/graphvm/vm.go`, `graphql.go`, `dex_resolvers.go` |
| KeyVM | `vms/kchainvm/vm.go`, `vms/kmsvm/vm.go` |
| QuantumVM | `vms/quantumvm/vm.go`, `quantum/signer.go` |
| ExchangeVM | `vms/exchangevm/vm.go`, `block/`, `txs/`, `state/` |
| ThresholdVM | `vms/thresholdvm/vm.go`, `protocols.go`, `fhe/` |
| ZKVM | `vms/zkvm/vm.go`, `proof_verifier.go`, `fhe/` |
| AIVM | `vms/aivm/vm.go`, `service.go` |
| DexVM | `vms/dexvm/vm.go`, `orderbook/`, `perpetuals/`, `liquidity/` |

---

*End of Audit Report*
