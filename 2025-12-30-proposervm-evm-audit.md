# ProposerVM and EVM Integration Audit

**Date**: 2025-12-30  
**Auditor**: CTO Agent  
**Scope**: `~/work/lux/node/vms/proposervm/`, `~/work/lux/evm/`

---

## Executive Summary

This audit examines the ProposerVM wrapper and EVM integration for the Lux blockchain. The implementation follows sound architectural principles with proper separation of concerns. Several security considerations and potential improvements are identified.

**Risk Assessment**: LOW-MEDIUM

| Category | Risk Level | Notes |
|----------|------------|-------|
| ProposerVM Block Timing | LOW | Well-designed windowing system |
| Proposer Selection | LOW | Cryptographically sound sampling |
| State Sync | MEDIUM | Complex multi-party protocol |
| Precompiles | LOW | Standard patterns with proper gas accounting |
| LP181 Epoching | LOW | Clean epoch transition logic |

---

## 1. ProposerVM Analysis

### 1.1 Block Timing and Windowing

**Files**: `proposer/windower.go`, `vm.go`

**Design**:
- Window duration: 5 seconds per slot
- Max verify windows: 6 (30 seconds)
- Max build windows: 60 (5 minutes)
- Max look-ahead slots: 720 (1 hour)

**Security Observations**:

1. **Time Skew Protection** (GOOD)
   ```go
   const maxSkew = 10 * time.Second
   ```
   - Blocks more than 10 seconds in the future are rejected
   - Prevents time manipulation attacks

2. **Minimum Block Delay** (GOOD)
   ```go
   DefaultMinBlockDelay = time.Second
   ```
   - Prevents rapid block spam
   - Configurable per network

3. **Monotonic Timestamp Enforcement** (GOOD)
   ```go
   if childTimestamp.Before(parentTimestamp) {
       return errTimeNotMonotonic
   }
   ```

**Potential Issues**:

1. **P-Chain Height Dependency** (LOW RISK)
   - Block validation depends on P-Chain height being available
   - During bootstrapping, P-Chain may lag behind
   - Mitigated: Returns `(time.Time{}, false, nil)` allowing graceful degradation

### 1.2 Proposer Selection

**Files**: `proposer/windower.go`, `proposer/validators.go`

**Algorithm**:
1. Fetch validator set from P-Chain at specified height
2. Sort validators by NodeID (canonical ordering)
3. Use MT19937_64 PRNG seeded with `chainSource ^ blockHeight ^ reversedSlot`
4. Sample weighted validators without replacement

**Security Observations**:

1. **Deterministic Sampling** (GOOD)
   - Uses Mersenne Twister with deterministic seed
   - All validators agree on proposer for any slot
   - Slot reversal prevents seed collision between height/slot combinations

2. **Weight-Based Selection** (GOOD)
   - Validators selected proportional to stake weight
   - Uses `sampler.NewDeterministicWeightedWithoutReplacement`

3. **Empty Validator Set Handling** (GOOD)
   ```go
   if len(validators) == 0 {
       return ids.EmptyNodeID, ErrAnyoneCanPropose
   }
   ```
   - When no validators, anyone can propose unsigned blocks
   - Prevents chain halt during validator set transitions

**Potential Issue**:

1. **Validator Grinding** (LOW RISK)
   - Seed includes only `chainSource ^ blockHeight ^ slot`
   - An attacker controlling timing could potentially wait for favorable slots
   - Mitigated: Weight-based selection means most slots go to high-stake validators

### 1.3 Quantum Finality Integration

**Files**: `config.go`, `block.go`

**Implementation**:
```go
type QuantumFinalityVerifier interface {
    RequireQuantumParent(parentID ids.ID, parentHeight uint64) error
    IsQuantumSafeOnly() bool
}
```

**Security Observations** (GOOD):
- Optional verifier for P/Q (post-quantum) finality
- When enabled, blocks MUST build on quantum-finalized ancestors
- Enforced at both verification and build time
- Uses BLS + Ringtail dual finality proofs

---

## 2. EVM Integration

### 2.1 State Sync

**Files**: `sync/statesync/state_syncer.go`

**Design**:
- Parallel trie syncing with segment splitting
- Code syncer runs asynchronously
- Maximum 8 concurrent workers
- Segment threshold: 500,000 leaves

**Security Observations**:

1. **State Verification** (GOOD)
   - Syncs against root hash commitment
   - Validates each trie segment against Merkle proofs

2. **Progress Tracking** (GOOD)
   - Persistent queue survives restarts
   - `clearIfRootDoesNotMatch` prevents stale state corruption

**Potential Issues**:

1. **State Sync Poisoning** (MEDIUM RISK)
   - Malicious peers could serve incorrect state
   - Mitigated: Hash verification against committed root
   - Consider: Peer reputation scoring for repeated failures

2. **Memory Pressure** (LOW RISK)
   - Large state tries could exhaust memory
   - Mitigated: Segmentation and worker limits

### 2.2 Block Building

**Files**: `plugin/evm/vm.go`

**Security Observations**:

1. **Block Timestamp Validation** (GOOD)
   ```go
   maxFutureBlockTime = 10 * time.Second
   ```
   - Consistent with ProposerVM skew limit

2. **Transaction Pool Security** (GOOD)
   - Configurable price limits and bump percentages
   - Local transactions can be prioritized
   - Account slots prevent single-account DoS

### 2.3 Precompiles

**Files**: `precompile/contracts/`

**Available Precompiles**:
- DeployerAllowList
- FeeManager
- NativeMinter
- RewardManager
- TxAllowList
- Warp

#### Warp Precompile Analysis

**File**: `precompile/contracts/warp/contract.go`

**Gas Costs**:
```go
GetVerifiedWarpMessageBaseCost = 2
GetBlockchainIDGasCost         = 2
AddWarpMessageGasCost          = 20_000
SendWarpMessageGasCost         = LogGas + 3*LogTopicGas + AddWarpMessageGasCost + WriteGasCostPerSlot
GasCostPerWarpSigner           = 500
GasCostPerSignatureVerification = 200_000
```

**Security Observations**:

1. **Gas Accounting** (GOOD)
   - Base cost + per-byte cost for payload
   - Overflow protection:
     ```go
     payloadGas, overflow := math.SafeMul(SendWarpMessageGasCostPerByte, uint64(len(input)))
     if overflow {
         return nil, 0, vm.ErrOutOfGas
     }
     ```

2. **Read-Only Protection** (GOOD)
   ```go
   if readOnly {
       return nil, remainingGas, vm.ErrWriteProtection
   }
   ```

3. **Message Verification** (GOOD)
   - Uses predicate storage slots for pre-verified messages
   - Signature verification cost: 200,000 gas

**Potential Issues**:

1. **Gas Price Oracle** (LOW RISK)
   - Conservative overestimate for message storage
   - May need tuning based on actual usage patterns

---

## 3. LP181 Epoching

**Files**: `lp181/epoch.go`

**Implementation**:
```go
func NewEpoch(
    upgrades upgrade.Config,
    parentPChainHeight uint64,
    parentEpoch block.Epoch,
    parentTimestamp time.Time,
    childTimestamp time.Time,
) block.Epoch
```

**Epoch Transition Logic**:
1. Not activated before Granite: returns empty epoch
2. First epoch: uses parent P-Chain height as reference
3. Epoch sealed when parent issued after epoch end time
4. New epoch starts with incremented number

**Security Observations**:

1. **Clean Transition** (GOOD)
   - Epoch changes are deterministic
   - Based on timestamp comparison against epoch end time

2. **P-Chain Height Locking** (GOOD)
   - Each epoch locks to a specific P-Chain height
   - Prevents validator set manipulation during epoch

---

## 4. Security Recommendations

### HIGH Priority

None identified.

### MEDIUM Priority

1. **State Sync Peer Reputation**
   - Implement peer scoring for state sync reliability
   - Ban peers that consistently provide incorrect proofs
   - Location: `sync/statesync/`

2. **Proposer Slot Analysis**
   - Add monitoring for proposer slot utilization
   - Detect potential grinding attempts
   - Location: `proposervm/proposer/`

### LOW Priority

1. **Timestamp Drift Monitoring**
   - Add metrics for block timestamp vs local time drift
   - Alert on persistent drift patterns
   - Location: `proposervm/vm.go`

2. **Epoch Transition Events**
   - Emit events on epoch transitions for monitoring
   - Location: `proposervm/lp181/`

3. **Gas Cost Calibration**
   - Profile warp message costs against actual execution
   - Consider dynamic adjustment based on network load
   - Location: `precompile/contracts/warp/`

---

## 5. Code Quality Observations

### Positive Patterns

1. **Interface Segregation**: Clean separation between ProposerVM wrapper and inner VM
2. **Error Handling**: Explicit error types with wrapped context
3. **Logging**: Comprehensive debug logging with structured fields
4. **Testing**: Extensive test coverage including byzantine scenarios

### Areas for Improvement

1. **Documentation**: Some complex algorithms lack inline comments
2. **Backup Files**: Multiple `.bak` files should be cleaned up:
   - `vm_test.go.bak` through `vm_test.go.bak7`
   - `blockchain_snapshot_test.go.bak`

3. **Debug Logging**: Production debug log file creation:
   ```go
   f, err := os.OpenFile("/tmp/evm-debug.log", ...)
   ```
   Should be gated by debug flag or removed.

---

## 6. Architecture Summary

```
                    ┌─────────────────────────────────┐
                    │         Consensus Engine         │
                    │    (Quasar / Snow Protocol)      │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │          ProposerVM              │
                    │  ┌────────────────────────────┐ │
                    │  │  Block Timing & Windowing  │ │
                    │  │  Proposer Selection (PRNG) │ │
                    │  │  LP181 Epoching            │ │
                    │  │  P/Q Finality Verification │ │
                    │  └────────────────────────────┘ │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │            EVM Plugin            │
                    │  ┌────────────────────────────┐ │
                    │  │  Block Building/Validation │ │
                    │  │  State Management          │ │
                    │  │  Transaction Pool          │ │
                    │  │  Precompiles (Warp, etc)   │ │
                    │  │  State Sync Client/Server  │ │
                    │  └────────────────────────────┘ │
                    └─────────────────────────────────┘
```

---

## 7. Conclusion

The ProposerVM and EVM integration demonstrates solid engineering practices with appropriate security measures. The windowing and proposer selection mechanisms are cryptographically sound. State sync follows established patterns with proper verification.

Key strengths:
- Deterministic proposer selection prevents coordination attacks
- Quantum finality integration provides forward security path
- LP181 epoching enables clean validator set transitions
- Gas accounting prevents DoS on precompiles

Areas requiring attention:
- State sync peer reputation for improved resilience
- Debug logging cleanup for production readiness
- Monitoring infrastructure for operational security

**Overall Assessment**: The codebase is production-ready with the noted recommendations for improved operational security.

---

*Audit completed: 2025-12-30*
