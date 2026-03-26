# Oracle and Attestation Protocol Security Audit

**Date**: 2025-12-30
**Scope**: Oracle and price feed infrastructure
**Auditor**: CTO Agent
**Severity Scale**: Critical > High > Medium > Low > Informational

---

## Executive Summary

The Lux oracle and attestation protocol provides a multi-source price aggregation system with comprehensive defensive measures. The architecture is well-designed with multiple redundant price sources (Pyth, Chainlink, native chains), robust aggregation via weighted median, circuit breakers, and quantum finality verification through Q-Chain.

**Overall Assessment**: **Good** with specific areas requiring hardening.

| Category | Finding Count | Status |
|----------|---------------|--------|
| Critical | 0 | - |
| High | 2 | Needs attention |
| Medium | 5 | Should fix |
| Low | 4 | Best practice |
| Informational | 3 | Notes |

---

## Architecture Overview

### Price Sources Reviewed

| Source | Location | Weight | Staleness |
|--------|----------|--------|-----------|
| Pyth Network | `price/pyth.go`, `lx/pyth_source.go` | 1.2-1.5 | 30s |
| Chainlink | `price/chainlink.go`, `lx/chainlink_source.go` | 1.0-2.0 | 60s |
| X-Chain (native) | `price/xchain.go` | 2.0 | 2s |
| C-Chain AMM | `price/cchain.go` | 1.8 | 5s |
| A-Chain Attestation | `price/achain.go` | 1.5 | 5s |
| Q-Chain Finality | `price/qchain.go` | N/A (verifier) | 5s |
| Orderbook | `price/source.go` | 1.0 | 1s |

### Aggregation Strategy

```
[Sources] -> [WeightedMedian] -> [OutlierRejection] -> [CircuitBreaker] -> [Final Price]
              MaxDeviation: 10%   MinSources: 1-2     MaxChange: 20%
```

---

## Findings

### HIGH-001: Default MinSources Too Low

**File**: `price/aggregator.go:40-41`
```go
strategy: &WeightedMedian{
    MinSources:   1,  // ISSUE: Single source acceptable
    MaxDeviation: 0.10,
},
```

**Risk**: Oracle manipulation via single compromised/malicious source.

**Attack Scenario**:
1. Attacker compromises one price source
2. Other sources go offline (network partition, DDoS)
3. Manipulated price accepted with MinSources=1
4. Flash loan exploit using stale/manipulated price

**Recommendation**: 
```go
MinSources: 2,  // Require at least 2 independent sources
```

For high-value operations (liquidations, large swaps), require MinSources >= 3.

---

### HIGH-002: TWAP/VWAP Not Used for Critical Operations

**File**: `price/aggregator.go:477-510`, `lx/oracle.go:759-805`

TWAP and VWAP are calculated but not enforced for price-sensitive operations.

**Current State**:
- TWAP/VWAP calculated every second over 5-minute window
- Values stored but not used in aggregation
- Spot price returned for all queries

**Risk**: Flash loan price manipulation within single block.

**Attack Scenario**:
1. Attacker takes flash loan
2. Manipulates spot price via large trade
3. Uses manipulated price for oracle-dependent operation
4. Reverses trade, repays loan

**Recommendation**:
```go
// For liquidations and large margin operations:
func (o *Oracle) SafePrice(symbol string) float64 {
    spot := o.Price(symbol)
    twap := o.TWAP(symbol)
    
    // Reject if spot deviates >5% from TWAP
    if math.Abs(spot-twap)/twap > 0.05 {
        return 0 // Require human intervention
    }
    
    // Use TWAP for critical operations
    return twap
}
```

---

### MEDIUM-001: Circuit Breaker Reset Window

**File**: `price/aggregator.go:454-457`
```go
if cb.Tripped && time.Since(cb.TripTime) > cb.Reset {
    cb.Tripped = false
}
```

**Issue**: Circuit breaker auto-resets without validating price stability.

**Risk**: Attacker waits for reset, immediately triggers manipulation.

**Recommendation**: Require stable prices for N consecutive readings before reset:
```go
type CircuitBreaker struct {
    // ... existing fields
    StableCount    int  // Consecutive stable readings
    StableRequired int  // Required for reset (e.g., 10)
}
```

---

### MEDIUM-002: Confidence Score Calculation

**File**: `price/aggregator.go:409-433`
```go
func (w *WeightedMedian) confidence(prices []*Data) float64 {
    sourceScore := float64(len(prices)) / float64(w.MinSources*2)
    // ...
    return sourceScore*0.6 + devScore*0.4
}
```

**Issue**: Confidence calculation doesn't account for:
- Source diversity (all sources from same provider)
- Source reputation/historical accuracy
- Time since last update per source

**Recommendation**: Implement diversity-aware confidence:
```go
func (w *WeightedMedian) confidence(prices []*Data) float64 {
    // Track unique source types
    sourceTypes := make(map[string]bool)
    for _, p := range prices {
        sourceTypes[classifySource(p.Source)] = true
    }
    diversityScore := float64(len(sourceTypes)) / 4.0 // 4 source categories
    
    // Weight: 40% count, 30% agreement, 30% diversity
    return sourceScore*0.4 + devScore*0.3 + diversityScore*0.3
}
```

---

### MEDIUM-003: Chainlink Simulation in Production Code

**File**: `price/chainlink.go:96-133`, `lx/chainlink_source.go:133-174`
```go
func (s *ChainlinkSource) simulate(symbol string) float64 {
    base := map[string]float64{
        "BTC-USD":  50000.0,
        // ...
    }
    v := (math.Sin(float64(time.Now().UnixNano())/1e9) * 0.001) + 1.0
    return b * v
}
```

**Issue**: Production code contains simulated prices instead of real oracle calls.

**Risk**: If deployed as-is, prices would be static/predictable.

**Recommendation**: Complete actual Chainlink integration:
```go
func (s *ChainlinkSource) fetch(ctx context.Context, symbol, addr string) {
    aggregator, _ := NewAggregatorV3Interface(common.HexToAddress(addr), client)
    roundData, _ := aggregator.LatestRoundData(nil)
    
    price := new(big.Float).SetInt(roundData.Answer)
    decimals, _ := aggregator.Decimals(nil)
    divisor := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
    price.Quo(price, divisor)
    // ...
}
```

---

### MEDIUM-004: A-Chain Attestation Quorum Too Low

**File**: `price/achain.go:69`
```go
quorum: 3, // 3 of N validators for consensus
```

**Issue**: With 4 validators configured, 3-of-4 quorum is 75%. A single validator going offline reduces to 3-of-3 (100% required).

**Validator Set**:
- validator-1: 1M stake
- validator-2: 500k stake  
- validator-3: 750k stake
- validator-4: 250k stake

**Risk**: 
- Validator collusion (3 validators = 90% stake)
- Single validator failure = system halt

**Recommendation**:
- Increase validator set size to 7+
- Use stake-weighted quorum: 66.7% of total stake
- Implement view-change for offline validators

---

### MEDIUM-005: Q-Chain Signature Verification Not Implemented

**File**: `price/qchain.go:200-234`
```go
func (v *QChainVerifier) simulateFinality(chain string) *QuantumFinality {
    // ...
    sigs = append(sigs, QuantumSignature{
        Validator: name,
        Algorithm: val.Algorithm,
        Signature: hash[:],        // Simulated, not actual signature
        PublicKey: pubKey[:64],
    })
}
```

**Issue**: Quantum signatures are simulated, not verified.

**Risk**: Finality proofs can be forged.

**Recommendation**: Implement actual PQ signature verification:
```go
import "github.com/luxfi/crypto/dilithium"

func (v *QChainVerifier) verifySignature(sig QuantumSignature, data []byte) bool {
    switch sig.Algorithm {
    case "dilithium3":
        return dilithium.Verify(sig.PublicKey, data, sig.Signature)
    case "sphincs-sha2-256f":
        return sphincs.Verify(sig.PublicKey, data, sig.Signature)
    }
    return false
}
```

---

### LOW-001: Pyth Confidence Calculation

**File**: `price/pyth.go:152-156`
```go
Confidence: 1.0 - (conf / price),
```

**Issue**: Pyth confidence interval is absolute, not percentage. Division by price is incorrect for USD-denominated assets.

**Recommendation**:
```go
// Pyth confidence is standard deviation
// Convert to 0-1 confidence score
confRatio := conf / price
if confRatio > 0.1 {
    Confidence = 0 // Too wide
} else {
    Confidence = 1.0 - (confRatio * 10) // Scale 0-10% to 0-1
}
```

---

### LOW-002: Symbol Normalization Edge Cases

**File**: `price/normalize.go:24-35`
```go
func detectPair(s string) string {
    quotes := []string{"USDC", "USDT", "USD", "BTC", "ETH", "LUX"}
    // ...
}
```

**Issue**: Order matters - "BTCUSD" would incorrectly split to "BTC-USD" but "USDBTC" would fail.

**Recommendation**: Add reverse lookup and explicit pair registry.

---

### LOW-003: History Buffer Overflow

**File**: `price/aggregator.go:162-164`
```go
if len(o.history[symbol]) > 10000 {
    o.history[symbol] = o.history[symbol][1:]
}
```

**Issue**: Slice reslicing creates memory pressure; old backing array not garbage collected.

**Recommendation**:
```go
const maxHistory = 10000
if len(o.history[symbol]) >= maxHistory {
    // Copy to new slice to allow GC
    newHist := make([]*Data, maxHistory-1)
    copy(newHist, o.history[symbol][1:])
    o.history[symbol] = newHist
}
```

---

### LOW-004: Race Condition in Source Polling

**File**: `price/cchain.go:211-219`
```go
func (s *CChainSource) poll() {
    var wg sync.WaitGroup
    for symbol, pair := range s.tokens {
        wg.Add(1)
        go func(sym string, p TokenPair) {
            // ...
        }(symbol, pair)
    }
}
```

**Issue**: Iterating over map in goroutine with value capture. Closure correctly captures, but map iteration order is undefined.

**Recommendation**: No action needed - current implementation is correct. Note for reference.

---

### INFO-001: Source Weight Configuration

Current weights:
- X-Chain (native DEX): 2.0
- Chainlink: 1.0-2.0
- C-Chain AMM: 1.8
- A-Chain Attestation: 1.5
- Pyth: 1.2
- Orderbook: 1.0

These weights favor on-chain sources, which is appropriate but should be configurable per deployment.

---

### INFO-002: Missing Staleness Alert Persistence

Staleness detection triggers alerts via channel but doesn't persist state:
```go
case o.alerts <- &Alert{...}:
default:
    // Dropped if channel full
}
```

Consider adding persistent alert logging for forensics.

---

### INFO-003: Test Coverage Gaps

Observed test files:
- `price_test.go` - Basic coverage
- `coverage_test.go` - Coverage improvement
- `oracle_test.go`, `oracle_comprehensive_test.go` - Good coverage

Missing:
- Adversarial manipulation tests
- Multi-source failure scenarios
- Flash loan attack simulations
- TWAP/VWAP manipulation edge cases

---

## Security Recommendations Summary

### Immediate Actions (High Priority)

1. **Increase MinSources to 2** for all price queries
2. **Use TWAP for liquidations** and margin operations
3. **Complete Chainlink integration** - remove simulation code
4. **Implement Q-Chain signature verification**

### Short-Term (Medium Priority)

5. Enhance circuit breaker with stability check before reset
6. Implement diversity-aware confidence scoring
7. Increase A-Chain validator set and use stake-weighted quorum
8. Add adversarial test suite

### Long-Term (Low Priority)

9. Memory optimization for history buffers
10. Persistent alert logging
11. Configurable source weights
12. Price feed monitoring dashboard

---

## Attestation Protocol Analysis

### A-Chain Architecture

The A-Chain attestation protocol provides validator-signed price attestations:

```
[External Oracle] -> [Validator Set] -> [Quorum Signing] -> [Finalized Attestation]
```

**Strengths**:
- Multi-validator consensus (3-of-4 currently)
- Stake-weighted validator set
- Hash-based attestation integrity
- Finalization flag for confirmation

**Weaknesses**:
- Small validator set (4 validators)
- No slashing for misbehavior
- Quorum calculation ignores stake weight
- No view-change protocol for offline validators

### Q-Chain Quantum Finality

Provides post-quantum finality verification:

**Supported Algorithms**:
- Dilithium3 (NIST Level 3)
- Dilithium5 (NIST Level 5)
- SPHINCS+-SHA2-256f

**Architecture**:
```
[Chain Finality] -> [Q-Chain Validators] -> [PQ Signature] -> [QuantumFinality Proof]
```

**Gap**: Signature verification not implemented - currently simulated.

---

## Oracle Manipulation Protection

### Flash Loan Attack Mitigation

| Protection | Status | Effectiveness |
|------------|--------|---------------|
| TWAP | Calculated, not enforced | Low |
| VWAP | Calculated, not enforced | Low |
| Circuit Breaker | Active, 20% threshold | Medium |
| Multi-Source | MinSources=1 default | Low |
| Staleness Check | 5s limit | Medium |

**Recommendation**: Enforce TWAP for all price-sensitive operations.

### Stale Price Protection

| Source | Staleness Limit | Action |
|--------|-----------------|--------|
| Pyth | 30s | HTTP fallback |
| Chainlink | 60s | Mark stale |
| X-Chain | 2s | Mark stale |
| C-Chain | 5s | Mark stale |
| A-Chain | 5s | Mark stale, require finalization |

**Recommendation**: Add emergency price feed for critical staleness scenarios.

---

## Conclusion

The Lux oracle protocol demonstrates a well-architected multi-source price aggregation system with quantum finality integration. The primary concerns are:

1. **Low MinSources default** - Single source attacks possible
2. **TWAP not enforced** - Flash loan manipulation risk
3. **Simulation code in production** - Chainlink/Q-Chain not fully integrated
4. **Small validator set** - Collusion and availability risks

Addressing the High-priority findings before mainnet deployment is recommended.

---

**Audit Completed**: 2025-12-30
**Next Review**: Before mainnet launch or after significant changes
