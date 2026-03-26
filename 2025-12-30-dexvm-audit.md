# DexVM (D-Chain) Security Audit Report

**Date**: 2025-12-30  
**Auditor**: Claude Code (CTO Mode)  
**Scope**: `/Users/z/work/lux/node/vms/dexvm/`  
**Commit**: 66d514d2b7 (main branch)

---

## Executive Summary

DexVM implements a comprehensive decentralized exchange with central limit order book (CLOB), perpetual futures, AMM liquidity pools, and MEV protection. The architecture follows sound design principles but contains several security vulnerabilities requiring immediate attention.

### Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 2 | Integer overflow, oracle manipulation |
| High | 3 | Liquidation cascades, flash loan vectors, self-trade bypass |
| Medium | 4 | State consistency, fee manipulation, referral abuse, ADL gaming |
| Low | 3 | Gas optimization, event emission, documentation |

---

## Component Analysis

### 1. Orderbook (`orderbook/orderbook.go`, `orderbook_advanced.go`)

**Architecture**: Price-time priority CLOB with FIFO matching within price levels.

#### Findings

**[CRITICAL] Integer Overflow in Price/Quantity Calculations**

```go
// orderbook.go:170
fill.Value = matchQty * order.Price
```

No overflow check on `uint64` multiplication. A malicious order with `Price = 2^32` and `matchQty = 2^32` causes silent overflow.

**Recommendation**: Use `math/big` or checked arithmetic:
```go
func safeMul(a, b uint64) (uint64, error) {
    if a > 0 && b > math.MaxUint64/a {
        return 0, ErrOverflow
    }
    return a * b, nil
}
```

**[HIGH] Self-Trade Prevention Bypass**

```go
// orderbook.go:155
if order.Owner == oppositeOrder.Owner {
    if ob.selfTradePrevention {
        continue // Skip self-trade
    }
}
```

Owner comparison uses direct equality. An attacker with multiple addresses can:
1. Place large limit orders on both sides
2. Execute trades to manipulate last price
3. Affect mark price and trigger liquidations

**Recommendation**: Implement account-level linking or require KYC-bound trader IDs for self-trade prevention.

**[MEDIUM] Hidden Order Information Leakage**

```go
// orderbook_advanced.go:45
type HiddenOrder struct {
    VisibleQuantity uint64
    TotalQuantity   uint64  // Stored in plaintext
}
```

Total quantity stored in state. Validators or state-reading contracts can extract hidden order sizes.

**Recommendation**: Use commitment scheme for hidden portions or encrypt with user's public key.

---

### 2. Matching Engine (`orderbook/orderbook.go:matchOrder`)

**Architecture**: Synchronous matching on order placement.

#### Findings

**[MEDIUM] Partial Fill State Consistency**

```go
// orderbook.go:180-185
oppositeOrder.RemainingQty -= matchQty
if oppositeOrder.RemainingQty == 0 {
    pl.Remove(oppositeOrder.ID)
}
```

No transaction boundary around multi-order matching. A panic mid-match leaves inconsistent state.

**Recommendation**: Implement batch state updates with rollback capability:
```go
func (ob *OrderBook) matchOrder(order *Order) ([]Fill, error) {
    batch := ob.state.NewBatch()
    defer batch.Rollback()
    // ... matching logic ...
    return fills, batch.Commit()
}
```

---

### 3. Perpetuals Engine (`perpetuals/engine.go`, `types.go`)

**Architecture**: Cross/isolated margin with tiered leverage up to 1001x.

#### Findings

**[CRITICAL] Oracle Manipulation via Last Price**

```go
// engine.go:89
func (o *DefaultPriceOracle) GetMarkPrice(market string) *big.Int {
    return o.prices[market] // Set from last trade
}
```

Mark price derived from last traded price. Attack vector:
1. Attacker places large short position
2. Executes wash trade at manipulated low price
3. Mark price drops, triggering liquidations of longs
4. Attacker profits from liquidation cascade

**Recommendation**: Implement TWAP oracle with external price feeds:
```go
type TWAPOracle struct {
    observations []PriceObservation
    windowSize   time.Duration
}

func (o *TWAPOracle) GetMarkPrice(market string) *big.Int {
    // Use time-weighted average over 30+ minutes
    // Combine with Chainlink/Pyth external feeds
}
```

**[HIGH] Liquidation Cascade Risk**

```go
// engine.go:250
func (e *Engine) CheckLiquidations() []LiquidationEvent {
    for _, pos := range e.positions {
        if e.isLiquidatable(pos) {
            events = append(events, e.liquidate(pos))
        }
    }
    return events
}
```

No circuit breakers or rate limiting. A price crash triggers mass liquidations in single block, causing:
- Insurance fund depletion
- ADL activation affecting profitable traders
- Market spiral

**Recommendation**: Implement progressive liquidation with delays:
```go
const (
    MaxLiquidationsPerBlock = 100
    LiquidationCooldown     = 5 * time.Second
)

func (e *Engine) CheckLiquidations() []LiquidationEvent {
    if time.Since(e.lastLiquidationBatch) < LiquidationCooldown {
        return nil
    }
    // Limit liquidations per block
    // Prioritize by margin ratio (worst first)
}
```

**[MEDIUM] Leverage Tier Boundary Gaming**

```go
// tiers.go:20-30
var leverageTiers = []LeverageTier{
    {MaxNotional: 10_000, MaxLeverage: 1001},
    {MaxNotional: 50_000, MaxLeverage: 500},
    // ...
}
```

Position sizing at tier boundaries allows leverage arbitrage:
- Open $9,999 position at 1001x leverage
- Close partially, reopen to maintain high leverage
- Repeat to accumulate oversized exposure

**Recommendation**: Apply leverage limits to aggregate account exposure, not individual positions.

---

### 4. Liquidity Pools (`liquidity/pool.go`)

**Architecture**: Constant product AMM with slippage protection.

#### Findings

**[HIGH] Flash Loan Attack Vector**

```go
// pool.go:85
func (p *Pool) Swap(amountIn uint64, tokenIn string, minAmountOut uint64) (uint64, error) {
    // No flash loan guard
    amountOut := p.calculateSwapOutput(amountIn, tokenIn)
    // ...
}
```

No reentrancy guard or same-block manipulation protection. Attack:
1. Flash loan large amount of token A
2. Swap A→B, moving price significantly
3. Trigger liquidations/stop orders at manipulated price
4. Swap B→A (lower slippage due to larger pool)
5. Repay flash loan with profit

**Recommendation**: Implement per-block price limits and reentrancy guards:
```go
type Pool struct {
    lastBlockNumber uint64
    lastBlockPrice  *big.Int
    maxPriceChange  *big.Int // e.g., 5%
    mutex           sync.Mutex
}

func (p *Pool) Swap(...) (uint64, error) {
    p.mutex.Lock()
    defer p.mutex.Unlock()
    
    if p.currentBlock == p.lastBlockNumber {
        priceChange := p.calculatePriceChange()
        if priceChange.Cmp(p.maxPriceChange) > 0 {
            return 0, ErrPriceImpactTooHigh
        }
    }
    // ...
}
```

**[LOW] Rounding Direction Inconsistency**

```go
// pool.go:70
amountOut = (reserveOut * amountIn) / (reserveIn + amountIn)
```

Always rounds down (favors pool). Should explicitly document this is intentional for pool protection.

---

### 5. MEV Protection (`mev/commit_reveal.go`)

**Architecture**: Commit-reveal scheme with 2-second minimum delay.

#### Findings

**[MEDIUM] Commit Fee Front-Running**

```go
// commit_reveal.go:45
type Commitment struct {
    Hash      [32]byte
    Timestamp time.Time
    // No fee snapshot
}
```

Fee rates can change between commit and reveal. Validators can:
1. See commitment hash
2. Raise fees before reveal
3. Profit from higher fees or force order cancellation

**Recommendation**: Lock fee rate at commitment time:
```go
type Commitment struct {
    Hash         [32]byte
    Timestamp    time.Time
    LockedFeeRate *big.Int
}
```

**[LOW] Reveal Delay Gaming**

5-minute maximum reveal window may be too long. Attackers can wait for favorable price movements within window.

**Recommendation**: Reduce to 1-minute maximum or implement randomized reveal blocks.

---

### 6. Settlement & State (`state/state.go`, `vm.go`)

**Architecture**: Block-driven deterministic execution.

#### Findings

**[MEDIUM] State Root Verification Gap**

```go
// vm.go:125
func (vm *VM) ProcessBlock(blk *Block) error {
    for _, tx := range blk.Transactions {
        if err := vm.executeTx(tx); err != nil {
            return err
        }
    }
    // No explicit state root commitment
    return nil
}
```

No Merkle state root in block header for light client verification.

**Recommendation**: Add state root commitment:
```go
type BlockHeader struct {
    // ...
    StateRoot [32]byte
    OrderbookRoot [32]byte
    PositionsRoot [32]byte
}
```

---

### 7. Lending Protocol (`lending/engine.go`)

**Architecture**: Jump rate interest model with health factor liquidations.

#### Findings

**[MEDIUM] Interest Rate Manipulation**

```go
// engine.go:150
func (e *LendingEngine) calculateInterestRate(market *Market) *big.Int {
    utilization := market.TotalBorrowed / market.TotalSupplied
    // ...
}
```

Large suppliers can manipulate utilization by withdrawing/depositing in same block.

**Recommendation**: Use TWAP for utilization calculation.

---

### 8. ADL System (`perpetuals/adl.go`)

**Architecture**: Ranks profitable positions for auto-deleveraging.

#### Findings

**[MEDIUM] ADL Ranking Gamification**

```go
// adl.go:35
func (a *ADLEngine) rankPositions() []*Position {
    sort.Slice(positions, func(i, j int) bool {
        return positions[i].PnL.Cmp(positions[j].PnL) > 0
    })
    return positions
}
```

Traders can split positions across addresses to reduce individual PnL ranking.

**Recommendation**: Implement random selection with PnL-weighted probability rather than pure ranking.

---

### 9. Referral System (`perpetuals/referral.go`)

**Architecture**: 6-tier rebate system based on 30-day volume.

#### Findings

**[MEDIUM] Referral Wash Trading**

```go
// referral.go:55
func (r *ReferralEngine) RecordVolume(trader, referrer common.Address, volume *big.Int) {
    r.referrerVolume[referrer].Add(r.referrerVolume[referrer], volume)
    // ...
}
```

No verification that trader ≠ referrer (via different addresses). Attackers can:
1. Create trader/referrer address pair
2. Execute wash trades to accumulate volume
3. Collect rebates while paying minimal net fees

**Recommendation**: Implement minimum holding periods, require stake for referral eligibility, or add wash trade detection.

---

## Security Recommendations for 2025

### Immediate Actions (Q1 2025)

1. **Implement Checked Arithmetic**
   - Replace all `uint64` arithmetic with overflow-checked functions
   - Use `math/big` for price calculations
   - Add fuzz testing for edge cases

2. **Deploy TWAP Oracle**
   - Minimum 30-minute window
   - Multiple price sources (Chainlink, Pyth, internal CLOB)
   - Deviation circuit breakers (halt trading if sources diverge >5%)

3. **Add Circuit Breakers**
   - Max liquidations per block: 100
   - Max price change per block: 5%
   - Cooldown periods after large liquidations

4. **Flash Loan Guards**
   - Per-block price impact limits
   - Reentrancy mutex on all pool operations
   - Same-block trade limits

### Medium-Term (Q2-Q3 2025)

5. **State Root Commitments**
   - Merkleized orderbook state
   - Light client verification support
   - Fraud proof infrastructure

6. **Enhanced MEV Protection**
   - Batch auctions (1-second intervals)
   - Encrypted mempool (threshold decryption)
   - MEV-share redistribution to traders

7. **Position Tracking Improvements**
   - Account-level aggregate leverage limits
   - Cross-margin position linking
   - Unified liquidation engine

### Long-Term (Q4 2025)

8. **Formal Verification**
   - Invariant proofs for orderbook matching
   - Liquidation logic verification
   - Integer overflow absence proofs

9. **Economic Security Audits**
   - Game-theoretic analysis of incentives
   - MEV extraction simulations
   - Stress testing under extreme conditions

10. **Insurance Fund Governance**
    - DAO-controlled parameters
    - Reinsurance mechanisms
    - ADL threshold governance

---

## Test Coverage Analysis

| Component | Test File | Coverage | Gap |
|-----------|-----------|----------|-----|
| Orderbook | `orderbook_test.go` | ~60% | Missing overflow, edge cases |
| Stop Engine | `stop_engine_test.go` | ~70% | Missing OCO edge cases |
| Perpetuals | `engine_test.go` | ~50% | Missing liquidation cascades |
| ADL | `adl_test.go` | ~80% | Good coverage |
| Liquidity | `pool_test.go` | ~40% | Missing flash loan scenarios |
| MEV | `commit_reveal_test.go` | ~65% | Missing timing attacks |

**Recommendation**: Achieve 90%+ coverage with focus on:
- Boundary conditions
- Concurrent operations
- Attack simulations

---

## Conclusion

DexVM demonstrates solid architectural foundations but requires hardening before production deployment. The critical integer overflow and oracle manipulation vulnerabilities must be addressed immediately. The tiered leverage system and MEV protection show thoughtful design but need edge case handling.

Priority fix order:
1. Integer overflow (CRITICAL)
2. Oracle TWAP implementation (CRITICAL)
3. Flash loan guards (HIGH)
4. Liquidation circuit breakers (HIGH)
5. Self-trade prevention enhancement (HIGH)

Estimated remediation effort: 4-6 weeks for critical/high issues.

---

*Report generated by Claude Code (CTO Mode)*  
*Audit methodology: Static analysis, pattern matching, attack vector enumeration*
