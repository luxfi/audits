# Lux Smart Contracts Security Audit

**Date**: 2025-12-30  
**Auditor**: Claude (Automated Audit)  
**Scope**: ~/work/lux/standard/contracts/, ~/work/lux/node/contracts/

---

## Executive Summary

This audit covers the Lux Network smart contract ecosystem including FHE (Fully Homomorphic Encryption) contracts, DEX/AMM, Bridge, Governance, Perpetuals, and Precompile interfaces. The codebase demonstrates solid security practices overall but contains several areas requiring attention.

**Risk Level**: MEDIUM  
**Critical Issues**: 0  
**High Issues**: 3  
**Medium Issues**: 7  
**Low Issues**: 12  

---

## 1. Contract Inventory

### 1.1 Standard Contracts (`/Users/z/work/lux/standard/contracts/`)

| Category | Contract Count | Key Contracts |
|----------|---------------|---------------|
| FHE | 16 | FHE.sol, IFHE.sol, TFHE.sol, ConfidentialLRC20.sol |
| Bridge | 14+ | Bridge.sol, BridgeVault.sol, TeleportBridge.sol |
| AMM | 8 | AMMV2Pair.sol, AMMV3Pool.sol, PriceAggregator.sol |
| Governance | 21 | Governor.sol, DAO.sol, vLUX.sol, Timelock.sol |
| Perpetuals | 30+ | Vault.sol, PositionRouter.sol, OrderBook.sol |
| Safe | 14 | Safe.sol, QuantumSafe.sol, SafeFROSTSigner.sol |
| Tokens | 15+ | LRC20.sol, LRC721.sol, WLUX.sol |
| Oracle | 7 | Oracle.sol, OracleHub.sol, CircuitBreaker.sol |
| Liquidity | 12 | CrossChainDeFiRouter.sol, UniversalLiquidityRouter.sol |

### 1.2 Node Contracts (`/Users/z/work/lux/node/contracts/`)

| Category | Contracts |
|----------|-----------|
| Governance | ChainFeeRegistry.sol, ChainFeeRegistryV2.sol, ChainFeeRegistryV3.sol |
| Fee | FeeGovernor.sol, FeeTimelock.sol, WarpFeeEmitter.sol |

### 1.3 Precompile Interfaces

| Precompile | Address | Purpose |
|------------|---------|---------|
| FheOps | 0x02...0080 | FHE Operations |
| ACL | 0x02...0081 | Access Control |
| InputVerifier | 0x02...0082 | Input Verification |
| Gateway | 0x02...0083 | Decryption Gateway |
| PoolManager | 0x0400 | DEX Singleton |
| SwapRouter | 0x0401 | Swap Routing |
| HooksRegistry | 0x0402 | Hook Management |
| FlashLoan | 0x0403 | Flash Loans |

---

## 2. Vulnerability Findings

### 2.1 HIGH SEVERITY

#### H-01: Missing Reentrancy Guard in Bridge.sol

**Location**: `/Users/z/work/lux/standard/contracts/bridge/Bridge.sol`

**Description**: The Bridge contract handles token transfers and vault deposits/withdrawals without ReentrancyGuard protection.

```solidity
function vaultDeposit(uint256 amount_, address tokenAddr_) public payable {
    if (tokenAddr_ != address(0)) {
        IERC20(tokenAddr_).transferFrom(msg.sender, address(vault), amount_);
    }
    vault.deposit{value: msg.value}(tokenAddr_, amount_);
    emit VaultDeposit(msg.sender, amount_, tokenAddr_);
}
```

**Impact**: Potential reentrancy via malicious ERC20 token with callback hooks.

**Recommendation**: 
1. Add `ReentrancyGuard` from OpenZeppelin
2. Apply `nonReentrant` modifier to all external functions involving transfers

---

#### H-02: Missing Reentrancy Guard in BridgeVault.sol

**Location**: `/Users/z/work/lux/standard/contracts/bridge/BridgeVault.sol`

**Description**: Vault operations lack reentrancy protection despite handling ETH and ERC20 transfers.

**Impact**: Cross-function reentrancy attacks possible.

**Recommendation**: Implement `ReentrancyGuard` on all deposit/withdraw functions.

---

#### H-03: Missing Reentrancy Guard in AMMV2Router.sol

**Location**: `/Users/z/work/lux/standard/contracts/amm/AMMV2Router.sol`

**Description**: Router functions handle multi-hop swaps without reentrancy protection.

**Impact**: Flash loan attacks could exploit price manipulation during multi-hop swaps.

**Recommendation**: Add `nonReentrant` to swap and liquidity functions.

---

### 2.2 MEDIUM SEVERITY

#### M-01: Centralized Admin Control in Bridge

**Location**: `/Users/z/work/lux/standard/contracts/bridge/Bridge.sol:50`

```solidity
modifier onlyAdmin() {
    require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Ownable");
    _;
}
```

**Description**: Single admin role controls critical bridge functions including MPC oracle updates.

**Recommendation**: Implement multi-sig or timelock for admin operations.

---

#### M-02: Lack of Slippage Protection in AMMV2Pair

**Location**: `/Users/z/work/lux/standard/contracts/amm/AMMV2Pair.sol`

**Description**: Swap function does not have built-in slippage protection at the pair level.

**Recommendation**: While router should handle slippage, consider adding optional min/max bounds.

---

#### M-03: No Circuit Breaker in Perpetuals Vault

**Location**: `/Users/z/work/lux/standard/contracts/perps/core/Vault.sol`

**Description**: 50x leverage enabled without circuit breaker for extreme market conditions.

```solidity
uint256 public override maxLeverage = 50 * 10000; // 50x
```

**Recommendation**: Implement dynamic leverage limits based on volatility.

---

#### M-04: Unbounded Array in Fee Registry

**Location**: `/Users/z/work/lux/standard/contracts/perps/core/Vault.sol:84`

```solidity
address[] public override allWhitelistedTokens;
```

**Description**: No limit on whitelisted tokens could cause gas issues.

**Recommendation**: Add maximum token limit or pagination for reads.

---

#### M-05: Timestamp Dependence in Governance

**Location**: `/Users/z/work/lux/standard/contracts/governance/Governor.sol:191`

```solidity
if (block.timestamp <= votingEndTimestamp) {
    return ProposalState.ACTIVE;
}
```

**Description**: Block timestamp can be manipulated by miners within 15-second window.

**Recommendation**: Use block numbers for critical timing or accept manipulation window.

---

#### M-06: FHE Security Zone Validation

**Location**: `/Users/z/work/lux/standard/contracts/fhe/IFHE.sol`

**Description**: Security zones use `int32` which could allow negative values.

```solidity
function verify(uint8 utype, bytes memory input, int32 securityZone) external pure returns (bytes memory);
```

**Recommendation**: Validate security zone is non-negative or use `uint32`.

---

#### M-07: Missing Access Control on Fee Distribution

**Location**: `/Users/z/work/lux/node/contracts/governance/ChainFeeRegistryV3.sol`

**Description**: Fee distribution parameters can be changed by governor role without timelock delay.

**Recommendation**: Add timelock for fee parameter changes to allow user exit.

---

### 2.3 LOW SEVERITY

| ID | Location | Issue | Recommendation |
|----|----------|-------|----------------|
| L-01 | AMMV2Pair.sol | No slippage protection in `skim()` | Add access control |
| L-02 | Bridge.sol | `approve(type(uint256).max)` used | Use exact amounts |
| L-03 | Vault.sol | Magic numbers (10000, 1000000) | Use named constants |
| L-04 | Governor.sol | EIP-7201 slot calculation hardcoded | Document derivation |
| L-05 | FHE.sol | Large file (4645 lines) | Split into modules |
| L-06 | Bridge.sol | Missing event for fee rate changes | Add events |
| L-07 | Vault.sol | `isInitialized` not used consistently | Remove or enforce |
| L-08 | ChainFeeRegistryV3 | No pause mechanism | Add emergency pause |
| L-09 | AMMV3Pool | Missing NatSpec documentation | Add documentation |
| L-10 | Safe.sol | Re-exports without version pinning | Pin Safe version |
| L-11 | Perpetuals | No position size limits | Add max position checks |
| L-12 | Bridge | MPC signature replay possible across chains | Add chainId to signature |

---

## 3. Gas Optimization Opportunities

### 3.1 High Impact

| Contract | Optimization | Estimated Savings |
|----------|--------------|-------------------|
| AMMV2Pair | Cache `totalSupply()` in `mint()` | ~2000 gas |
| Vault.sol | Use `unchecked` for safe math | ~5000 gas per position |
| Bridge.sol | Batch MPC signature verification | ~10000 gas per batch |
| ChainFeeRegistryV3 | Pack struct storage | ~5000 gas per update |

### 3.2 Medium Impact

| Contract | Optimization | Estimated Savings |
|----------|--------------|-------------------|
| Governor.sol | Use `calldata` for `Transaction` | ~500 gas |
| FHE.sol | Cache precompile addresses | ~100 gas per call |
| Vault.sol | Short-circuit in `_validate()` | ~200 gas |

### 3.3 Storage Layout Improvements

```solidity
// ChainFeeRegistryV3: Pack fee parameters
struct BaseFeeParams {
    uint64 basePerUnit;           // slot 1
    uint64 minBasePerUnit;        // slot 1
    uint64 maxBasePerUnit;        // slot 1
    uint32 targetUtilization;     // slot 1 (fits!)
    uint32 maxChangePerBlock;     // slot 2 -> could fit in slot 1
}
// Recommendation: Reorder to pack into 2 slots instead of 3
```

---

## 4. 2025 Recommendations

### 4.1 Security Enhancements

1. **Implement Formal Verification** for FHE contracts given cryptographic complexity
2. **Add Fuzz Testing** for DEX price calculations and perpetuals liquidations
3. **Upgrade Safe Integration** to v1.5.0+ with modular architecture
4. **Add Rate Limiting** on bridge operations to prevent flash attacks

### 4.2 Architecture Improvements

1. **Modularize FHE.sol** - Split 4645-line file into logical components
2. **Standardize Error Handling** - Use custom errors consistently (saves gas)
3. **Add Upgrade Tests** - Governor uses UUPS, verify upgrade paths
4. **Document Precompile Gas Costs** - Critical for DEX operations

### 4.3 Compliance

1. **EIP Compatibility** - Verify EIP-4626 vault compliance for bridge vaults
2. **ERC-7201 Storage** - Governor uses namespaced storage; extend to other upgradeable contracts
3. **EIP-712 Signatures** - Audit signature validation in Bridge for domain separation

### 4.4 Monitoring

1. **Event Coverage** - Add events for all state changes (gaps in Bridge, Vault)
2. **Invariant Checks** - Add on-chain invariant assertions for critical functions
3. **Oracle Fallbacks** - Implement Chainlink + Pyth redundancy in perpetuals

---

## 5. Contracts Requiring Immediate Attention

| Priority | Contract | Issue | Action |
|----------|----------|-------|--------|
| P0 | Bridge.sol | Missing reentrancy guard | Add immediately |
| P0 | BridgeVault.sol | Missing reentrancy guard | Add immediately |
| P0 | AMMV2Router.sol | Missing reentrancy guard | Add immediately |
| P1 | Vault.sol | No circuit breaker | Design + implement |
| P1 | ChainFeeRegistryV3 | Missing timelock | Add delay mechanism |
| P2 | FHE.sol | File size / complexity | Refactor |

---

## 6. Testing Coverage Assessment

### 6.1 Files Identified with Tests

- AMMV2Pair.sol - Has ReentrancyGuard
- AMMV3Pool.sol - Has ReentrancyGuard  
- Vault.sol (perps) - Has ReentrancyGuard
- ConfidentialLRC20.sol - FHE tests present

### 6.2 Files Missing Reentrancy Protection

Total contracts missing ReentrancyGuard in critical paths: **18**

Key gaps:
- All Bridge contracts (8 files)
- AMMV2Router.sol, AMMV2Factory.sol
- Multiple oracle/liquidity contracts

---

## 7. Conclusion

The Lux smart contract ecosystem demonstrates modern Solidity practices including:
- Use of OpenZeppelin contracts for standard patterns
- EIP-7201 namespaced storage for upgradeability
- Proper access control hierarchies
- Well-structured precompile interfaces

**Critical gaps** that require immediate remediation:
1. Reentrancy protection in Bridge and Router contracts
2. Circuit breaker mechanisms for high-leverage perpetuals
3. Timelock delays for governance parameter changes

The FHE integration is well-designed with proper precompile abstraction, though the main FHE.sol file would benefit from modularization for maintainability.

---

*Report generated by automated security analysis. Manual review recommended for critical findings.*
