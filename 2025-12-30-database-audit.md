# Lux Database Layer Audit Report

**Date**: 2025-12-30
**Auditor**: Claude Code (Opus 4.5)
**Scope**: `/Users/z/work/lux/node/internal/database/`, `/Users/z/work/lux/node/x/merkledb/`, `/Users/z/work/lux/node/x/blockdb/`, `/Users/z/work/lux/node/x/archivedb/`, `/Users/z/work/lux/node/cache/`

---

## Executive Summary

The Lux database layer demonstrates sound engineering with multiple layers of crash recovery, checksumming, and concurrent access control. The architecture separates concerns effectively:

| Component | Risk Level | Key Finding |
|-----------|------------|-------------|
| BadgerDB Integration | Low | Thin wrapper, delegates to `luxfi/database` |
| PebbleDB Support | Low | Alternative backend, same interface |
| MerkleDB | Medium | Complex but well-designed; rebuild on unclean shutdown |
| BlockDB | Low | Strong crash recovery with checksums |
| ArchiveDB | Low | Simple append-only design |
| Caching | Medium | Size-based LRU; potential memory pressure under load |

**Overall Assessment**: Production-ready with minor recommendations for 2025.

---

## 1. BadgerDB Integration

### Implementation
- **Location**: `/Users/z/work/lux/node/internal/database/factory/factory.go`
- **Design**: Thin wrapper around `github.com/luxfi/database/factory.New`

```go
func New(name string, path string, readOnly bool, config []byte,
    gatherer metrics.MultiGatherer, logger log.Logger,
    metricsPrefix string, meterDBRegName string) (database.Database, error) {
    return factory.New(name, path, readOnly, config, gatherer, logger, metricsPrefix, meterDBRegName)
}
```

### Findings
- **Data Corruption Risk**: LOW - BadgerDB handles its own crash recovery internally
- **Batch Capacity**: Constants in `common.go` suggest awareness of write amplification

```go
const (
    BatchCapacityCap = 128 * units.MiB  // Maximum batch size
    BatchCapacityMin = 1 * units.MiB    // Minimum batch size
)
```

### Recommendations
1. Consider exposing BadgerDB's value log GC tuning for long-running nodes
2. Add metrics for LSM compaction pressure

---

## 2. PebbleDB Support

### Implementation
- Available as `"pebbledb"` option in factory
- Same `database.Database` interface as BadgerDB

### Findings
- **Alternative Backend**: Provides choice for operators
- **Interface Compliance**: Uses standard `database.Database` interface

### Recommendations
1. Document performance characteristics vs BadgerDB for operator guidance
2. Consider making PebbleDB the default (RocksDB lineage, battle-tested)

---

## 3. MerkleDB

### Implementation
- **Location**: `/Users/z/work/lux/node/x/merkledb/`
- **Design**: Radix trie with Merkle proofs, MVCC views

### Architecture

```
                    ┌─────────────────┐
                    │     merkleDB    │
                    │  (db.go:1400+)  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼───────┐   ┌────────▼────────┐   ┌───────▼───────┐
│intermediateDB │   │   valueNodeDB   │   │   onEvictCache│
│ (write buffer)│   │   (LRU cache)   │   │   (FIFO)      │
└───────────────┘   └─────────────────┘   └───────────────┘
```

### Crash Recovery Mechanism

```go
// Marker key for clean shutdown detection
cleanShutdownKey = []byte(string(metadataPrefix) + "cleanShutdown")
hadCleanShutdown = []byte{1}
didNotHaveCleanShutdown = []byte{0}
```

**Recovery Flow**:
1. On open: Check `cleanShutdownKey` value
2. If `didNotHaveCleanShutdown`: Call `rebuild()` to reconstruct trie
3. Immediately write `didNotHaveCleanShutdown` marker
4. On clean close: Write `hadCleanShutdown` marker

### Concurrency Model

**Dual Lock Pattern**:
```go
type merkleDB struct {
    lock       sync.RWMutex  // Protects general state
    commitLock sync.RWMutex  // Prevents concurrent commits
    // ...
}
```

**View-Based MVCC**:
- `NewView()` creates isolated snapshots
- Views share read access, commits serialize via `commitLock`

### Findings

| Area | Risk | Details |
|------|------|---------|
| Data Corruption | LOW | Rebuilds from raw key-values on crash |
| Race Conditions | LOW | Proper dual-lock prevents concurrent commits |
| Memory Usage | MEDIUM | Unbounded view accumulation possible |
| Performance | GOOD | Write buffers, batch eviction |

### Critical Code Paths

**Write Buffer Eviction** (`intermediate_node_db.go`):
```go
// Fatal error handling - closes database on write failures
if err := i.evictToDisk(evictionBatchSize); err != nil {
    return nil, err  // Propagates up, triggers shutdown
}
```

**Atomic Closed State** (`value_node_db.go`):
```go
type valueNodeDB struct {
    closed atomic.Bool  // Safe concurrent close detection
    // ...
}
```

### Recommendations
1. Add view lifecycle limits to prevent memory exhaustion
2. Consider background compaction for intermediate node DB
3. Add metrics for rebuild time on recovery

---

## 4. BlockDB

### Implementation
- **Location**: `/Users/z/work/lux/node/x/blockdb/database.go`
- **Design**: Block storage with index file and data files

### Crash Recovery Mechanism

**Index File Structure**:
```
┌──────────────────┬──────────────────┬─────────────────────┐
│ Version Header   │ Block Index      │ Checksum            │
│ (magic + version)│ (height->offset) │ (xxhash per block)  │
└──────────────────┴──────────────────┴─────────────────────┘
```

**Recovery Algorithm**:
1. Validate index file header
2. If corrupted: Scan data files sequentially
3. Verify each block's xxhash checksum
4. Rebuild index from valid blocks
5. Truncate at first corrupted block

### Concurrency Model

```go
type Database struct {
    closeMu             sync.RWMutex           // Close coordination
    fileOpenMu          sync.Mutex             // File handle management
    blockHeights        atomic.Pointer[...]    // Lock-free height queries
    nextDataWriteOffset atomic.Uint64          // Lock-free offset tracking
    headerWriteOccupied atomic.Bool            // Single header writer
}
```

**Atomic Operations**:
- `blockHeights` uses atomic pointer swap for lock-free reads
- `nextDataWriteOffset` enables concurrent write offset calculation
- `headerWriteOccupied` prevents concurrent header updates

### Compression
- Uses zstd compression for block data
- Configurable compression level

### Findings

| Area | Risk | Details |
|------|------|---------|
| Data Corruption | VERY LOW | xxhash checksums, recovery scan |
| Race Conditions | LOW | Well-designed atomic/mutex hybrid |
| Memory Usage | LOW | Streaming I/O, minimal buffering |
| Performance | GOOD | Lock-free reads, batch writes |

### Test Coverage
- `recovery_test.go` covers various corruption scenarios
- Tests include partial writes, truncated files, corrupted checksums

### Recommendations
1. Add periodic background checksum verification
2. Consider index file replication for faster recovery

---

## 5. ArchiveDB

### Implementation
- **Location**: `/Users/z/work/lux/node/x/archivedb/db.go`
- **Design**: Append-only height-indexed state changes

### Findings
- **Simplest Component**: Thin wrapper for height-based queries
- **No Complex Recovery**: Relies on underlying database's durability
- **Risk Level**: LOW

---

## 6. Caching Layer

### Implementation
- **Location**: `/Users/z/work/lux/node/cache/`

### LRU Cache Types

| Type | Location | Use Case |
|------|----------|----------|
| `SizedLRU` | `lru/sized_cache.go` | Size-based eviction |
| `LRU` | `lru_cache.go` | Count-based eviction |
| `onEvictCache` | `merkledb/cache.go` | Callback on eviction |

### SizedLRU Implementation

```go
type SizedLRU[K comparable, V any] struct {
    lock        sync.Mutex
    elements    *linked.Hashmap[K, *sizedElement[V]]
    maxSize     int
    currentSize int
}

type sizedElement[V any] struct {
    Value V
    Size  int  // Stored size prevents recalculation inconsistencies
}
```

**Key Design Decision**: Size stored with element prevents inconsistencies if value is modified after insertion.

### onEvictCache (MerkleDB)

```go
type onEvictCache[K comparable, V any] struct {
    lock       sync.RWMutex
    maxSize    int
    fifo       *linked.Hashmap[K, V]  // FIFO for eviction order
    onEviction func(K, V) error       // Callback on evict
}
```

**FIFO vs LRU**: Uses FIFO for eviction order, not LRU. This is intentional for write buffer semantics.

### Findings

| Area | Risk | Details |
|------|------|---------|
| Memory Leaks | LOW | Proper size tracking, eviction callbacks |
| Race Conditions | LOW | Mutex-protected operations |
| Performance | MEDIUM | Lock contention possible under high load |

### Recommendations
1. Consider sharded caches for reduced lock contention
2. Add cache hit/miss metrics for tuning
3. Evaluate ARC or 2Q algorithms for better hit rates

---

## Data Integrity Analysis

### Defense in Depth

```
Layer 1: Application Checksums (xxhash in BlockDB)
    │
    ▼
Layer 2: Clean Shutdown Markers (MerkleDB)
    │
    ▼
Layer 3: Database Engine Recovery (BadgerDB/PebbleDB)
    │
    ▼
Layer 4: Filesystem Journaling (ext4/APFS)
```

### Corruption Scenarios Handled

| Scenario | MerkleDB | BlockDB |
|----------|----------|---------|
| Process crash mid-write | Rebuild from raw KV | Checksum validation |
| Partial block write | N/A | Truncate at corruption |
| Index corruption | Rebuild trie | Scan data files |
| Power failure | Rebuild from raw KV | Rebuild index |

### Gap Analysis

| Scenario | Current Handling | Risk |
|----------|------------------|------|
| Bit rot in cold data | Not detected | LOW (rare) |
| Concurrent file access | Mutex protected | LOW |
| Full disk | Propagates error | MEDIUM |

---

## Performance Analysis

### Write Path

```
Application Write
    │
    ▼
┌───────────────┐
│ Write Buffer  │ ◄── Deferred disk writes
│ (in-memory)   │
└───────┬───────┘
        │ Batch eviction
        ▼
┌───────────────┐
│ BadgerDB/     │ ◄── LSM tree writes
│ PebbleDB      │
└───────────────┘
```

**Optimizations**:
- Write buffers reduce disk I/O
- Batch eviction amortizes write costs
- Atomic operations reduce lock overhead

### Read Path

```
Application Read
    │
    ▼
┌───────────────┐
│ LRU Cache     │ ◄── O(1) lookup
└───────┬───────┘
        │ Miss
        ▼
┌───────────────┐
│ Write Buffer  │ ◄── Check pending writes
└───────┬───────┘
        │ Miss
        ▼
┌───────────────┐
│ Database      │ ◄── Disk read
└───────────────┘
```

### Bottlenecks

| Component | Bottleneck | Mitigation |
|-----------|------------|------------|
| MerkleDB | Commit serialization | Expected (consistency) |
| BlockDB | Single header writer | Batched updates |
| Cache | Lock contention | Sharding (recommended) |

---

## Security Concerns

### Low Risk
1. **No External Input**: Database layer receives validated data from VM layer
2. **No Network Exposure**: Internal component, not directly accessible

### Moderate Risk
1. **Denial of Service**: Unbounded view creation could exhaust memory
2. **Resource Exhaustion**: Large batch operations could pressure memory

### Recommendations
1. Add view count limits per database instance
2. Implement memory pressure backoff for batch operations

---

## 2025 Recommendations

### Priority 1: Observability
- [ ] Add Prometheus metrics for cache hit rates
- [ ] Add metrics for MerkleDB rebuild time
- [ ] Add BlockDB checksum verification stats

### Priority 2: Performance
- [ ] Evaluate sharded caches for high-throughput scenarios
- [ ] Consider ARC/2Q cache replacement algorithms
- [ ] Profile lock contention under production load

### Priority 3: Resilience
- [ ] Implement periodic background checksum verification for BlockDB
- [ ] Add memory pressure detection and backoff
- [ ] Consider index file replication for faster BlockDB recovery

### Priority 4: Documentation
- [ ] Document BadgerDB vs PebbleDB performance characteristics
- [ ] Add runbook for crash recovery scenarios
- [ ] Document tuning parameters for different hardware profiles

---

## Appendix A: File Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `internal/database/factory/factory.go` | ~30 | Database creation |
| `internal/database/common.go` | ~20 | Batch constants |
| `x/merkledb/db.go` | ~1400 | Core MerkleDB |
| `x/merkledb/cache.go` | ~150 | onEvictCache |
| `x/merkledb/intermediate_node_db.go` | ~250 | Write buffer |
| `x/merkledb/value_node_db.go` | ~200 | Value storage |
| `x/blockdb/database.go` | ~1200 | Block storage |
| `x/archivedb/db.go` | ~200 | Archive storage |
| `cache/lru/sized_cache.go` | ~150 | Size-based LRU |
| `cache/lru_cache.go` | ~100 | Basic LRU |

## Appendix B: Key Constants

```go
// Batch capacity management
BatchCapacityCap = 128 * units.MiB
BatchCapacityMin = 1 * units.MiB

// MerkleDB markers
cleanShutdownKey = []byte(metadataPrefix + "cleanShutdown")
hadCleanShutdown = []byte{1}
didNotHaveCleanShutdown = []byte{0}

// BlockDB
indexFileVersion = 1
dataFileVersion = 1
```

---

**End of Audit Report**
