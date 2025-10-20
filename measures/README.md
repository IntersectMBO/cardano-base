# Measures

## Overview

The `measures` package provides abstractions for working with multidimensional measurements and capacity-based operations. It's designed for scenarios where you need to track and limit resources across multiple dimensions simultaneously, such as managing memory usage, transaction sizes, or other bounded quantities.

## Core Concepts

The package revolves around the `Measure` type class, which represents quantities that can be:
- **Combined** using `plus` (addition)
- **Compared** using partial ordering (`min`, `max`)
- **Zeroed** with a `zero` identity element

Think of measurements like `(Age, Height)`, `(MemoryUsage, CPUTime)`, or `(ByteSize, TransactionCount)` - tuples where each component represents a different dimension of resource usage.

## Key Type Class

```haskell
class Measure a where
  zero :: a                    -- Identity element (e.g., (0, 0))
  plus :: a -> a -> a          -- Combine measurements
  min :: a -> a -> a           -- Component-wise minimum
  max :: a -> a -> a           -- Component-wise maximum
```

## Usage Examples

### Basic Measurements

```haskell
import Data.Measure

-- Define a 2D measurement type
type ResourceUsage = (Int, Int)  -- (Memory, CPU)

-- ResourceUsage automatically has Measure instances through tuples
memory_cpu :: ResourceUsage
memory_cpu = (100, 50)  -- 100MB memory, 50% CPU

-- Combine measurements
total = plus (100, 50) (200, 30)  -- (300, 80)

-- Check capacity constraints
capacity = (500, 100)
canFit = memory_cpu <= capacity  -- True (component-wise comparison)
```

### Partial Ordering

```haskell
-- Partial ordering: <= means ALL components are <=
usage1 = (100, 50)
usage2 = (80, 60)
capacity = (200, 100)

-- Check if usage1 fits in capacity
fits1 = usage1 <= capacity      -- True: both 100<=200 and 50<=100

-- usage1 and usage2 are incomparable (neither <= the other)
comparable = usage1 <= usage2    -- False: 100 > 80 but 50 < 60
```

### Capacity-Based List Operations

The real power comes from capacity-aware list operations:

```haskell
-- splitAt: Split list when accumulated measure hits limit
splitAt :: Measure a => (e -> a) -> a -> [e] -> ([e], [e])

-- Example: Split transactions by total (size, count) limits
data Transaction = Tx { size :: Int, priority :: Int }

measureTx :: Transaction -> (Int, Int)  -- (size, count)
measureTx tx = (size tx, 1)

transactions = [Tx 100 1, Tx 200 2, Tx 150 1, Tx 50 3]
blockLimit = (400, 3)  -- Max 400 bytes, 3 transactions

-- Split into what fits in block vs overflow
(inBlock, overflow) = splitAt measureTx blockLimit transactions
-- inBlock: first transactions totaling <= (400, 3)
-- overflow: remaining transactions
```

### Resource-Constrained Processing

```haskell
-- take: Get prefix that fits within limits
take :: Measure a => (e -> a) -> a -> [e] -> [e]

-- drop: Skip prefix that fits, return remainder
drop :: Measure a => (e -> a) -> a -> [e] -> [e]

-- Example: Memory-constrained batch processing
data Job = Job { memReq :: Int, cpuReq :: Int }

measureJob :: Job -> (Int, Int)
measureJob (Job mem cpu) = (mem, cpu)

jobs = [Job 100 10, Job 200 20, Job 150 15, Job 300 25]
systemLimit = (450, 40)

-- Process as many jobs as fit in system limits
batch1 = take measureJob systemLimit jobs
remaining = drop measureJob systemLimit jobs

putStrLn $ "Processing " ++ show (length batch1) ++ " jobs"
putStrLn $ "Deferred " ++ show (length remaining) ++ " jobs"
```

## Advanced Examples

### Custom Measurement Types

```haskell
-- Define custom multi-dimensional resource
data NetworkResource = NetworkResource
  { bandwidth :: Int     -- MB/s
  , connections :: Int   -- active connections
  , latency :: Int       -- milliseconds
  } deriving (Eq, Show)

-- Manual Measure instance (tuples get this automatically)
instance Measure NetworkResource where
  zero = NetworkResource 0 0 0

  plus (NetworkResource b1 c1 l1) (NetworkResource b2 c2 l2) =
    NetworkResource (b1 + b2) (c1 + c2) (max l1 l2)  -- max latency

  min (NetworkResource b1 c1 l1) (NetworkResource b2 c2 l2) =
    NetworkResource (min b1 b2) (min c1 c2) (min l1 l2)

  max (NetworkResource b1 c1 l1) (NetworkResource b2 c2 l2) =
    NetworkResource (max b1 b2) (max c1 c2) (max l1 l2)
```

### Blockchain Transaction Batching

```haskell
import Data.Measure

type TxLimits = (Int, Int, Int)  -- (bytes, gas, count)

data CardanoTx = CardanoTx
  { txBytes :: Int
  , txGas :: Int
  } deriving (Show)

-- Measure function for transactions
measureTx :: CardanoTx -> TxLimits
measureTx tx = (txBytes tx, txGas tx, 1)

-- Block limits
blockLimits :: TxLimits
blockLimits = (1000000, 5000000, 100)  -- 1MB, 5M gas, 100 txs

-- Split transactions into valid blocks
createBlocks :: [CardanoTx] -> [[CardanoTx]]
createBlocks [] = []
createBlocks txs =
  let (block, rest) = splitAt measureTx blockLimits txs
  in block : createBlocks rest

-- Example usage
transactions = [CardanoTx 1000 50000, CardanoTx 2000 100000, CardanoTx 500 25000]
blocks = createBlocks transactions
putStrLn $ "Created " ++ show (length blocks) ++ " blocks"
```

## Common Patterns

### Memory Management
```haskell
type MemoryUsage = (Int, Int)  -- (heap, stack)

-- Check if operation fits in memory budget
fitsInMemory :: MemoryUsage -> MemoryUsage -> Bool
fitsInMemory usage limit = usage <= limit

-- Accumulate memory usage safely
safeAccumulate :: [MemoryUsage] -> MemoryUsage -> [MemoryUsage]
safeAccumulate usages limit = take id limit usages
```

### Rate Limiting
```haskell
type RateLimit = (Int, Int, Int)  -- (requests, bandwidth, duration)

measureRequest :: Request -> RateLimit
measureRequest req = (1, requestSize req, requestTime req)

-- Apply rate limiting
limitedRequests :: [Request] -> RateLimit -> [Request]
limitedRequests reqs limit = take measureRequest limit reqs
```

## Performance Considerations

- **Lazy Evaluation**: `take` is non-strict and works well with infinite lists
- **Strict Accumulation**: Internal counters use `BangPatterns` for efficiency
- **Early Termination**: Operations stop as soon as limits are exceeded
- **Memory Efficient**: Minimal allocation for capacity checking

## Integration

This package is commonly used with:
- **Resource management** in long-running services
- **Transaction batching** in blockchain applications
- **Memory-constrained** processing
- **Rate limiting** and throttling systems

## See Also

- **Base types** - Tuples `(a, b)` automatically implement `Measure`
- **Custom instances** - Implement `Measure` for domain-specific types
- **Blockchain applications** - Transaction and block size management