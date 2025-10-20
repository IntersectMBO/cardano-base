# heapwords

## Overview

The `heapwords` package provides utilities for measuring and analyzing heap memory usage of Haskell values. It allows developers to calculate the exact memory footprint of data structures, which is essential for memory-sensitive applications like blockchain nodes where memory usage must be carefully monitored and optimized.

## Core Functionality

### HeapWords Type Class

The main interface is the `HeapWords` type class, which calculates the size of values in heap words:

```haskell
class HeapWords a where
  heapWords :: a -> Int  -- Size in words (multiply by 8 for bytes on 64-bit)
```

### Memory Size Utilities

```haskell
heapSizeMb :: Int -> Int    -- Convert words to megabytes
heapSizeKb :: Int -> Int    -- Convert words to kilobytes
wordSize :: Int             -- 8 bytes on 64-bit architecture
```

## Usage Examples

### Basic Memory Measurement

```haskell
import Cardano.HeapWords

-- Measure simple values
intSize = heapWords (42 :: Int)              -- Typically 1 word
stringSize = heapWords "Hello, World!"      -- Varies by string length
listSize = heapWords [1, 2, 3, 4, 5]       -- List cons cells + elements

-- Convert to human-readable sizes
sizeInBytes = intSize * wordSize             -- 8 bytes
sizeInKB = heapSizeKb stringSize            -- KB
sizeInMB = heapSizeMb listSize              -- MB

putStrLn $ "Integer uses " ++ show sizeInBytes ++ " bytes"
putStrLn $ "String uses " ++ show sizeInKB ++ " KB"
putStrLn $ "List uses " ++ show sizeInMB ++ " MB"
```

### Data Structure Analysis

```haskell
import Cardano.HeapWords
import qualified Data.Map as Map
import qualified Data.Set as Set

-- Analyze container memory usage
analyzeContainers :: IO ()
analyzeContainers = do
  let smallMap = Map.fromList [(i, i*2) | i <- [1..100]]
  let largeSet = Set.fromList [1..10000]
  let textData = replicate 1000 "Sample text"

  putStrLn $ "Small map (100 entries): " ++ show (heapWords smallMap) ++ " words"
  putStrLn $ "Large set (10k entries): " ++ show (heapWords largeSet) ++ " words"
  putStrLn $ "Text list (1000 items): " ++ show (heapWords textData) ++ " words"

  -- Memory efficiency comparison
  let mapMB = heapSizeMb (heapWords smallMap)
  let setMB = heapSizeMb (heapWords largeSet)

  putStrLn $ "Map uses " ++ show mapMB ++ " MB"
  putStrLn $ "Set uses " ++ show setMB ++ " MB"
```

### Custom Data Type Measurement

```haskell
import Cardano.HeapWords

-- Define a blockchain transaction type
data Transaction = Transaction
  { txId :: String
  , txInputs :: [String]
  , txOutputs :: [(String, Int)]
  , txFee :: Int
  } deriving (Show)

-- HeapWords instance is automatically derived for most standard types
-- but you can also measure manually:
measureTransaction :: Transaction -> Int
measureTransaction tx =
  heapWords (txId tx) +
  heapWords (txInputs tx) +
  heapWords (txOutputs tx) +
  heapWords (txFee tx) +
  4  -- 4 words for the Transaction constructor overhead

-- Example usage
sampleTx = Transaction
  { txId = "abc123"
  , txInputs = ["input1", "input2"]
  , txOutputs = [("output1", 100), ("output2", 200)]
  , txFee = 10
  }

txSize = measureTransaction sampleTx
putStrLn $ "Transaction size: " ++ show txSize ++ " words (" ++
           show (txSize * wordSize) ++ " bytes)"
```

## Advanced Usage

### Memory Profiling

```haskell
import Cardano.HeapWords

-- Profile memory usage of different implementations
compareImplementations :: IO ()
compareImplementations = do
  let list = [1..1000] :: [Int]
  let vector = V.fromList [1..1000]
  let unboxedVector = V.U.fromList [1..1000]

  putStrLn "Memory usage comparison:"
  putStrLn $ "List: " ++ show (heapSizeMb (heapWords list)) ++ " MB"
  putStrLn $ "Boxed Vector: " ++ show (heapSizeMb (heapWords vector)) ++ " MB"
  putStrLn $ "Unboxed Vector: " ++ show (heapSizeMb (heapWords unboxedVector)) ++ " MB"
```

### Blockchain Memory Monitoring

```haskell
import Cardano.HeapWords

-- Monitor blockchain state memory usage
data BlockchainState = BlockchainState
  { ledger :: Map.Map String Int
  , mempool :: [Transaction]
  , recentBlocks :: [Block]
  } deriving (Show)

monitorMemoryUsage :: BlockchainState -> IO ()
monitorMemoryUsage state = do
  let totalWords = heapWords state
  let totalMB = heapSizeMb totalWords

  putStrLn $ "Blockchain state uses " ++ show totalMB ++ " MB"

  -- Component breakdown
  let ledgerMB = heapSizeMb (heapWords (ledger state))
  let mempoolMB = heapSizeMb (heapWords (mempool state))
  let blocksMB = heapSizeMb (heapWords (recentBlocks state))

  putStrLn $ "  Ledger: " ++ show ledgerMB ++ " MB"
  putStrLn $ "  Mempool: " ++ show mempoolMB ++ " MB"
  putStrLn $ "  Recent blocks: " ++ show blocksMB ++ " MB"

  -- Memory pressure warning
  when (totalMB > 1000) $
    putStrLn "⚠️  Warning: Memory usage exceeds 1GB"
```

### Memory-Bounded Operations

```haskell
import Cardano.HeapWords

-- Process data with memory constraints
processWithMemoryLimit :: Int -> [a] -> IO [a]
processWithMemoryLimit maxMB items = do
  let maxWords = maxMB * 1024 * 1024 `div` wordSize

  let processChunk acc remaining currentSize
        | currentSize >= maxWords = return (reverse acc)
        | null remaining = return (reverse acc)
        | otherwise = do
            let item = head remaining
            let itemSize = heapWords item
            let newSize = currentSize + itemSize

            if newSize <= maxWords
              then processChunk (item : acc) (tail remaining) newSize
              else return (reverse acc)

  processChunk [] items 0
```

## Built-in HeapWords Instances

The package provides `HeapWords` instances for many common types:

### Basic Types
- `Int`, `Word`, `Integer`, `Natural`
- `Bool`, `Char`
- `Float`, `Double`
- `()` (unit type)

### Container Types
- Lists `[a]`
- `Maybe a`
- `Either a b`
- Tuples `(a, b)`, `(a, b, c)`, etc.

### Collections
- `ByteString` (strict and lazy)
- `Text`
- `Map k v`
- `Set a`
- `IntMap a`
- `IntSet`
- `Seq a`
- `Vector a` (boxed and unboxed)

### Time Types
- `Day`
- `UTCTime`

## Helper Functions

The package provides convenient functions for measuring multiple values:

```haskell
heapWords0 :: Int                              -- Constant 0
heapWords1 :: HeapWords a => a -> Int
heapWords2 :: (HeapWords a, HeapWords b) => a -> b -> Int
-- ... up to heapWords13 for measuring multiple values at once

-- Example: measure a complex data structure's components
totalSize = heapWords4 field1 field2 field3 field4
```

## Performance Considerations

- **Zero Runtime Cost**: Memory measurement happens at compile time where possible
- **64-bit Assumption**: Calculations assume 64-bit architecture (8-byte words)
- **Approximation**: Measures heap words, not total memory including GC overhead
- **Deep Evaluation**: Some instances require fully evaluating the structure

## Memory Optimization Tips

1. **Use Unboxed Types**: `Vector.Unboxed` uses less memory than `Vector`
2. **Strict Fields**: Use `!` to avoid storing thunks
3. **Appropriate Containers**: Choose `IntMap` over `Map Int` for integer keys
4. **Memory Monitoring**: Regularly check memory usage in long-running applications

## Integration with Cardano

This package is particularly useful in the Cardano ecosystem for:

- **Node Memory Management**: Monitoring blockchain state size
- **Transaction Pool**: Managing mempool memory usage
- **UTXO Set**: Tracking ledger state memory footprint
- **Performance Tuning**: Optimizing data structure choices

## See Also

- **GHC Profiling** - Use with `+RTS -h` for comprehensive memory profiling
- **cardano-strict-containers** - Memory-efficient strict data structures
- **NoThunks** - Detect memory leaks from unevaluated thunks