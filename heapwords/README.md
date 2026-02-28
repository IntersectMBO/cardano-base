# heapwords

Heap memory footprint estimation for Haskell values.

[![Hackage](https://img.shields.io/hackage/v/heapwords)](https://hackage.haskell.org/package/heapwords)

## Overview

`heapwords` provides the `HeapWords` typeclass, which estimates how many
machine words a Haskell value occupies on the heap. On a 64-bit system,
1 word = 8 bytes.

The Cardano mempool uses `HeapWords` to enforce a memory limit on pending
transactions. Without this limit, an adversary could flood the mempool with
transactions, causing the node to exhaust memory. By tracking heap usage,
the mempool can reject new transactions when the memory budget is full.

## Installation

```cabal
build-depends: heapwords >= 0.1
```

## The `HeapWords` Typeclass

```haskell
class HeapWords a where
  -- | Estimate the number of heap words consumed by this value.
  -- The estimate covers constructors and their fields, but does
  -- not account for sharing (aliased sub-values are counted twice).
  heapWords :: a -> Int
```

A heap word estimate for a constructor:
```
words(Con field1 field2 ... fieldN) = 1 (header) + N (fields) + Σ words(fieldᵢ)
```

## Usage Example

```haskell
import Cardano.HeapWords

-- Built-in instances:
-- >>> heapWords (42 :: Int)
-- 0   -- unboxed Int# needs 0 extra words (stored directly)

-- >>> heapWords (Just (42 :: Int))
-- 2   -- Just header (1) + pointer (1); Int# stored unboxed
--     -- (actual value depends on representation)

-- >>> heapWords ([] :: [Int])
-- 1   -- [] constructor

-- >>> heapWords [1 :: Int, 2, 3]
-- 10  -- 3 × (: header + ptr + Int#) = 9, plus [] = 1

-- >>> heapWords ("hello" :: String)
-- 31  -- 5 chars × 5 words each + [] + overhead
```

## Defining a `HeapWords` Instance

When creating a type that will be stored in the mempool or ledger state,
implement `HeapWords` by summing the field estimates plus the constructor
header:

```haskell
import Cardano.HeapWords

data TxIn = TxIn
  { txHash  :: TxId        -- a ByteString-based hash
  , txIndex :: Word16
  }

instance HeapWords TxIn where
  heapWords (TxIn txid idx) =
    1                    -- TxIn constructor header
    + heapWords txid     -- TxId (ByteString)
    + heapWords idx      -- Word16 (usually 0 if unboxed)

-- Word16 and other small unboxed types typically contribute 0 words
-- since they are stored directly in the constructor.
```

## Using `heapWords` for Memory Budgeting

```haskell
import Cardano.HeapWords

-- A simple mempool with a word-based memory limit
data Mempool tx = Mempool
  { transactions :: [tx]
  , usedWords    :: Int
  , maxWords     :: Int
  }

-- Try to add a transaction; fail if it would exceed the budget
addToMempool
  :: HeapWords tx
  => tx
  -> Mempool tx
  -> Either String (Mempool tx)
addToMempool tx pool =
  let txSize = heapWords tx
      newUsed = usedWords pool + txSize
  in  if newUsed > maxWords pool
        then Left $ "Mempool full: would use "
                  <> show newUsed <> " / "
                  <> show (maxWords pool) <> " words"
        else Right pool
              { transactions = tx : transactions pool
              , usedWords    = newUsed
              }

-- Create a mempool with a 50 MB limit
-- 50 MB = 50 * 1024 * 1024 / 8 words on 64-bit
newMempool :: Mempool tx
newMempool = Mempool [] 0 (50 * 1024 * 1024 `div` 8)
```

## Notes

- Results are **estimates**, not exact measurements. They do not account
  for GHC's pointer tagging optimisations or sharing between values.
- For production memory accounting, use the estimates as a conservative
  upper bound rather than a precise measurement.
- Instances are provided for `Int`, `Word`, `Word8`–`Word64`, `Integer`,
  `ByteString`, `Text`, `Maybe`, `Either`, tuples, lists, `Map`, `Set`,
  and all Cardano base types.
