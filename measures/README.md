# measures

Abstract measurement algebra for annotated finger trees.

[![Hackage](https://img.shields.io/hackage/v/measures)](https://hackage.haskell.org/package/measures)

## Overview

`measures` provides the `Measure` typeclass — an abstraction for values
that can be **accumulated** (via `Monoid`) and **compared** (via `Ord`).

Finger trees use cached measure annotations to enable O(log n) search by
any accumulated property of a sequence. `measures` provides the typeclass
that finger tree elements implement to supply those annotations.

## Installation

```cabal
build-depends: measures >= 0.1
```

## The `Measure` Typeclass

```haskell
-- In Data.Measure.Class:
class (Monoid v, Ord v) => Measure v a where
  -- | Compute the measure of a single element.
  measure :: a -> v
```

The type parameters:
- `v` — the **measurement type** (must be a `Monoid` and `Ord`)
- `a` — the **element type** being measured

## How Finger Trees Use Measures

A finger tree with measure `v` caches the accumulated `v` at each internal
node. This lets you binary-search the tree by the accumulated measure in
O(log n):

```
Tree: [tx1, tx2, tx3, tx4, tx5]
      ↓
Cached sizes:  5 | 12 | 3 | 8 | 7   (individual)
Prefix sums:   5 | 17 | 20 | 28 | 35 (accumulated left-to-right)

"Find the split point where total size exceeds 20"
→ binary search on prefix sums → O(log n)
```

## Usage Examples

### Measuring a sequence by element count

```haskell
import Data.Measure.Class
import Data.Sequence.Strict (StrictSeq)

-- Use the built-in Sum Int measure for counting
instance Measure (Sum Int) a where
  measure _ = Sum 1    -- every element counts as 1

-- Now split a sequence at position n in O(log n):
splitAt' :: Int -> StrictSeq a -> (StrictSeq a, StrictSeq a)
splitAt' n = split (\(Sum count) -> count > n)
```

### Measuring transactions by byte size

A more realistic example: finding all transactions that fit within a
block's maximum body size.

```haskell
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

import Data.Measure.Class
import Data.FingerTree.Strict
import Data.Monoid (Sum (..))

-- Our measure type: accumulated byte size
newtype Bytes = Bytes { unBytes :: Word64 }
  deriving (Show, Eq, Ord)
  deriving (Semigroup, Monoid) via Sum Word64

-- Transactions carry a pre-computed serialised size
data Tx = Tx
  { txId       :: TxId
  , txPayload  :: ByteString
  , txByteSize :: Word64        -- cached at construction
  }

instance Measure Bytes Tx where
  measure tx = Bytes (txByteSize tx)

-- Select transactions that fit in maxSize bytes — O(log n)
selectFitting
  :: Word64                        -- max block body size
  -> StrictFingerTree Bytes Tx
  -> StrictFingerTree Bytes Tx
selectFitting maxSize txs =
  let (fits, _) = split (> Bytes maxSize) txs
  in  fits

-- Usage:
-- buildBlock :: Word64 -> [Tx] -> [Tx]
-- buildBlock maxBodySize pending =
--   let tree   = fromList pending
--       fitted = selectFitting maxBodySize tree
--   in  toList fitted
```

### Measuring by fee (priority ordering)

```haskell
newtype Lovelace = Lovelace Word64
  deriving (Eq, Ord, Show)
  deriving (Semigroup, Monoid) via Sum Word64

instance Measure Lovelace Tx where
  measure tx = txFee tx

-- Find the cut-off where accumulated fees exceed a threshold — O(log n)
highValueTxs :: Lovelace -> StrictFingerTree Lovelace Tx -> [Tx]
highValueTxs threshold txs =
  let (_, highFee) = split (>= threshold) txs
  in  toList highFee
```

## The `Data.Measure` Module

`Data.Measure` re-exports the `Measure` typeclass and provides common
pre-built instances:

```haskell
import Data.Measure

-- Count elements:
instance Measure (Sum Int) a where
  measure _ = Sum 1

-- Combine multiple measures with a tuple:
instance (Measure v1 a, Measure v2 a) => Measure (v1, v2) a where
  measure x = (measure x, measure x)
```

## Running Tests

```bash
cabal test measures:tests
```
