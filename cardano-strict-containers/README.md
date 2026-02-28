# cardano-strict-containers

Strict (spine- and value-strict) variants of standard Haskell containers.

[![Hackage](https://img.shields.io/hackage/v/cardano-strict-containers)](https://hackage.haskell.org/package/cardano-strict-containers)

## Overview

Haskell is lazy by default. Data structures in `base` and `containers` can
accumulate large numbers of unevaluated **thunks** (deferred computations)
inside their cells. For short programs this is efficient; for a long-running
process like `cardano-node` it causes unbounded memory growth and
unpredictable GC pauses.

`cardano-strict-containers` provides strict drop-in replacements for the most
commonly used container types:

| Module | Type | Replaces |
|--------|------|---------|
| `Data.Sequence.Strict` | `StrictSeq a` | `Data.Sequence.Seq` |
| `Data.Maybe.Strict` | `StrictMaybe a` | `Prelude.Maybe` |
| `Data.FingerTree.Strict` | `StrictFingerTree v a` | `Data.FingerTree.FingerTree` |
| `Data.Unit.Strict` | `StrictUnit` | `()` |

The API mirrors the standard containers exactly, so migration is a matter of
changing import paths.

## Installation

```cabal
build-depends: cardano-strict-containers >= 0.1
```

## `StrictSeq` — Strict Sequence

A doubly-ended queue backed by a finger tree. Supports O(1) access at both
ends and O(log n) splitting, concatenation, and lookup by position.

Used in the ledger for ordered collections of transactions within a block.

```haskell
import Data.Sequence.Strict

-- Construction
empty  :: StrictSeq a
single :: a -> StrictSeq a     -- StrictSeq.singleton

-- Append / prepend — O(1) amortised
(|>) :: StrictSeq a -> a -> StrictSeq a   -- append to right
(<|) :: a -> StrictSeq a -> StrictSeq a   -- prepend to left

-- Concatenation — O(log(min(n,m)))
(><) :: StrictSeq a -> StrictSeq a -> StrictSeq a

-- Length — O(1)
length :: StrictSeq a -> Int

-- Convert
fromList :: [a] -> StrictSeq a
toList   :: StrictSeq a -> [a]
```

### Example

```haskell
import Data.Sequence.Strict (StrictSeq)
import qualified Data.Sequence.Strict as Seq

-- Build a sequence of transactions
buildTxSeq :: [Tx] -> StrictSeq Tx
buildTxSeq = Seq.fromList

-- Add a transaction to the end
addTx :: StrictSeq Tx -> Tx -> StrictSeq Tx
addTx txs tx = txs Seq.|> tx

-- Add a transaction to the front (e.g. fee transaction)
prependTx :: Tx -> StrictSeq Tx -> StrictSeq Tx
prependTx = (Seq.<|)

-- Check for emptiness
isEmptyBlock :: StrictSeq Tx -> Bool
isEmptyBlock = Seq.null

-- Fold over transactions (strict, avoids thunk buildup)
totalFees :: StrictSeq Tx -> Lovelace
totalFees = foldl' (\acc tx -> acc + txFee tx) 0
```

## `StrictMaybe` — Strict Optional Value

A strict variant of `Maybe`. `SJust x` evaluates `x` immediately on
construction, so a `StrictMaybe` never holds a thunk inside `SJust`.

Used throughout the ledger for optional fields in UTxO entries, governance
parameters, and protocol configuration.

```haskell
import Data.Maybe.Strict

-- Constructors
SNothing :: StrictMaybe a
SJust    :: a -> StrictMaybe a   -- 'a' evaluated immediately

-- Elimination
strictMaybe :: b -> (a -> b) -> StrictMaybe a -> b
strictMaybe def f SNothing  = def
strictMaybe _   f (SJust x) = f x

-- Conversion
strictMaybeToMaybe :: StrictMaybe a -> Maybe a
maybeToStrictMaybe :: Maybe a -> StrictMaybe a

-- Common utilities
fromSMaybe :: a -> StrictMaybe a -> a
isSNothing :: StrictMaybe a -> Bool
isSJust    :: StrictMaybe a -> Bool
```

### Example

```haskell
import Data.Maybe.Strict

-- Represent an optional stake delegation target
data StakeCredential = StakeCredential { poolId :: PoolId }

data StakeEntry = StakeEntry
  { stakeCredential :: StakeCredential
  , delegation      :: StrictMaybe PoolId   -- Nothing if undelegated
  }

-- Check if a stake entry is delegated
isDelegated :: StakeEntry -> Bool
isDelegated = isSJust . delegation

-- Get delegation target (with default)
delegationTarget :: StakeEntry -> PoolId -> PoolId
delegationTarget entry defaultPool =
  fromSMaybe defaultPool (delegation entry)

-- Update delegation
delegate :: PoolId -> StakeEntry -> StakeEntry
delegate pool entry = entry { delegation = SJust pool }

undelegate :: StakeEntry -> StakeEntry
undelegate entry = entry { delegation = SNothing }
```

## `StrictFingerTree` — Strict Annotated Sequence

A strict variant of `Data.FingerTree.FingerTree`. Finger trees are annotated
sequences — each subtree carries a cached `Measured` value that enables
O(log n) search by accumulated measure.

Used in `cardano-strict-containers` as the backing structure for `StrictSeq`.

```haskell
import Data.FingerTree.Strict
import Data.Measure.Class (Measure (..))

-- The Measured typeclass provides the annotation
class Measured v a where
  measure :: a -> v

-- Build and query a strict finger tree
empty    :: Measured v a => StrictFingerTree v a
singleton :: Measured v a => a -> StrictFingerTree v a
(|>)     :: Measured v a => StrictFingerTree v a -> a -> StrictFingerTree v a

-- Split at a point where the accumulated measure satisfies a predicate
split
  :: Measured v a
  => (v -> Bool)
  -> StrictFingerTree v a
  -> (StrictFingerTree v a, StrictFingerTree v a)
```

### Example: find transactions up to a size limit

```haskell
import Data.FingerTree.Strict
import Data.Sequence.Strict    (StrictSeq)

newtype TxSize = TxSize Word64
  deriving (Eq, Ord, Show)
  deriving (Semigroup, Monoid) via (Sum Word64)

instance Measured TxSize Tx where
  measure tx = TxSize (serializedSize tx)

-- Take transactions up to a block size limit
takeTxsUpTo
  :: Word64               -- max block body size in bytes
  -> StrictSeq Tx
  -> StrictSeq Tx
takeTxsUpTo limit txs =
  let (fits, _) = split (> TxSize limit) (toFingerTree txs)
  in  fromFingerTree fits
```

## `StrictUnit`

A strict version of `()`. In practice identical to `()` at runtime, but
useful in generic contexts where strictness annotations on all fields are
required.

```haskell
import Data.Unit.Strict (StrictUnit (..))

unit :: StrictUnit
unit = StrictUnit
```

## Why Strict Containers Matter

Consider a lazy `Map` accumulating updates over millions of blocks:

```haskell
-- Lazy — builds a thunk chain for every update:
let m' = Map.insert k v m   -- stores (insert k v m), not the result

-- After 1M updates, forcing the map forces 1M nested thunks at once:
-- → GC spike, potential stack overflow
```

With strict containers, each update is evaluated immediately:

```haskell
-- Strict — evaluates the update now:
let m' = Map.Strict.insert k v m   -- stores the final value
-- No thunk accumulation, predictable memory usage
```

`cardano-node` processes millions of UTxO updates per day. Strict containers
keep memory usage flat and GC pauses short.

## Running Tests

```bash
cabal test cardano-strict-containers:tests
```
