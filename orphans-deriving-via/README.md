# orphans-deriving-via

Orphan typeclass instances for external types, implemented via `DerivingVia`.

[![Hackage](https://img.shields.io/hackage/v/orphans-deriving-via)](https://hackage.haskell.org/package/orphans-deriving-via)

## Overview

An **orphan instance** is a typeclass instance defined in a module that owns
neither the typeclass nor the type. In Haskell, orphan instances are sometimes
necessary when neither the typeclass nor the type is under your control —
for example, providing a `NoThunks` instance for a type defined in an external
library.

`orphans-deriving-via` collects these orphan instances for types used across
the Cardano codebase, implemented cleanly using `DerivingVia` to avoid
repetitive boilerplate.

## Installation

```cabal
build-depends: orphans-deriving-via >= 0.1
```

> **Note:** Import this package only where you actually need the instances.
> Because these are orphan instances, importing the module in multiple
> compilation units can cause "duplicate instance" errors. The typical pattern
> is to import it at the top of your executable or test entry point, not in
> library modules.

## Modules

### `Data.DerivingVia.NoThunks`

Provides orphan `NoThunks` instances for external types using `DerivingVia`.

`NoThunks` (from the [`nothunks`](https://hackage.haskell.org/package/nothunks)
package) is a typeclass for detecting unexpected unevaluated thunks in a
value. Cardano uses this in test suites to catch memory leaks: if a value
that should be fully evaluated still contains thunks, the test fails.

```haskell
import Data.DerivingVia.NoThunks
```

#### How it works

```haskell
-- DerivingVia strategy: check for thunks the same way InspectHeap does
-- (i.e. structurally traverse the value and report any thunks found)
deriving via InspectHeap SomeExternalType
  instance NoThunks SomeExternalType
```

#### Usage in tests

```haskell
import Test.NoThunks (noThunks, ThunkInfo (..))
import Data.DerivingVia.NoThunks ()   -- import to bring instances into scope

-- Check that a value is thunk-free after evaluation
assertNoThunks :: NoThunks a => String -> a -> IO ()
assertNoThunks label val = do
  result <- noThunks [] val
  case result of
    Nothing             -> pure ()   -- all good
    Just (ThunkInfo ctx) ->
      assertFailure $
        label <> " contains unexpected thunks at: " <> show ctx

-- Example test:
testLedgerStateNoThunks :: IO ()
testLedgerStateNoThunks = do
  let state = applyBlock block initialState
  evaluate (force state)          -- fully evaluate
  assertNoThunks "LedgerState" state
```

### `Data.DerivingVia.DeepSeq`

Provides orphan `NFData` instances for external types using `DerivingVia`.

`NFData` (from [`deepseq`](https://hackage.haskell.org/package/deepseq)) marks
types that can be fully evaluated to **Normal Form** — no constructors left
unevaluated, no thunks. The `rnf` function drives this evaluation.

```haskell
import Data.DerivingVia.DeepSeq
```

#### How it works

```haskell
-- DerivingVia strategy: derive NFData generically
deriving via NFDataVia SomeExternalType
  instance NFData SomeExternalType
```

#### Usage

```haskell
import Control.DeepSeq (NFData, force, rnf)
import Data.DerivingVia.DeepSeq ()  -- bring instances into scope

-- Fully evaluate a value (useful in benchmarks to avoid lazy measurement)
fullyEvaluate :: NFData a => a -> IO a
fullyEvaluate = evaluate . force

-- Use in benchmarks to ensure no lazy work bleeds into the timed section:
benchmarkBlock :: Block -> Benchmark
benchmarkBlock block =
  bench "apply block" $
    nf (applyBlock block) initialLedgerState
    -- 'nf' calls rnf on the result, requiring NFData
```

## Why These Are Orphans

Consider: `SomeExternalType` is defined in package A. `NoThunks` is defined
in package B. This package (`orphans-deriving-via`) is package C.

- Package A cannot define the `NoThunks` instance — it doesn't depend on B.
- Package B cannot define it — it doesn't know about A.
- Package C must define it as an orphan.

This is the standard Haskell solution for cross-package instance requirements.
The `DerivingVia` approach keeps the instances minimal and auditable — each
one is a one-liner that delegates to a well-understood strategy.

## Notes

- GHC will warn about orphan instances (`-Worphans`). This is expected and
  intentional for this package; the warning can be suppressed with
  `{-# OPTIONS_GHC -Wno-orphans #-}` at the import site if needed.
- Only import these modules at the **top** of a dependency chain
  (executables, test suites) to avoid duplicate instance compilation errors.
