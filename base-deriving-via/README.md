# base-deriving-via

Newtype helpers for deriving `Semigroup` and `Monoid` instances via GHC
Generics and `DerivingVia`.

[![Hackage](https://img.shields.io/hackage/v/base-deriving-via)](https://hackage.haskell.org/package/base-deriving-via)

## Overview

Haskell's `DerivingVia` extension (GHC 8.6+) lets you say: *"derive this
typeclass instance the same way this other type would."* `base-deriving-via`
provides the helper newtypes needed to derive `Semigroup` and `Monoid`
instances for any product type using `GHC.Generics` — eliminating boilerplate
without sacrificing safety.

## Installation

```cabal
{-# LANGUAGE DerivingVia #-}

build-depends: base-deriving-via >= 0.1
```

## Modules

### `Data.DerivingVia`

Re-exports all helpers. Import this as your one-stop shop:

```haskell
import Data.DerivingVia
```

### `Data.DerivingVia.GHC.Generics.Semigroup`

Provides `GenericSemigroup`, a newtype wrapper that derives `Semigroup` for
any type with a `Generic` instance by combining each field with `(<>)`.

```haskell
newtype GenericSemigroup a = GenericSemigroup a
-- Semigroup instance combines fields left-to-right
```

### `Data.DerivingVia.GHC.Generics.Monoid`

Provides `GenericMonoid`, which extends `GenericSemigroup` to also derive
`Monoid` by taking `mempty` of each field.

```haskell
newtype GenericMonoid a = GenericMonoid a
-- Monoid instance: mempty = constructor with mempty in every field
```

## Usage Examples

### Without `base-deriving-via` (verbose)

```haskell
data Config = Config
  { timeout :: Sum Int
  , retries :: Sum Int
  , labels  :: [Text]
  }

-- Must write this by hand:
instance Semigroup Config where
  Config t1 r1 l1 <> Config t2 r2 l2 =
    Config (t1 <> t2) (r1 <> r2) (l1 <> l2)

instance Monoid Config where
  mempty = Config mempty mempty mempty
```

### With `base-deriving-via` (concise)

```haskell
{-# LANGUAGE DerivingVia  #-}
{-# LANGUAGE DeriveGeneric #-}

import GHC.Generics    (Generic)
import Data.DerivingVia

data Config = Config
  { timeout :: Sum Int
  , retries :: Sum Int
  , labels  :: [Text]
  } deriving (Generic)
    deriving (Semigroup, Monoid) via GenericMonoid Config

-- Done! Instances are derived automatically.
-- mempty = Config (Sum 0) (Sum 0) []
-- Config a1 b1 c1 <> Config a2 b2 c2
--   = Config (a1+a2) (b1+b2) (c1++c2)
```

### Real-world example: accumulating statistics

```haskell
{-# LANGUAGE DerivingVia  #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia
import GHC.Generics (Generic)
import Data.Monoid  (Sum (..))

data ChainStats = ChainStats
  { blocksProcessed :: Sum Int
  , txsProcessed    :: Sum Int
  , bytesProcessed  :: Sum Word64
  } deriving (Show, Generic)
    deriving (Semigroup, Monoid) via GenericMonoid ChainStats

-- Accumulate stats from multiple segments:
totalStats :: [ChainStats] -> ChainStats
totalStats = mconcat

-- Example:
-- mconcat
--   [ ChainStats 100 1000 5_000_000
--   , ChainStats 200 2000 9_000_000
--   ]
-- = ChainStats 300 3000 14_000_000
```

### Using `GenericSemigroup` alone

If your type has no sensible `mempty`, derive only `Semigroup`:

```haskell
data NonEmpty a = NonEmpty a [a]
  deriving Generic
  deriving Semigroup via GenericSemigroup (NonEmpty a)
-- No Monoid — there is no empty NonEmpty
```

## Requirements

- GHC 8.6 or later (for `DerivingVia` and `DeriveGeneric`)
- All fields of the derived type must themselves have `Semigroup` / `Monoid`
  instances
- The type must have a `Generic` instance (use `deriving Generic` or
  `DeriveGeneric`)
