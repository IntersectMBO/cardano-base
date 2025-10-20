# base-deriving-via

## Overview

The `base-deriving-via` package provides general newtype wrappers for use with GHC's `DerivingVia` extension. It offers a flexible hook mechanism for deriving type class instances through constraints, particularly focusing on generic derivation of `Semigroup` and `Monoid` instances.

This package fills gaps that "should have been" defined in `base` and other foundational packages, providing these utilities while we wait for upstream definitions.

## Core Functionality

### InstantiatedAt

The primary export is `InstantiatedAt`, a newtype wrapper that enables constraint-based `deriving via`:

```haskell path=null start=null
newtype InstantiatedAt (c :: Type -> Constraint) a = InstantiatedAt a
```

This allows you to derive instances via type class constraints, with `Generic` being the most common example.

## Usage Examples

### Basic Generic Deriving

```haskell path=null start=null
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia
import GHC.Generics

-- Define your data type with Generic
data Point = Point Int Int
  deriving (Generic, Show)
  deriving (Semigroup, Monoid)
    via InstantiatedAt Generic Point

-- Usage
p1 = Point 1 2
p2 = Point 3 4
result = p1 <> p2  -- Point 4 6 (field-wise combination)
empty = mempty     -- Point 0 0 (field-wise mempty)
```

### Product Type Examples

```haskell path=null start=null
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia
import GHC.Generics

-- Configuration with multiple fields
data Config = Config
  { configName :: String
  , configValue :: Sum Int  -- Using Sum for addition
  , configFlags :: [Bool]
  } deriving (Generic, Show)
    deriving (Semigroup, Monoid)
      via InstantiatedAt Generic Config

-- Usage
config1 = Config "app" (Sum 10) [True, False]
config2 = Config "tool" (Sum 20) [False, True]  
merged = config1 <> config2  
-- Result: Config "apptool" (Sum 30) [True, False, False, True]
```

### Record Type Combinations

```haskell path=null start=null
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia
import GHC.Generics
import Data.Monoid (First(..), Last(..))

-- User preferences with optional fields
data UserPrefs = UserPrefs
  { prefTheme :: First String      -- Keep first non-Nothing
  , prefLanguage :: Last String    -- Keep last non-Nothing  
  , prefHistory :: [String]        -- Concatenate lists
  } deriving (Generic, Show)
    deriving (Semigroup, Monoid)
      via InstantiatedAt Generic UserPrefs

-- Usage
defaultPrefs = UserPrefs (First Nothing) (Last Nothing) []
userPrefs = UserPrefs (First $ Just "dark") (Last $ Just "en") ["file1"]
sessionPrefs = UserPrefs (First Nothing) (Last $ Just "fr") ["file2"]

-- Combine preferences (first theme wins, last language wins, concat history)
finalPrefs = defaultPrefs <> userPrefs <> sessionPrefs
-- Result: UserPrefs (First (Just "dark")) (Last (Just "fr")) ["file1","file2"]
```

### Nested Product Types

```haskell path=null start=null
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia
import GHC.Generics

-- Nested structures work automatically
data Inner = Inner (Sum Int) String
  deriving (Generic, Show)
  deriving (Semigroup, Monoid)
    via InstantiatedAt Generic Inner

data Outer = Outer Inner [Bool] (Product Int)
  deriving (Generic, Show)  
  deriving (Semigroup, Monoid)
    via InstantiatedAt Generic Outer

-- Usage
inner1 = Inner (Sum 5) "hello"
inner2 = Inner (Sum 3) " world"
combined = inner1 <> inner2  -- Inner (Sum 8) "hello world"

outer1 = Outer inner1 [True] (Product 2)
outer2 = Outer inner2 [False] (Product 3)
finalOuter = outer1 <> outer2
-- Result: Outer (Inner (Sum 8) "hello world") [True,False] (Product 6)
```

## Advanced Usage

### Custom Constraint-Based Deriving

```haskell path=null start=null
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}

import Data.DerivingVia

-- You can use InstantiatedAt with other constraints besides Generic
-- (though you'd need to provide the instances)

-- Hypothetical usage with Ord constraint
data Sorted a = Sorted [a]
  deriving (Eq, Ord)
  -- deriving SomeCustomClass via InstantiatedAt Ord (Sorted a)
```

### Working with Cardano Types

```haskell path=null start=null
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia  
import GHC.Generics

-- Blockchain-related example
data BlockHeader = BlockHeader
  { blockNumber :: Sum Word64      -- Additive block numbers
  , blockHash :: First ByteString  -- Keep first hash seen
  , timestamp :: Max UTCTime       -- Keep latest timestamp
  } deriving (Generic, Show)
    deriving (Semigroup, Monoid)
      via InstantiatedAt Generic BlockHeader

-- Combine headers (useful for merging partial information)
header1 = BlockHeader (Sum 100) (First $ Just "hash1") (Max someTime1)
header2 = BlockHeader (Sum 0) (First Nothing) (Max someTime2) 
merged = header1 <> header2  -- Gets hash from header1, latest time
```

## Implementation Details

### Generic Semigroup

The package provides `GSemigroup` for generic semigroup operations:

```haskell path=null start=null
class GSemigroup rep where
  gsappend :: rep x -> rep x -> rep x
```

This works by:
- Combining fields using their respective `<>` operations for product types
- Providing appropriate instances for `K1` (constants), `M1` (metadata), `U1` (unit), and `:*:` (products)
- Explicitly preventing sum types (`:+:`) with helpful type errors

### Generic Monoid

The package provides `GMonoid` for generic monoid operations:

```haskell path=null start=null
class GMonoid rep where
  gmempty :: rep x
```

This provides `mempty` for each field in product types, but prevents usage with sum types.

### Type Safety

The implementation includes helpful compile-time errors for unsupported patterns:

```haskell path=null start=null
-- This would produce a clear type error:
data BadType = A Int | B String
  deriving Generic
  -- deriving (Semigroup, Monoid) via InstantiatedAt Generic BadType
  -- Error: No Generics definition of Semigroup for types with multiple constructors
```

## Constraints and Limitations

### Supported Types
- ✅ Product types (records with multiple fields)
- ✅ Single constructor types
- ✅ Nested product types
- ✅ Unit types

### Not Supported
- ❌ Sum types (multiple constructors)
- ❌ Recursive types without proper termination
- ❌ Types with existential quantification

### Requirements
- All fields must have `Semigroup` instances for `Semigroup` derivation
- All fields must have `Monoid` instances for `Monoid` derivation
- The type must have a `Generic` instance

## Performance Considerations

- **Zero Runtime Overhead**: The newtype wrapper has no runtime cost
- **Compile-Time Safety**: Type errors caught at compile time
- **Generic Efficiency**: Uses GHC's efficient generic representation
- **Field-by-Field Operations**: Each field is combined independently

## Integration with Cardano Ecosystem

This package is particularly useful in Cardano development for:

- **Configuration Merging**: Combining partial configurations
- **State Accumulation**: Merging blockchain state updates  
- **Preference Handling**: Combining user and default settings
- **Data Aggregation**: Combining metrics and statistics
- **Event Processing**: Merging event data from multiple sources

## Best Practices

1. **Choose Appropriate Wrappers**: Use `Sum`, `Product`, `First`, `Last`, etc., for fields
2. **Document Semantics**: Make it clear how fields combine in your domain
3. **Test Thoroughly**: Verify that generic derivation matches expected semantics
4. **Prefer Explicit**: When generic derivation is unclear, implement instances manually
5. **Mind Performance**: For hot paths, consider manual implementations

## See Also

- **DerivingVia** - GHC extension for flexible instance derivation
- **GHC.Generics** - Generic programming in Haskell
- **Data.Monoid** - Monoid wrappers like `Sum`, `Product`, `First`, `Last`
- **orphans-deriving-via** - Additional deriving via utilities for orphan instances