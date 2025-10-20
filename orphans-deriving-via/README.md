# orphans-deriving-via

## Overview

The `orphans-deriving-via` package provides orphan instances that extend the `base-deriving-via` hooks to work with additional type classes, specifically `NFData` from `deepseq` and `NoThunks` from `nothunks`. These orphan instances enable generic derivation of these important type classes using the `DerivingVia` extension.

This package solves the issue of needing these instances while keeping them separate from `base-deriving-via` to avoid unnecessary dependencies.

## Core Functionality

### NFData Instance

Provides automatic derivation of `NFData` (deep evaluation) instances via `Generic`:

```haskell 
instance (Generic a, GNFData (Rep a)) => NFData (InstantiatedAt Generic a)
```

### NoThunks Instance  

Provides automatic derivation of `NoThunks` (thunk detection) instances via `Generic`:

```haskell 
instance (Generic a, GShowTypeOf (Rep a), GWNoThunks '[] (Rep a)) => 
  NoThunks (InstantiatedAt Generic a)
```

## Usage Examples

### Basic NFData Derivation

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Control.DeepSeq
import Data.DerivingVia
import Data.DerivingVia.DeepSeq  -- Import the orphan instances
import GHC.Generics

-- Automatically derive NFData for deep evaluation
data MyData = MyData
  { field1 :: String
  , field2 :: [Int] 
  , field3 :: Maybe (String, Int)
  } deriving (Generic, Show)
    deriving NFData via InstantiatedAt Generic MyData

-- Usage
example = MyData "hello" [1,2,3] (Just ("world", 42))
deeplyEvaluated = example `deepseq` "Data is fully evaluated"
```

### NoThunks Derivation for Memory Safety

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Data.DerivingVia
import Data.DerivingVia.NoThunks  -- Import the orphan instances
import GHC.Generics
import NoThunks.Class

-- Derive NoThunks to detect unevaluated thunks
data BlockData = BlockData
  { blockNumber :: Int
  , blockTransactions :: [Transaction]
  , blockMetadata :: Map String Int
  } deriving (Generic, Show)
    deriving NoThunks via InstantiatedAt Generic BlockData

data Transaction = Transaction
  { txId :: String
  , txAmount :: Int
  } deriving (Generic, Show)
    deriving NoThunks via InstantiatedAt Generic Transaction

-- Usage - check for thunks in blockchain data
checkBlockData :: BlockData -> IO ()
checkBlockData block = do
  result <- noThunks [] block
  case result of
    Nothing -> putStrLn "✓ Block data contains no thunks"
    Just context -> putStrLn $ "⚠️  Found thunk at: " ++ show context
```

### Combined NFData and NoThunks

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Control.DeepSeq
import Data.DerivingVia
import Data.DerivingVia.DeepSeq
import Data.DerivingVia.NoThunks
import GHC.Generics
import NoThunks.Class

-- Derive both NFData and NoThunks for comprehensive memory management
data CardanoState = CardanoState
  { ledger :: Map AccountId Balance
  , mempool :: [Transaction]
  , epochInfo :: EpochInfo
  } deriving (Generic, Show)
    deriving (NFData, NoThunks) via InstantiatedAt Generic CardanoState

-- Usage in Cardano node context
processState :: CardanoState -> IO CardanoState
processState state = do
  -- Check for thunks before processing
  thunkCheck <- noThunks [] state
  case thunkCheck of
    Just ctx -> error $ "State contains thunks: " ++ show ctx
    Nothing -> do
      putStrLn "✓ State is clean"
      -- Force deep evaluation before returning
      return $! state `deepseq` processedState
  where
    processedState = updateState state
```

### Working with Recursive Data Structures

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Control.DeepSeq
import Data.DerivingVia
import Data.DerivingVia.DeepSeq
import Data.DerivingVia.NoThunks
import GHC.Generics
import NoThunks.Class

-- Tree structure with automatic instances
data Tree a = Leaf a | Node (Tree a) a (Tree a)
  deriving (Generic, Show, Eq)
  deriving (NFData, NoThunks) via InstantiatedAt Generic (Tree a)

-- Usage
binaryTree :: Tree Int
binaryTree = Node 
  (Node (Leaf 1) 2 (Leaf 3))
  4
  (Node (Leaf 5) 6 (Leaf 7))

-- Verify no thunks and deep evaluation
verifyTree :: Tree Int -> IO ()
verifyTree tree = do
  -- Check for thunks
  result <- noThunks [] tree
  case result of
    Nothing -> putStrLn "✓ Tree contains no thunks"
    Just ctx -> putStrLn $ "⚠️  Tree has thunk: " ++ show ctx
  
  -- Force full evaluation
  let !evaluated = tree `deepseq` tree
  putStrLn "✓ Tree fully evaluated"
```

### Cardano-Specific Examples

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Control.DeepSeq
import Data.DerivingVia
import Data.DerivingVia.DeepSeq
import Data.DerivingVia.NoThunks
import GHC.Generics
import NoThunks.Class

-- UTXO entry with automatic memory management
data UTxO = UTxO
  { utxoInputs :: Set TxIn
  , utxoOutputs :: Map TxOut Value
  , utxoMetadata :: Map TxId Metadata
  } deriving (Generic, Show)
    deriving (NFData, NoThunks) via InstantiatedAt Generic UTxO

-- Stake pool registration
data PoolRegistration = PoolRegistration
  { poolId :: PoolId
  , poolVrfKey :: VrfKey
  , poolRewardAccount :: StakeAddress
  , poolOwners :: Set StakeKeyHash
  , poolMargin :: Rational
  , poolCost :: Coin
  } deriving (Generic, Show)
    deriving (NFData, NoThunks) via InstantiatedAt Generic PoolRegistration

-- Memory-safe processing
processUTxO :: UTxO -> IO UTxO
processUTxO utxo = do
  -- Verify no thunks before expensive operations
  noThunksResult <- noThunks ["processUTxO"] utxo
  case noThunksResult of
    Just thunkContext -> 
      error $ "UTxO contains thunks: " ++ show thunkContext
    Nothing -> do
      -- Process and ensure full evaluation
      let processed = updateUTxO utxo
      return $! processed `deepseq` processed

updateUTxO :: UTxO -> UTxO
updateUTxO = id  -- Placeholder for actual processing
```

## Advanced Usage

### Custom Type Hierarchies

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Control.DeepSeq
import Data.DerivingVia
import Data.DerivingVia.DeepSeq
import Data.DerivingVia.NoThunks
import GHC.Generics
import NoThunks.Class

-- Base types
newtype Hash = Hash ByteString
  deriving (Generic, Show, Eq, Ord)
  deriving (NFData, NoThunks) via InstantiatedAt Generic Hash

newtype Signature = Signature ByteString  
  deriving (Generic, Show, Eq)
  deriving (NFData, NoThunks) via InstantiatedAt Generic Signature

-- Complex composed types automatically get instances
data SignedData a = SignedData
  { signedDataPayload :: a
  , signedDataSignature :: Signature
  , signedDataHash :: Hash
  } deriving (Generic, Show)
    deriving (NFData, NoThunks) via InstantiatedAt Generic (SignedData a)

-- Works with any payload type that has NFData/NoThunks
type SignedTransaction = SignedData Transaction
type SignedBlock = SignedData Block
```

### Performance-Critical Paths

```haskell 
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}

import Control.DeepSeq
import Data.DerivingVia
import Data.DerivingVia.DeepSeq
import Data.DerivingVia.NoThunks
import GHC.Generics
import NoThunks.Class

-- High-frequency data with automatic optimization
data BlockHeader = BlockHeader
  { headerPrevHash :: Hash
  , headerMerkleRoot :: Hash  
  , headerTimestamp :: UTCTime
  , headerNonce :: Word64
  } deriving (Generic, Show, Eq)
    deriving (NFData, NoThunks) via InstantiatedAt Generic BlockHeader

-- Batch processing with memory guarantees
processBatch :: [BlockHeader] -> IO [BlockHeader]
processBatch headers = do
  -- Verify entire batch is thunk-free
  mapM_ checkHeader headers
  -- Process with guaranteed evaluation
  return $ map (force . processHeader) headers
  where
    checkHeader h = do
      result <- noThunks [] h
      case result of
        Just ctx -> error $ "Header has thunk: " ++ show ctx
        Nothing -> return ()
    
    processHeader = id  -- Placeholder for processing logic
    force = (`deepseq` h) where h = undefined
```

## Implementation Details

### GNFData Class

The package implements its own generic NFData class:

```haskell 
class GNFData rep where
  grnf :: rep x -> ()
```

This provides instances for:
- `K1` (constants): Uses the underlying type's `rnf`
- `M1` (metadata): Recursively applies `grnf`
- `V1` (empty): Pattern match on empty case
- `U1` (unit): Returns unit immediately
- `:*:` (products): Evaluates both sides sequentially
- `:+:` (sums): Pattern matches and evaluates the appropriate side

### Integration with NoThunks

The `NoThunks` instance reuses the existing generic machinery from the `nothunks` library, providing compatibility with the `InstantiatedAt` wrapper.

## Performance Considerations

### NFData Performance
- **Sequential Evaluation**: Product types are evaluated left-to-right
- **Deep Traversal**: All nested structures are fully evaluated
- **Sum Type Efficiency**: Only the active constructor is evaluated
- **Lazy Recursion**: Recursive structures are handled properly

### NoThunks Performance  
- **Compile-Time Optimizations**: Type information used for efficient checks
- **Context Tracking**: Provides detailed information about thunk locations
- **Early Termination**: Stops at first thunk found

### Memory Implications
- **Heap Pressure**: `deepseq` can increase temporary memory usage
- **Thunk Prevention**: `NoThunks` helps prevent memory leaks
- **GC Benefits**: Fully evaluated structures are more GC-friendly

## Best Practices

### When to Use NFData
1. **Before Expensive Operations**: Ensure all inputs are evaluated
2. **Inter-Thread Communication**: Avoid passing thunks between threads  
3. **Serialization Boundaries**: Evaluate before serialization
4. **Memory Management**: Force evaluation to reduce heap size

### When to Use NoThunks
1. **Long-Lived Data**: State that persists across operations
2. **Performance-Critical Paths**: Where thunks would cause issues
3. **Memory Safety**: Prevent unexpected memory growth
4. **Debugging**: Detect evaluation issues during development

### Cardano-Specific Guidelines
1. **Blockchain State**: Always use both `NFData` and `NoThunks`
2. **Transaction Processing**: Verify inputs before processing
3. **Consensus Data**: Ensure all consensus-critical data is evaluated
4. **Network Messages**: Evaluate before sending/after receiving

## Integration with Cardano Ecosystem

This package is essential for:

- **Node Memory Management**: Preventing thunk accumulation in long-running nodes
- **Consensus Safety**: Ensuring all consensus data is properly evaluated
- **Performance Optimization**: Avoiding evaluation costs in critical paths
- **Memory Leak Prevention**: Detecting and preventing common memory issues
- **Testing and Debugging**: Verifying memory properties in tests

## See Also

- **base-deriving-via** - The foundational package for generic deriving
- **deepseq** - Deep evaluation and strictness control
- **nothunks** - Thunk detection for memory safety
- **NoThunks.Class** - The core NoThunks functionality
- **Control.DeepSeq** - Deep evaluation utilities