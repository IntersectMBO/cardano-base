# cardano-strict-containers

## Overview

`cardano-strict-containers` provides strict variants of common Haskell container types, ensuring that values stored in these containers are evaluated to Weak Head Normal Form (WHNF). This eliminates memory leaks from accumulated thunks and provides predictable memory usage patterns, which is crucial for long-running blockchain applications.

## Why Strict Containers?

### The Problem with Lazy Containers
Haskell's default containers are lazy, meaning they can store unevaluated expressions (thunks) instead of actual values. In long-running applications like blockchain nodes, these thunks can accumulate and cause:

- **Memory leaks** - Thunks pile up in memory without being garbage collected
- **Unpredictable performance** - Sudden evaluation bursts when thunks are finally forced
- **Stack overflows** - Deep chains of thunks can exhaust stack space
- **Space leaks** - References to large structures kept alive by small thunks

### The Solution: Strict Evaluation
Strict containers automatically evaluate values to WHNF when they're inserted, ensuring:

- **Predictable memory usage** - Values are evaluated immediately
- **Better garbage collection** - No thunk accumulation
- **Consistent performance** - No deferred computation surprises
- **Memory efficiency** - Reduced memory overhead from thunk metadata

## Core Types

### StrictMaybe
A strict variant of `Maybe` that forces its contained value to WHNF.

```haskell
import Data.Maybe.Strict

-- Basic usage
let value = SJust (expensive computation)  -- Computation happens immediately
let empty = SNothing

-- Pattern matching
processValue :: StrictMaybe Int -> String
processValue SNothing = "No value"
processValue (SJust n) = "Value: " ++ show n

-- Conversion to/from regular Maybe
regularMaybe :: Maybe String = Just "hello"
strictVersion :: StrictMaybe String = maybeToStrictMaybe regularMaybe
backToRegular :: Maybe String = strictMaybeToMaybe strictVersion
```

### StrictSeq
A strict sequence that forces all elements to WHNF, based on `Data.Sequence`.

```haskell
import Data.Sequence.Strict

-- Construction
emptySeq = empty
singleSeq = singleton 42
leftCons = 1 <| (2 <| (3 <| empty))     -- [1,2,3]
rightSnoc = empty |> 1 |> 2 |> 3        -- [1,2,3]
fromListSeq = fromList [1,2,3,4,5]

-- Pattern matching with ViewPatterns
processSeq :: StrictSeq Int -> String
processSeq Empty = "Empty sequence"
processSeq (x :<| xs) = "Head: " ++ show x ++ ", rest has " ++ show (length xs) ++ " elements"
processSeq (xs :|> x) = "Last: " ++ show x ++ ", prefix has " ++ show (length xs) ++ " elements"

-- Operations
seq1 = fromList [1,2,3]
seq2 = fromList [4,5,6]
combined = seq1 >< seq2                 -- [1,2,3,4,5,6]
doubled = fmap (*2) seq1                -- [2,4,6]
filtered = filter (> 2) combined       -- [3,4,5,6]
```

### StrictUnit and forceElemsToWHNF
Utilities for enforcing strictness in custom data structures.

```haskell
import Data.Unit.Strict

-- Force all elements in a container to WHNF
strictList :: [Int]
strictList = forceElemsToWHNF [expensive1, expensive2, expensive3]
-- All computations happen immediately

-- Custom strict container
makeStrictList :: [a] -> [a]
makeStrictList xs = forceElemsToWHNF xs
```

## Common Usage Patterns

### Replacing Maybe in Strict Contexts

```haskell
-- Instead of:
data Config = Config
  { configPort :: Maybe Int
  , configHost :: Maybe String
  }

-- Use:
import Data.Maybe.Strict

data StrictConfig = StrictConfig
  { configPort :: StrictMaybe Int
  , configHost :: StrictMaybe String
  }

-- Processing is more predictable
processConfig :: StrictConfig -> IO ()
processConfig cfg = do
  port <- pure $ fromSMaybe 8080 (configPort cfg)  -- No thunk evaluation surprise
  host <- pure $ fromSMaybe "localhost" (configHost cfg)
  putStrLn $ "Starting server on " ++ host ++ ":" ++ show port
```

### Building Strict Sequences Efficiently

```haskell
import Data.Sequence.Strict

-- Efficient left-to-right building
buildSequence :: [a] -> StrictSeq a
buildSequence = foldl (|>) empty

-- Efficient right-to-left building
buildSequenceR :: [a] -> StrictSeq a
buildSequenceR = foldr (<|) empty

-- Batch operations
processItems :: [ExpensiveItem] -> StrictSeq ProcessedItem
processItems items =
  fromList (map processExpensive items)  -- All processing happens at fromList
```

### Performance-Critical Accumulation

```haskell
-- Instead of lazy accumulation that can build up thunks:
sumLazy :: [Int] -> Int
sumLazy = foldl (+) 0  -- Can build thunk chains

-- Use strict containers for intermediate results:
sumStrict :: [Int] -> Int
sumStrict xs =
  let strictSeq = fromList xs  -- Forces evaluation
      result = foldl (+) 0 strictSeq
  in result
```

## Advanced Usage

### Custom Strict Data Types

```haskell
import Data.Unit.Strict

data StrictPair a b = StrictPair !a !b

makeStrictPair :: a -> b -> StrictPair a b
makeStrictPair x y =
  let forced = forceElemsToWHNF [x, y]  -- Forces both to WHNF
  in forced `seq` StrictPair x y

-- Even more control:
data StrictTree a = Leaf !a | Branch !(StrictTree a) !(StrictTree a)

forceStrictTree :: StrictTree a -> StrictTree a
forceStrictTree tree = forceElemsToWHNF [tree] `seq` tree
```

### Integration with Serialization

```haskell
import Data.Maybe.Strict
import Cardano.Binary

-- StrictMaybe has built-in CBOR support
data NetworkMessage = NetworkMessage
  { msgId :: Int
  , msgPayload :: StrictMaybe ByteString  -- Guarantees no thunks in serialization
  }
  deriving (Generic)

instance ToCBOR NetworkMessage
instance FromCBOR NetworkMessage

-- Deserialization automatically forces strictness
processMessage :: ByteString -> Either String NetworkMessage
processMessage bytes =
  case decodeFull bytes of
    Right msg -> Right msg  -- msg.msgPayload is strict
    Left err -> Left (show err)
```

### Working with JSON APIs

```haskell
import Data.Maybe.Strict
import Data.Aeson

data ApiResponse = ApiResponse
  { responseId :: Int
  , responseData :: StrictMaybe Value
  , responseError :: StrictMaybe Text
  } deriving (Generic, ToJSON, FromJSON)

-- JSON parsing automatically creates strict values
parseApiResponse :: ByteString -> Maybe ApiResponse
parseApiResponse = decode  -- StrictMaybe fields are forced during parsing
```

## Performance Considerations

### When to Use Strict Containers

✅ **Good for:**
- Long-running applications (blockchain nodes, servers)
- Accumulating data structures over time
- Known finite data sizes
- When memory usage predictability is important
- Preventing space leaks

⚠️ **Consider carefully for:**
- Very large data structures (strict evaluation uses more immediate memory)
- Deeply recursive computations (may cause stack overflow)
- Streaming/infinite data (defeats the purpose)
- When you need lazy evaluation for algorithmic reasons

### Memory Usage Patterns

```haskell
-- Lazy: Memory usage grows unpredictably
lazyAccumulate :: [Int] -> Maybe Int
lazyAccumulate [] = Nothing
lazyAccumulate (x:xs) = Just (x + fromMaybe 0 (lazyAccumulate xs))  -- Thunk buildup

-- Strict: Predictable memory usage
strictAccumulate :: [Int] -> StrictMaybe Int
strictAccumulate [] = SNothing
strictAccumulate xs = SJust $ foldl' (+) 0 xs  -- Evaluated immediately
```

## Integration with Other Packages

### cardano-binary
All strict container types support CBOR serialization for blockchain persistence.

```haskell
import Cardano.Binary

-- Automatic CBOR support
strictData :: StrictSeq Transaction
strictData = fromList transactions

encoded :: ByteString
encoded = serialize strictData  -- All transactions are already forced

decoded :: Either DecoderError (StrictSeq Transaction)
decoded = decodeFull encoded    -- Deserialization forces strictness
```

### NoThunks Integration
Strict containers integrate with the `NoThunks` framework for thunk detection.

```haskell
import NoThunks.Class

-- StrictMaybe and StrictSeq automatically check for thunks
checkForThunks :: StrictSeq SomeData -> IO ()
checkForThunks strictSeq = do
  result <- noThunks [] strictSeq
  case result of
    Nothing -> putStrLn "No thunks found!"
    Just info -> putStrLn $ "Thunks detected: " ++ show info
```

## Migration Guide

### From Maybe to StrictMaybe

```haskell
-- Before
data OldType = OldType
  { field1 :: Maybe String
  , field2 :: Maybe Int
  }

processOld :: OldType -> String
processOld obj = fromMaybe "default" (field1 obj)

-- After
import Data.Maybe.Strict

data NewType = NewType
  { field1 :: StrictMaybe String
  , field2 :: StrictMaybe Int
  }

processNew :: NewType -> String
processNew obj = fromSMaybe "default" (field1 obj)

-- Migration utility
migrateType :: OldType -> NewType
migrateType old = NewType
  { field1 = maybeToStrictMaybe (field1 old)
  , field2 = maybeToStrictMaybe (field2 old)
  }
```

### From [a] to StrictSeq a

```haskell
-- Before
processItems :: [Item] -> [ProcessedItem]
processItems = map processItem

-- After
import Data.Sequence.Strict

processItems :: StrictSeq Item -> StrictSeq ProcessedItem
processItems = fmap processItem  -- More efficient, guaranteed strict

-- Migration
migrateList :: [a] -> StrictSeq a
migrateList = fromList  -- Forces all elements
```

## Testing Strictness

```haskell
import Control.Exception (evaluate)
import Control.DeepSeq (deepseq)

-- Test that values are actually strict
testStrictness :: IO ()
testStrictness = do
  let lazyValue = error "This will explode!"
  let strictMaybe = SJust lazyValue  -- Should explode immediately

  -- This should not reach the print statement
  print "If you see this, strictness failed!"

-- Verify no thunks accumulate
testNoThunkAccumulation :: IO ()
testNoThunkAccumulation = do
  let bigList = [1..1000000]
  let strictSeq = fromList bigList  -- Should evaluate immediately

  -- Memory usage should be predictable here
  print $ length strictSeq
```

## See Also

- [`cardano-binary`](../cardano-binary/README.md) - CBOR serialization support
- [NoThunks](https://hackage.haskell.org/package/nothunks) - Thunk detection framework
- [Data.Sequence](https://hackage.haskell.org/package/containers/docs/Data-Sequence.html) - Underlying sequence implementation
- [Haskell Performance](https://wiki.haskell.org/Performance) - General performance guidance