# cardano-slotting

## Overview

The `cardano-slotting` package provides essential types and functions for working with Cardano's time and slot management system. It handles the mapping between real-world time and Cardano's discrete slot-based timeline, including epochs, slot numbers, and time calculations.

## Core Concepts

### Slots and Time
- **SlotNo**: A 0-based index for Ouroboros time slots
- **SystemStart**: The UTC time when the blockchain began
- **RelativeTime**: Time relative to the system start (picosecond precision)
- **SlotLength**: Duration of a single slot (millisecond precision)

### Epochs
- **EpochNo**: The number/identifier of an epoch
- **EpochSize**: Number of slots in an epoch
- **EpochInterval**: A span of epochs

### WithOrigin Type
The `WithOrigin` type handles values that may or may not have been set, distinguishing between "never happened" (`Origin`) and "happened at time/slot X" (`At X`).

## Key Types and Usage

### Basic Slot Operations

```haskell
import Cardano.Slotting.Slot

-- Create slot numbers
slot1 = SlotNo 42
slot2 = SlotNo 100

-- Slots are ordered and enumerable
nextSlot = succ slot1  -- SlotNo 43
isEarlier = slot1 < slot2  -- True

-- Work with epochs
epoch = EpochNo 5
epochSize = EpochSize 432000  -- slots per epoch
interval = EpochInterval 2    -- 2 epochs

-- Add interval to epoch
futureEpoch = addEpochInterval epoch interval  -- EpochNo 7
```

### Time Calculations

```haskell
import Cardano.Slotting.Time
import Data.Time

-- System start time
systemStart = SystemStart $ read "2017-09-23 21:44:51 UTC"

-- Slot length (1 second slots)
slotLen = slotLengthFromSec 1

-- Convert between time representations
now <- getCurrentTime
relTime = toRelativeTime systemStart now
utcTime = fromRelativeTime systemStart relTime

-- Work with slot lengths
slotMs = slotLengthFromMillisec 1000  -- 1 second
slotSecs = slotLengthToSec slotMs     -- 1
```

### WithOrigin Pattern

```haskell
import Cardano.Slotting.Slot

-- Handle optional slots
maybeSlot :: WithOrigin SlotNo
maybeSlot = At (SlotNo 42)  -- or Origin

-- Extract values safely
currentSlot = fromWithOrigin (SlotNo 0) maybeSlot  -- SlotNo 42

-- Convert to/from Maybe
mbSlot = withOriginToMaybe maybeSlot        -- Just (SlotNo 42)
backToWithOrigin = withOriginFromMaybe mbSlot  -- At (SlotNo 42)

-- Pattern matching
processSlot :: WithOrigin SlotNo -> String
processSlot Origin = "No slot yet"
processSlot (At slot) = "Current slot: " ++ show slot
```

### EpochInfo for Complex Calculations

```haskell
import Cardano.Slotting.EpochInfo

-- EpochInfo provides epoch-aware time calculations
-- (Usually provided by the consensus layer)
epochInfo :: EpochInfo IO
epochInfo = -- ... implementation depends on era and parameters

-- Calculate which epoch contains a slot
epoch <- epochInfoEpoch epochInfo (SlotNo 1000000)

-- Get the size of a specific epoch
size <- epochInfoSize epochInfo (EpochNo 5)

-- Find the first slot of an epoch
firstSlot <- epochInfoFirst epochInfo (EpochNo 10)

-- Get the time range of an epoch
(startSlot, endSlot) <- epochInfoRange epochInfo (EpochNo 10)

-- Convert slot to absolute time
utcTime <- epochInfoSlotToUTCTime epochInfo systemStart (SlotNo 42)

-- Get slot length (may vary by era)
length <- epochInfoSlotLength epochInfo (SlotNo 42)
```

## Common Patterns

### Working with Genesis Blocks
```haskell
-- Genesis blocks exist at "Origin" - before the first slot
genesisBlock :: WithOrigin SlotNo
genesisBlock = Origin

isGenesis :: WithOrigin SlotNo -> Bool
isGenesis Origin = True
isGenesis (At _) = False
```

### Slot Arithmetic
```haskell
-- Slots support standard numeric operations
slot = SlotNo 100
nextSlot = slot + 1      -- SlotNo 101
slotDiff = slot - SlotNo 50  -- SlotNo 50

-- Work with epoch boundaries
epochStart = EpochNo 5
epochEnd = addEpochInterval epochStart (EpochInterval 1)
```

### Time Conversions
```haskell
-- Convert between different time representations
millisecondSlot = slotLengthFromMillisec 2000  -- 2 second slots
secondSlot = slotLengthFromSec 2              -- same as above

-- Relative time arithmetic
relTime1 = RelativeTime 1000  -- 1000 seconds from system start
relTime2 = addRelativeTime 500 relTime1  -- add 500 more seconds
timeDiff = diffRelativeTime relTime2 relTime1  -- 500 seconds
```

## Integration with Other Packages

### Serialization (cardano-binary)
All types support CBOR serialization for blockchain storage and network transmission.

```haskell
import Cardano.Binary

-- Serialize a slot
slot = SlotNo 42
encoded = serialize slot
decoded = decodeFull encoded  -- Right (SlotNo 42)
```

### JSON (Aeson)
Types support JSON serialization for APIs and configuration files.

```haskell
import Data.Aeson

slot = SlotNo 42
json = encode slot  -- "42"
```

## Advanced Usage

### Custom Epoch Info
```haskell
-- Create simple fixed-size epoch info
simpleEpochInfo :: EpochSize -> SlotLength -> EpochInfo Identity
simpleEpochInfo epochSize slotLength = EpochInfo
  { epochInfoSize_ = \_ -> pure epochSize
  , epochInfoFirst_ = \(EpochNo e) -> pure $ SlotNo (e * unEpochSize epochSize)
  , epochInfoEpoch_ = \(SlotNo s) -> pure $ EpochNo (s `div` unEpochSize epochSize)
  , epochInfoSlotToRelativeTime_ = \(SlotNo s) -> 
      pure $ RelativeTime (fromIntegral s * getSlotLength slotLength)
  , epochInfoSlotLength_ = \_ -> pure slotLength
  }
```

### Monad Transformations
```haskell
-- Transform EpochInfo between monads
identityEI :: EpochInfo Identity
identityEI = -- ... 

ioEI :: EpochInfo IO
ioEI = generalizeEpochInfo identityEI
```

## Error Handling

Most operations are pure, but EpochInfo operations may fail in the underlying monad when:
- Requesting information beyond available blockchain data
- Working with invalid or future slot numbers
- Epoch transition information is not yet available

Always handle potential failures appropriately based on your use case.

## Performance Considerations

- Slot numbers and epochs are based on `Word64`, providing a very large range
- Time calculations use high-precision types to avoid rounding errors
- The `WithOrigin` type is optimized for common blockchain patterns
- EpochInfo queries may require blockchain state access and should be cached when possible

## See Also

- [`cardano-binary`](../cardano-binary/README.md) - CBOR serialization
- [`cardano-crypto-class`](../cardano-crypto-class/README.md) - Cryptographic primitives
- [Ouroboros Papers](https://iohk.io/research/) - The consensus protocol research