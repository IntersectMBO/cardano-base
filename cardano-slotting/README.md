# cardano-slotting

Slot and epoch time abstractions for Cardano.

[![Hackage](https://img.shields.io/hackage/v/cardano-slotting)](https://hackage.haskell.org/package/cardano-slotting)

## Overview

Cardano operates on a discrete time grid. Time is divided into **slots**
(currently 1 second each on mainnet), which are grouped into **epochs**
(currently 432,000 slots ≈ 5 days). Every on-chain event is anchored to a
slot number.

`cardano-slotting` provides:

- `SlotNo` and `EpochNo` — type-safe wrappers for slot and epoch numbers
- `EpochInfo` — an interface for converting between slots, epochs, and UTC time
- `BlockNo` — a separate counter for actual blocks produced (slots can be empty)
- Wall-clock conversion utilities

## Installation

```cabal
build-depends: cardano-slotting >= 0.2
```

## Core Types

### `SlotNo`

A newtype over `Word64`. Slot 0 is the genesis slot. Never use a plain integer
where a `SlotNo` is expected — the newtype prevents mixing up slot numbers with
other `Word64` values.

```haskell
import Cardano.Slotting.Slot (SlotNo (..))

-- Construction
currentSlot :: SlotNo
currentSlot = SlotNo 9_500_000

-- Arithmetic via Num instance
nextSlot :: SlotNo -> SlotNo
nextSlot s = s + 1

slotsUntil :: SlotNo -> SlotNo -> Word64
slotsUntil (SlotNo from) (SlotNo to)
  | to >= from = to - from
  | otherwise  = 0

-- Comparison via Ord instance
isRecent :: SlotNo -> SlotNo -> Bool
isRecent tip candidate = candidate >= tip - 100
```

### `EpochNo`

A newtype over `Word64` for epoch numbers.

```haskell
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..))

currentEpoch :: EpochNo
currentEpoch = EpochNo 470

-- Epoch size varies by era; typically 432,000 on mainnet
mainnetEpochSize :: EpochSize
mainnetEpochSize = EpochSize 432_000
```

### `BlockNo`

A newtype over `Word64` for block numbers. Block numbers only increment when
a block is actually produced; they advance more slowly than slot numbers
because slots can be empty.

```haskell
import Cardano.Slotting.Block (BlockNo (..))

currentBlock :: BlockNo
currentBlock = BlockNo 10_500_000
```

## `EpochInfo` — Slot / Epoch Conversions

`EpochInfo m` carries the information needed to translate between slots,
epochs, and sizes. The `m` parameter is the monad in which queries run
(typically `Either EpochInfoError` or `IO`).

```haskell
import Cardano.Slotting.EpochInfo.API

-- Convert a slot to the epoch it belongs to
slotToEpoch
  :: Monad m
  => EpochInfo m
  -> SlotNo
  -> m EpochNo
slotToEpoch ei slot = epochInfoEpoch ei slot

-- Get the first slot of an epoch
epochStart
  :: Monad m
  => EpochInfo m
  -> EpochNo
  -> m SlotNo
epochStart ei epoch = epochInfoFirst ei epoch

-- Get the number of slots in an epoch
epochLength
  :: Monad m
  => EpochInfo m
  -> EpochNo
  -> m EpochSize
epochLength ei epoch = epochInfoSize ei epoch
```

### Building an `EpochInfo`

For a chain with a fixed epoch size (Byron, or single-era analysis):

```haskell
import Cardano.Slotting.EpochInfo.Impl (fixedEpochInfo)
import Cardano.Slotting.Time           (slotLengthFromSec)

-- Fixed-size epochs, 1-second slots
simpleEpochInfo :: EpochInfo (Either EpochInfoError)
simpleEpochInfo =
  fixedEpochInfo
    (EpochSize 432_000)       -- slots per epoch
    (slotLengthFromSec 1)     -- slot duration
```

### Practical example

```haskell
import Cardano.Slotting.EpochInfo
import Cardano.Slotting.EpochInfo.Impl
import Cardano.Slotting.Slot
import Cardano.Slotting.Time

-- Given a slot, print its epoch and position within that epoch
describeSlot :: EpochInfo (Either EpochInfoError) -> SlotNo -> IO ()
describeSlot ei slot = do
  case epochInfoEpoch ei slot of
    Left  err   -> putStrLn $ "Error: " <> show err
    Right epoch -> do
      case epochInfoFirst ei epoch of
        Left  err        -> putStrLn $ "Error: " <> show err
        Right epochStart -> do
          let SlotNo s  = slot
              SlotNo es = epochStart
              posInEpoch = s - es
          putStrLn $ "Slot "   <> show s
                  <> " is in epoch " <> show (unEpochNo epoch)
                  <> " at position " <> show posInEpoch

-- >>> describeSlot simpleEpochInfo (SlotNo 9_500_000)
-- Slot 9500000 is in epoch 21 at position 452000
-- (approximate; depends on epoch size)
```

## Wall-Clock Time Conversion

`Cardano.Slotting.Time` converts between `SlotNo` and UTC `NominalDiffTime` /
`UTCTime` given the chain's start time and slot duration.

```haskell
import Cardano.Slotting.Time

-- Chain start time (from genesis config)
mainnetStart :: SystemStart
mainnetStart = SystemStart $ UTCTime (fromGregorian 2017 9 23) 21600
-- September 23, 2017, 06:00:00 UTC (Byron mainnet genesis)

-- Slot duration
slotLen :: SlotLength
slotLen = slotLengthFromSec 1  -- 1 second per slot (Shelley+)

-- Convert slot to UTC time
slotToTime :: SlotNo -> UTCTime
slotToTime slot =
  addUTCTime
    (fromIntegral (unSlotNo slot) * getSlotLength slotLen)
    (getSystemStart mainnetStart)

-- Convert UTC time to slot
timeToSlot :: UTCTime -> SlotNo
timeToSlot t =
  let diff = diffUTCTime t (getSystemStart mainnetStart)
      slots = floor (diff / getSlotLength slotLen)
  in  SlotNo (max 0 slots)

-- Example: when did slot 9,500,000 occur?
-- >>> slotToTime (SlotNo 9_500_000)
-- 2020-04-02 21:56:40 UTC  (approximate)
```

## `EpochInfo` Extension

`Cardano.Slotting.EpochInfo.Extend` provides utilities for building `EpochInfo`
values that span multiple eras (each with different epoch sizes) — used by the
full Cardano consensus layer:

```haskell
import Cardano.Slotting.EpochInfo.Extend

-- Combine two EpochInfos: the first covers slots [0, boundary),
-- the second covers [boundary, ∞)
extendSafeZone
  :: EpochInfo m
  -> SlotNo     -- boundary slot
  -> EpochInfo m
  -> EpochInfo m
```

## Integration with `cardano-binary`

`SlotNo`, `EpochNo`, and `BlockNo` all implement `ToCBOR` / `FromCBOR`,
so they can be serialised directly:

```haskell
import Cardano.Binary        (serialize', decodeFull')
import Cardano.Slotting.Slot (SlotNo (..))

encodeSlot :: SlotNo -> ByteString
encodeSlot = serialize'

decodeSlot :: ByteString -> Either DecoderError SlotNo
decodeSlot = decodeFull'
```

## Running Tests

```bash
cabal test cardano-slotting:tests
```
