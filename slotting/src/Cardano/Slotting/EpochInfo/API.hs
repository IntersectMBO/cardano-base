{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Cardano.Slotting.EpochInfo.API
  ( EpochInfo (..),
    epochInfoFirst,
    epochInfoEpoch,
    epochInfoRange,
    epochInfoSlotToRelativeTime,
    epochInfoSlotToUTCTime,
  )
where

import Cardano.Binary
import Cardano.Slotting.EpochInfo.Impl
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))
import Cardano.Slotting.Time
import Data.Time.Clock (UTCTime)
import GHC.Generics
import NoThunks.Class (NoThunks)

-- | Information about epochs. This assumes the epoch size and slot length are
-- fixed.
data EpochInfo
  = EpochInfo
      { -- | The size of an epoch as a number of slots.
        epochInfoSize       :: EpochSize
        -- | The slot length.
      , epochInfoSlotLength :: SlotLength
      }
  deriving (Generic, Show, NoThunks)

instance ToCBOR EpochInfo where
  toCBOR (EpochInfo epochSize slotLength) = mconcat
    [ encodeListLen 2
    , toCBOR epochSize
    , toCBOR slotLength
    ]

instance FromCBOR EpochInfo where
  fromCBOR = do
    enforceSize "EpochInfo" 2
    EpochInfo <$> fromCBOR <*> fromCBOR

-- | First slot in the specified epoch
--
-- See also 'epochInfoRange'
epochInfoFirst :: EpochInfo -> EpochNo -> SlotNo
epochInfoFirst (EpochInfo epochSize _) e = fixedEpochInfoFirst epochSize e

-- | Epoch containing the given slot
--
-- We have the property that
--
-- > s `inRange` epochInfoRange (epochInfoEpoch s)
epochInfoEpoch :: EpochInfo -> SlotNo -> EpochNo
epochInfoEpoch (EpochInfo epochSize _) sl = fixedEpochInfoEpoch epochSize sl

-- | The 'RelativeTime' of the start of the given slot
--
-- This calculation depends on the varying slot lengths of the relevant
-- epochs.
--
-- See also 'epochInfoSlotToUTCTime'.
epochInfoSlotToRelativeTime :: EpochInfo -> SlotNo -> RelativeTime
epochInfoSlotToRelativeTime (EpochInfo _ slotLength) (SlotNo slot)
  = RelativeTime (fromIntegral slot * getSlotLength slotLength)

epochInfoRange :: EpochInfo -> EpochNo -> (SlotNo, SlotNo)
epochInfoRange epochInfo epochNo =
  aux
    (epochInfoFirst epochInfo epochNo)
    (epochInfoSize epochInfo)
  where
    aux :: SlotNo -> EpochSize -> (SlotNo, SlotNo)
    aux (SlotNo s) (EpochSize sz) = (SlotNo s, SlotNo (s + sz - 1))

-- | The start of the given slot
epochInfoSlotToUTCTime ::
     EpochInfo
  -> SystemStart
  -> SlotNo
  -> UTCTime
epochInfoSlotToUTCTime ei start sl =
  fromRelativeTime start (epochInfoSlotToRelativeTime ei sl)
