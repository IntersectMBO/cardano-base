module Cardano.Slotting.EpochInfo.Impl
  ( fixedEpochInfo,
  )
where

import Cardano.Slotting.EpochInfo.API
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))
import Cardano.Slotting.Time (RelativeTime (..), SlotLength, getSlotLength)

fixedEpochInfo :: Monad m => EpochSize -> SlotLength -> EpochInfo m
fixedEpochInfo (EpochSize size) slotLength = EpochInfo
  { epochInfoSize_ = \_ ->
      return $ EpochSize size,
    epochInfoFirst_ = \(EpochNo epochNo) ->
      return $ SlotNo (epochNo * size),
    epochInfoEpoch_ = \(SlotNo slot) ->
      return $ EpochNo (slot `div` size),
    epochInfoSlotToRelativeTime_ = \(SlotNo slot) ->
      return $ RelativeTime (fromIntegral slot * getSlotLength slotLength)
  }
