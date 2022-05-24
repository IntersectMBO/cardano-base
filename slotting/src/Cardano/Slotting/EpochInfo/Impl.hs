-- | For use in trivial cases, such as in mocks, tests, etc.
module Cardano.Slotting.EpochInfo.Impl
  ( fixedEpochInfo,

    -- * Shortcuts
    fixedEpochInfoEpoch,
    fixedEpochInfoFirst,
  )
where

import Cardano.Slotting.EpochInfo.API
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))
import Cardano.Slotting.Time (RelativeTime (..), SlotLength, getSlotLength)

-- | The 'EpochInfo' induced by assuming the epoch size and slot length are
-- fixed for the entire system lifetime
fixedEpochInfo :: Monad m => EpochSize -> SlotLength -> EpochInfo m
fixedEpochInfo (EpochSize size) slotLength =
  EpochInfo
    { epochInfoSize_ = \_ ->
        return $ EpochSize size,
      epochInfoFirst_ = \e -> return $ fixedEpochInfoFirst (EpochSize size) e,
      epochInfoEpoch_ = \sl -> return $ fixedEpochInfoEpoch (EpochSize size) sl,
      epochInfoSlotToRelativeTime_ = \(SlotNo slot) ->
        return $ RelativeTime (fromIntegral slot * getSlotLength slotLength),
      epochInfoSlotLength_ = const $ pure slotLength
    }

-- | The pure computation underlying 'epochInfoFirst' applied to
-- 'fixedEpochInfo'
--
-- You don't need a 'SlotLength' for this.
fixedEpochInfoFirst :: EpochSize -> EpochNo -> SlotNo
fixedEpochInfoFirst (EpochSize size) (EpochNo epochNo) =
  SlotNo (epochNo * size)

-- | The pure computation underlying 'epochInfoEpoch' applied to
-- 'fixedEpochInfo'
--
-- You don't need a 'SlotLength' for this.
fixedEpochInfoEpoch :: EpochSize -> SlotNo -> EpochNo
fixedEpochInfoEpoch (EpochSize size) (SlotNo slot) =
  EpochNo (slot `div` size)
