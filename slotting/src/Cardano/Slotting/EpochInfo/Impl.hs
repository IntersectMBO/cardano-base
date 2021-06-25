-- | For use in trivial cases, such as in mocks, tests, etc.
module Cardano.Slotting.EpochInfo.Impl
  ( fixedEpochInfoEpoch,
    fixedEpochInfoFirst,
  )
where

import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))

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
