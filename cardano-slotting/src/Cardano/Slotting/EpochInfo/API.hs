{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}

module Cardano.Slotting.EpochInfo.API (
  EpochInfo (..),
  epochInfoSize,
  epochInfoFirst,
  epochInfoEpoch,
  epochInfoRange,
  epochInfoSlotToRelativeTime,
  epochInfoSlotToUTCTime,
  epochInfoSlotLength,

  -- * Utility
  hoistEpochInfo,
  generalizeEpochInfo,
)
where

import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))
import Cardano.Slotting.Time (RelativeTime, SlotLength, SystemStart, fromRelativeTime)
import Control.Monad.Morph (generalize)
import Data.Functor.Identity
import Data.Time.Clock (UTCTime)
import GHC.Stack (HasCallStack)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

-- | Information about epochs
--
-- Different epochs may have different sizes and different slot lengths. This
-- information is encapsulated by 'EpochInfo'. It is parameterized over a monad
-- @m@ because the information about how long each epoch is may depend on
-- information derived from the blockchain itself. It ultimately requires acess
-- to state, and so either uses the monad for that or uses the monad to reify
-- failure due to cached state information being too stale for the current
-- query.
data EpochInfo m = EpochInfo
  { epochInfoSize_ :: HasCallStack => EpochNo -> m EpochSize
  -- ^ Return the size of the given epoch as a number of slots
  --
  -- Note that the number of slots does /not/ bound the number of blocks,
  -- since the EBB and a regular block share a slot number.
  , epochInfoFirst_ :: HasCallStack => EpochNo -> m SlotNo
  -- ^ First slot in the specified epoch
  --
  -- See also 'epochInfoRange'
  , epochInfoEpoch_ :: HasCallStack => SlotNo -> m EpochNo
  -- ^ Epoch containing the given slot
  --
  -- We should have the property that
  --
  -- > s `inRange` epochInfoRange (epochInfoEpoch s)
  , epochInfoSlotToRelativeTime_ ::
      HasCallStack =>
      SlotNo ->
      m RelativeTime
  -- ^ The 'RelativeTime' of the start of the given slot
  --
  -- This calculation depends on the varying slot lengths of the relevant
  -- epochs.
  --
  -- See also 'epochInfoSlotToUTCTime'.
  , epochInfoSlotLength_ ::
      HasCallStack =>
      SlotNo ->
      m SlotLength
  -- ^ Return the length of the specified slot.
  }
  deriving (NoThunks) via OnlyCheckWhnfNamed "EpochInfo" (EpochInfo m)

-- | Unhelpful instance, but this type occurs in records (eg @Shelley.Globals@)
-- that we want to be able to 'show'
instance Show (EpochInfo f) where
  showsPrec _ _ = showString "EpochInfoHasNoUsefulShowInstance"

epochInfoRange :: Monad m => EpochInfo m -> EpochNo -> m (SlotNo, SlotNo)
epochInfoRange epochInfo epochNo =
  aux
    <$> epochInfoFirst epochInfo epochNo
    <*> epochInfoSize epochInfo epochNo
  where
    aux :: SlotNo -> EpochSize -> (SlotNo, SlotNo)
    aux (SlotNo s) (EpochSize sz) = (SlotNo s, SlotNo (s + sz - 1))

-- | The start of the given slot
epochInfoSlotToUTCTime ::
  (HasCallStack, Monad m) =>
  EpochInfo m ->
  SystemStart ->
  SlotNo ->
  m UTCTime
epochInfoSlotToUTCTime ei start sl =
  fromRelativeTime start <$> epochInfoSlotToRelativeTime ei sl

{-------------------------------------------------------------------------------
  Extraction functions that preserve the HasCallStack constraint

  (Ideally, ghc would just do this..)
-------------------------------------------------------------------------------}

epochInfoSize :: HasCallStack => EpochInfo m -> EpochNo -> m EpochSize
epochInfoSize = epochInfoSize_

epochInfoFirst :: HasCallStack => EpochInfo m -> EpochNo -> m SlotNo
epochInfoFirst = epochInfoFirst_

epochInfoEpoch :: HasCallStack => EpochInfo m -> SlotNo -> m EpochNo
epochInfoEpoch = epochInfoEpoch_

epochInfoSlotToRelativeTime ::
  HasCallStack => EpochInfo m -> SlotNo -> m RelativeTime
epochInfoSlotToRelativeTime = epochInfoSlotToRelativeTime_

epochInfoSlotLength ::
  HasCallStack => EpochInfo m -> SlotNo -> m SlotLength
epochInfoSlotLength = epochInfoSlotLength_

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

hoistEpochInfo :: (forall a. m a -> n a) -> EpochInfo m -> EpochInfo n
hoistEpochInfo f ei =
  EpochInfo
    { epochInfoSize_ = f . epochInfoSize ei
    , epochInfoFirst_ = f . epochInfoFirst ei
    , epochInfoEpoch_ = f . epochInfoEpoch ei
    , epochInfoSlotToRelativeTime_ = f . epochInfoSlotToRelativeTime ei
    , epochInfoSlotLength_ = f . epochInfoSlotLength ei
    }

generalizeEpochInfo :: Monad m => EpochInfo Identity -> EpochInfo m
generalizeEpochInfo = hoistEpochInfo generalize
