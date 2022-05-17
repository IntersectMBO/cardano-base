module Cardano.Slotting.EpochInfo.Extend where

import Cardano.Slotting.EpochInfo.API (EpochInfo (..))
import Cardano.Slotting.Slot (EpochNo (EpochNo), EpochSize (EpochSize), SlotNo (SlotNo))
import Cardano.Slotting.Time
  ( SlotLength (getSlotLength),
    addRelativeTime,
    multNominalDiffTime,
  )

-- | Given a basis point, use it and its slot length to impute a linear
-- relationship between slots and time in order to extend an 'EpochInfo' to
-- infinity.
--
-- The returned `EpochInfo` may still fail (according to the semantics of the
-- specified monad) if any of the underlying operations fail. For example, if we
-- cannot translate the basis point.
unsafeLinearExtendEpochInfo ::
  Monad m =>
  SlotNo ->
  EpochInfo m ->
  EpochInfo m
unsafeLinearExtendEpochInfo basisSlot underlyingEI =
  let lastKnownEpochM = epochInfoEpoch_ underlyingEI basisSlot

      goSize = \en -> do
        lke <- lastKnownEpochM
        if en <= lke
          then epochInfoSize_ underlyingEI en
          else epochInfoSize_ underlyingEI lke
      goFirst = \en -> do
        lke <- lastKnownEpochM
        if en <= lke
          then epochInfoFirst_ underlyingEI en
          else do
            SlotNo lkeStart <- epochInfoFirst_ underlyingEI lke
            EpochSize sz <- epochInfoSize_ underlyingEI en
            let EpochNo numEpochs = en - lke
            pure . SlotNo $ lkeStart + (numEpochs * sz)
      goEpoch = \sn ->
        if sn <= basisSlot
          then epochInfoEpoch_ underlyingEI sn
          else do
            lke <- lastKnownEpochM
            lkeStart <- epochInfoFirst_ underlyingEI lke
            EpochSize sz <- epochInfoSize_ underlyingEI lke
            let SlotNo slotsForward = sn - lkeStart
            pure . (lke +) . EpochNo $ slotsForward `div` sz
      goTime = \sn ->
        if sn <= basisSlot
          then epochInfoSlotToRelativeTime_ underlyingEI sn
          else do
            let SlotNo slotDiff = sn - basisSlot

            a1 <- epochInfoSlotToRelativeTime_ underlyingEI basisSlot
            lgth <- epochInfoSlotLength_ underlyingEI basisSlot

            pure $
              addRelativeTime
                (multNominalDiffTime (getSlotLength lgth) slotDiff)
                a1
      goLength = \sn ->
        if sn <= basisSlot
          then epochInfoSlotLength_ underlyingEI sn
          else epochInfoSlotLength_ underlyingEI basisSlot
   in EpochInfo
        { epochInfoSize_ = goSize,
          epochInfoFirst_ = goFirst,
          epochInfoEpoch_ = goEpoch,
          epochInfoSlotToRelativeTime_ = goTime,
          epochInfoSlotLength_ = goLength
        }
