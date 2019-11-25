{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Slotting.EpochInfo.Impl
  ( fixedSizeEpochInfo,
  )
where

import Cardano.Slotting.EpochInfo.API
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))
import Data.List (maximumBy)
import Data.Ord (comparing)

fixedSizeEpochInfo :: Monad m => EpochSize -> EpochInfo m
fixedSizeEpochInfo (EpochSize size) = EpochInfo
  { epochInfoSize = \_ ->
      return $ EpochSize size,
    epochInfoFirst = \(EpochNo epochNo) ->
      return $ SlotNo (epochNo * size),
    epochInfoEpoch = \(SlotNo slot) ->
      return $ EpochNo (slot `div` size)
  }
