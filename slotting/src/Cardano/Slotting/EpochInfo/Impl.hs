{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Slotting.EpochInfo.Impl
  ( fixedSizeEpochInfo,
  )
where

import Cardano.Slotting.EpochInfo.API
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..), SlotNo (..))

fixedSizeEpochInfo :: Monad m => EpochSize -> EpochInfo m
fixedSizeEpochInfo (EpochSize size) = EpochInfo
  { epochInfoSize_ = \_ ->
      return $ EpochSize size,
    epochInfoFirst_ = \(EpochNo epochNo) ->
      return $ SlotNo (epochNo * size),
    epochInfoEpoch_ = \(SlotNo slot) ->
      return $ EpochNo (slot `div` size)
  }
