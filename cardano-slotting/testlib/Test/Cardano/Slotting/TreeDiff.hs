{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Slotting.TreeDiff where

import Cardano.Slotting.Slot
import Cardano.Slotting.Block
import Data.TreeDiff

instance ToExpr x => ToExpr (WithOrigin x)

instance ToExpr SlotNo

instance ToExpr BlockNo

instance ToExpr EpochNo

instance ToExpr EpochSize
