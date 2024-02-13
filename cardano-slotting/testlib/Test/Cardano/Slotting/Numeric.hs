{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Slotting.Numeric () where

import Cardano.Slotting.Slot
  ( EpochSize (EpochSize),
    EpochNo (EpochNo),
  )

deriving newtype instance Num EpochNo

deriving newtype instance Num EpochSize

deriving newtype instance Real EpochSize

deriving newtype instance Integral EpochSize
