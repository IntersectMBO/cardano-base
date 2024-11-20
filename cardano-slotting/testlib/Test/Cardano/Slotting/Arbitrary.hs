{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Slotting.Arbitrary () where

import Cardano.Slotting.Slot
import Test.QuickCheck

instance Arbitrary SlotNo where
  arbitrary =
    SlotNo
      <$> ( (getPositive <$> arbitrary)
              `suchThat` (\n -> n < maxBound - 2 ^ (32 :: Int))
          )

  -- need some room, we're assuming we'll never wrap around 64bits

  shrink (SlotNo n) = [SlotNo n' | n' <- shrink n, n' > 0]

deriving newtype instance Arbitrary EpochNo
