{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Slotting.Arbitrary () where

import Cardano.Slotting.Block (BlockNo (..))
import Cardano.Slotting.Slot (
  EpochInterval (..),
  EpochNo (..),
  EpochSize (..),
  SlotNo (..),
  WithOrigin (..),
 )
import Cardano.Slotting.Time (SystemStart (..))
import Test.QuickCheck
import Test.QuickCheck.Instances.Time ()

deriving instance Arbitrary BlockNo

deriving instance Arbitrary EpochNo

deriving instance Arbitrary EpochSize

deriving instance Arbitrary EpochInterval

instance Arbitrary SlotNo where
  arbitrary =
    SlotNo
      <$> ( (getPositive <$> arbitrary)
              `suchThat` (\n -> n < maxBound - 2 ^ (32 :: Int))
          )

  -- need some room, we're assuming we'll never wrap around 64bits

  shrink (SlotNo n) = [SlotNo n' | n' <- shrink n, n' > 0]

instance Arbitrary t => Arbitrary (WithOrigin t) where
  arbitrary = frequency [(20, pure Origin), (80, At <$> arbitrary)]
  shrink = \case
    Origin -> []
    At x -> Origin : map At (shrink x)

deriving instance Arbitrary SystemStart
