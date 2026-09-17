{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.StrictContainers.Instances where

import Test.QuickCheck (Arbitrary (..), Gen, chooseInt, frequency, listOf)

import Data.Bitmap (Bitmap)
import qualified Data.Bitmap as Bitmap
import Data.Foldable (toList)
import Data.Maybe.Strict
import Data.Sequence.Strict (StrictSeq (..))
import qualified Data.Sequence.Strict as SSeq

instance Arbitrary e => Arbitrary (StrictSeq e) where
  arbitrary = SSeq.fromList <$> arbitrary
  shrink = fmap SSeq.fromList . shrink . toList

instance Arbitrary e => Arbitrary (StrictMaybe e) where
  arbitrary = maybeToStrictMaybe <$> arbitrary
  shrink = fmap maybeToStrictMaybe . shrink . strictMaybeToMaybe

genBitmap :: Integral a => Gen a -> Gen (Bitmap a)
genBitmap genIx = do
  maxIx <- frequency [(9, fromIntegral <$> chooseInt (0, 2000)), (1, genIx)]
  indices <- listOf (fromIntegral <$> chooseInt (0, fromIntegral maxIx))
  pure $ Bitmap.fromIndices maxIx indices
