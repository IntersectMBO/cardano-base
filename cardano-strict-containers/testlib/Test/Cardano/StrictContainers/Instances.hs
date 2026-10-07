{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.StrictContainers.Instances where

import Test.QuickCheck (Arbitrary (..))

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
