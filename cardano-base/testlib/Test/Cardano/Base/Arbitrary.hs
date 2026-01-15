{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Base.Arbitrary () where

import Cardano.Base.IP
import Test.QuickCheck

instance Arbitrary IPv4 where
  arbitrary = toIPv4w <$> arbitrary

instance Arbitrary IPv6 where
  arbitrary = do
    t <- (,,,) <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    pure $ toIPv6w t
