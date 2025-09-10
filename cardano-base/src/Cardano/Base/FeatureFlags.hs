{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Mini-abstraction to aid parallel development of experimental Cardano
-- features.
--
-- == Usage example
--
-- >>> import Data.Set (Set)
-- >>> import qualified Data.Set as Set
-- >>> import Cardano.Base.FeatureFlags (CardanoFeatureFlag (..))
--
-- >>> :{
-- logic :: Set CardanoFeatureFlag -> Int -> Int
-- logic featureFlags
--   | Set.member PerasFlag featureFlags = (+ 2)
--   | otherwise = (+ 1)
-- :}
module Cardano.Base.FeatureFlags (
  CardanoFeatureFlag (..),
) where

import qualified Data.Aeson as Aeson
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

-- | An experimental Cardano feature.
data CardanoFeatureFlag
  = -- | Feature flag for Ouroboros Leios (higher throughput).
    LeiosFlag
  | -- | Feature flag for Ouroboros Peras (faster settlement).
    PerasFlag
  | -- | Feature flag for Ouroboros Phalanx (anti-grinding).
    PhalanxFlag
  deriving stock (Show, Read, Eq, Ord, Enum, Bounded, Generic)
  deriving anyclass (NoThunks)

instance Aeson.FromJSON CardanoFeatureFlag where
  parseJSON = Aeson.withText "CardanoFeatureFlag" $ \case
    "Leios" -> pure LeiosFlag
    "Peras" -> pure PerasFlag
    "Phalanx" -> pure PhalanxFlag
    t -> fail $ "Unknown flag: " <> show t

instance Aeson.ToJSON CardanoFeatureFlag where
  toJSON = \case
    LeiosFlag -> "Leios"
    PerasFlag -> "Peras"
    PhalanxFlag -> "Phalanx"
