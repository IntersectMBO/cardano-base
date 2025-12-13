{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}

module Cardano.Crypto.Peras.Cert (
  -- * Peras certificates
  PerasCert (..),
) where

import Cardano.Crypto.Peras (PerasRoundNo)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

{-------------------------------------------------------------------------------
   Peras certificates
-------------------------------------------------------------------------------}

-- | Opaque type representing a boosted block.
--
-- NOTE: this will be fleshed out in the future.
data BoostedBlock = BoostedBlock
  deriving (Eq, Show, Generic, NoThunks)

-- | A Peras certificate indicating that a node has received a weight boost.
--
-- NOTE: this will be fleshed out in the future.
data PerasCert = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Round number
  , pcBostedBlock :: !BoostedBlock
  -- ^ The block that received the boost
  }
  deriving (Eq, Show, Generic, NoThunks)
