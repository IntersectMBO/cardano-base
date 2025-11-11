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

-- | A Peras certificate indicating that a node has received a weight boost.
--
-- NOTE: this is an initial sketch and will change in the future.
data PerasCert blk = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Round number
  , pcBostedBlock :: !blk
  -- ^ The block that received the boost
  }
  deriving (Eq, Show, Generic, NoThunks)
