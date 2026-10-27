{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE NumericUnderscores #-}

module Cardano.Crypto.Peras.Cert (
  -- * Peras certificates
  PerasCert (..),
  PerasCertSize (..),
  maxPerasCertSize,
) where

import Cardano.Crypto.Peras (PerasRoundNo)
import Data.Word (Word32)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

{-------------------------------------------------------------------------------
   Peras certificates
-------------------------------------------------------------------------------}

-- | Size of a Peras certificate in bytes. Used to account for its inclusion in
-- a block and to check it against the certificate size limit.
newtype PerasCertSize = PerasCertSize {unPerasCertSize :: Word32}
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
  deriving (Enum, Real, Integral, Num) via Word32

-- | Policy limit for a CBOR-encoded Peras certificate, in bytes.
--
-- The maximum mainnet block size was 90,112 bytes as of 2026-08-06. A limit of
-- 40,000 bytes leaves roughly half the block for other contents. wFA^LS
-- certificates would reach this size with around 800 non-persistent seats in
-- the voting committee.
--
-- This is not a cryptographic size bound.
maxPerasCertSize :: PerasCertSize
maxPerasCertSize = 40_000

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
