{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}

module Cardano.Crypto.Peras.Vote (
  PerasVote (..),
  PerasVoteEligibilityProof (..),
) where

import Cardano.Crypto.Peras (
  PerasBoostedBlock (..),
  PerasRoundNo (..),
  PerasSeatIndex (..),
  PerasSignature (..),
  PerasVRFOutput (..),
 )
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

{-------------------------------------------------------------------------------
   Votes
-------------------------------------------------------------------------------}

-- | An individual vote cast by a single committee member, prior to
-- aggregation into a 'Cardano.Crypto.Peras.Cert.PerasCert'.
data PerasVote = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !PerasSignature
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NoThunks, NFData)

-- | A committee member's proof of eligibility to vote in a given round.
--
-- Persistent voters were sampled once for the whole committee's lifetime and
-- need no further proof; non-persistent voters were sampled for this round
-- only and carry the VRF output that proves it.
data PerasVoteEligibilityProof
  = PersistentPerasVoteEligibilityProof
  | NonPersistentPerasVoteEligibilityProof !PerasVRFOutput
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NoThunks, NFData)
