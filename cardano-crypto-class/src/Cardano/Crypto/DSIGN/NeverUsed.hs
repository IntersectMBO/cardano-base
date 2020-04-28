{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
module Cardano.Crypto.DSIGN.NeverUsed
  ( NeverDSIGN
  , VerKeyDSIGN (..)
  , SignKeyDSIGN (..)
  , SigDSIGN (..)
  )
where

import GHC.Generics (Generic)

import Cardano.Binary
import Cardano.Crypto.DSIGN.Class
import Cardano.Prelude (NoUnexpectedThunks)

-- | DSIGN never used
--
-- The type of keys and signatures is isomorphic to unit, but when actually
-- trying to sign or verify something a runtime exception will be thrown.
data NeverDSIGN

instance DSIGNAlgorithm NeverDSIGN where

  data VerKeyDSIGN  NeverDSIGN = NeverUsedVerKeyDSIGN
     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  data SignKeyDSIGN NeverDSIGN = NeverUsedSignKeyDSIGN
     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  data SigDSIGN     NeverDSIGN = NeverUsedSigDSIGN
     deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  algorithmNameDSIGN _ = "never"

  deriveVerKeyDSIGN _ = NeverUsedVerKeyDSIGN

  abstractSizeVKey _ = error "abstract size not available"
  abstractSizeSig  _ = error "abstract size not available"

  signDSIGN   = error "DSIGN not available"
  verifyDSIGN = error "DSIGN not available"

  seedSizeDSIGN     _ = 0
  genKeyDSIGN       _ = NeverUsedSignKeyDSIGN

  encodeVerKeyDSIGN  _ = toCBOR ()
  encodeSignKeyDSIGN _ = toCBOR ()
  encodeSigDSIGN     _ = toCBOR ()

  decodeVerKeyDSIGN  = return NeverUsedVerKeyDSIGN
  decodeSignKeyDSIGN = return NeverUsedSignKeyDSIGN
  decodeSigDSIGN     = return NeverUsedSigDSIGN

