{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# OPTIONS_GHC -Wno-orphans #-} -- need NoThunks for secp256k1-haskell types

module Cardano.Crypto.DSIGN.SECP256k1 where

import Data.Kind (Type)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import qualified Crypto.Secp256k1 as SECP
import NoThunks.Class (NoThunks)
import Cardano.Crypto.DSIGN.Class (DSIGNAlgorithm (VerKeyDSIGN, SignKeyDSIGN, SigDSIGN,
  SeedSizeDSIGN, SizeSigDSIGN, SizeSignKeyDSIGN, SizeVerKeyDSIGN, algorithmNameDSIGN,
  deriveVerKeyDSIGN, signDSIGN, verifyDSIGN, genKeyDSIGN, rawSerialiseSigDSIGN,
  Signable))

data SECP256k1DSIGN

instance NoThunks (VerKeyDSIGN SECP256k1DSIGN)

instance NoThunks (SignKeyDSIGN SECP256k1DSIGN)

instance NoThunks (SigDSIGN SECP256k1DSIGN)

instance DSIGNAlgorithm SECP256k1DSIGN where
  type SeedSizeDSIGN SECP256k1DSIGN = 32
  type SizeSigDSIGN SECP256k1DSIGN = 72
  type SizeSignKeyDSIGN SECP256k1DSIGN = 32
  type SizeVerKeyDSIGN SECP256k1DSIGN = 33 -- approximate, as it's 257 bits
  type Signable SECP256k1DSIGN = ((~) SECP.Msg)
  newtype VerKeyDSIGN SECP256k1DSIGN = VerKeySECP256k1 SECP.PubKey
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  newtype SignKeyDSIGN SECP256k1DSIGN = SignKeySECP256k1 SECP.SecKey
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  newtype SigDSIGN SECP256k1DSIGN = SigSECP256k1 SECP.Sig
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  algorithmNameDSIGN _ = "secp256k1"
  deriveVerKeyDSIGN (SignKeySECP256k1 sk) = VerKeySECP256k1 . SECP.derivePubKey $ sk
  signDSIGN () msg (SignKeySECP256k1 k) = _
  verifyDSIGN = _
  genKeyDSIGN = _
  rawSerialiseSigDSIGN = _

-- Required orphans

instance NoThunks SECP.PubKey

instance NoThunks SECP.SecKey

instance NoThunks SECP.Sig
