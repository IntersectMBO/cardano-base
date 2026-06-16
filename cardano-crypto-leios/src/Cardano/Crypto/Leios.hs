{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Cryptographic data types and operations used in Leios per CIP-164. Leios
-- uses BLS12-381 MinSig as its signature scheme and definees a 'LeiosCert' that
-- can be included into blocks.
module Cardano.Crypto.Leios where

import Cardano.Binary (enforceSize)
import Cardano.Crypto.DSIGN (
  SigDSIGN,
  SignKeyDSIGN,
  VerKeyDSIGN,
  decodeSigDSIGN,
  encodeSigDSIGN,
 )
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN)
import Codec.CBOR.Decoding (Decoder, decodeBytes)
import Codec.CBOR.Encoding (Encoding, encodeBytes, encodeListLen)
import Control.DeepSeq (NFData)
import Data.ByteString (ByteString)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

-- * Cryptographic primitives

type LeiosDSIGN = BLS12381MinSigDSIGN

type LeiosSigningKey = SignKeyDSIGN LeiosDSIGN

type LeiosVerificationKey = VerKeyDSIGN LeiosDSIGN

type LeiosSignature = SigDSIGN LeiosDSIGN

-- * Leios certificates

-- | A Leios certificate over an endorser block, as specified in CIP-164:
--
-- @
-- leios_certificate =
--   [ signers               : bytes ; bitfield over the epoch's committee, MSB-first
--   , aggregated_signature  : leios_bls_signature
--   ]
-- @
--
-- The committee is derived deterministically from the active stake distribution
-- for the epoch of the announcing RB, so individual voter identities and
-- eligibility proofs are not carried in the certificate; 'signers' is a
-- @⌈N\/8⌉@-byte bitfield over the committee where bit @i@ is set iff voter
-- index @i@ signed.
data LeiosCert = LeiosCert
  { signers :: !ByteString
  , aggregatedSignature :: !LeiosSignature
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | Plain CBOR encoder for 'LeiosCert', matching the CDDL in 'LeiosCert'.
encodeLeiosCert :: LeiosCert -> Encoding
encodeLeiosCert cert =
  encodeListLen 2
    <> encodeBytes cert.signers
    <> encodeSigDSIGN cert.aggregatedSignature

-- | Plain CBOR decoder for 'LeiosCert', matching the CDDL in 'LeiosCert'.
decodeLeiosCert :: Decoder s LeiosCert
decodeLeiosCert = do
  enforceSize "LeiosCert" 2
  LeiosCert
    <$> decodeBytes
    <*> decodeSigDSIGN
