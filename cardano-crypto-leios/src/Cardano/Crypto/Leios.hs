{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Cardano.Crypto.Leios (
  -- * Endorser block hashes
  EbHash (..),
  encodeEbHash,
  decodeEbHash,
  prettyEbHash,

  -- * Leios certificates
  LeiosCert (..),
  encodeLeiosCert,
  decodeLeiosCert,

  -- * BLS signing primitives
  LeiosDSIGN,
  LeiosSigningKey,
  LeiosVerificationKey,
  LeiosSignature,
) where

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (toCBOR), enforceSize)
import Cardano.Crypto.DSIGN (
  SigDSIGN,
  SignKeyDSIGN,
  VerKeyDSIGN,
  decodeSigDSIGN,
  encodeSigDSIGN,
 )
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN)
import Cardano.Slotting.Slot (SlotNo)
import Codec.CBOR.Decoding (Decoder, decodeBytes)
import Codec.CBOR.Encoding (Encoding, encodeBytes, encodeListLen)
import Codec.Serialise (Serialise)
import Control.DeepSeq (NFData)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

-- | Hash of the RB header that announced the endorser block.
--
-- Per CIP-0164 this is a @hash32@ (Blake2b-256, 32 bytes); the underlying
-- bytes are stored unwrapped to stay representation-compatible with the
-- previous definition in @ouroboros-consensus@.
newtype EbHash = MkEbHash {ebHashBytes :: ByteString}
  deriving stock (Eq, Ord, Generic)
  deriving newtype (NFData, NoThunks, Serialise, ToCBOR, FromCBOR)

instance Show EbHash where
  show = prettyEbHash

encodeEbHash :: EbHash -> Encoding
encodeEbHash (MkEbHash bytes) = encodeBytes bytes

decodeEbHash :: Decoder s EbHash
decodeEbHash = MkEbHash <$> decodeBytes

prettyEbHash :: EbHash -> String
prettyEbHash (MkEbHash bytes) = BS8.unpack (Base16.encode bytes)

-- | Leios uses BLS12-381 MinSig as its signature scheme; see CIP-0164.
type LeiosDSIGN = BLS12381MinSigDSIGN

type LeiosSigningKey = SignKeyDSIGN LeiosDSIGN

type LeiosVerificationKey = VerKeyDSIGN LeiosDSIGN

type LeiosSignature = SigDSIGN LeiosDSIGN

-- | A Leios certificate over an endorser block, as specified in CIP-0164:
--
-- @
-- leios_certificate =
--   [ slot_no
--   , endorser_block_hash
--   , signers               : bytes          ; bitfield over the epoch's committee, MSB-first
--   , aggregated_signature  : leios_bls_signature
--   ]
-- @
--
-- The committee is derived deterministically from the active stake
-- distribution for the epoch of the announcing RB, so individual voter
-- identities and eligibility proofs are not carried in the certificate;
-- 'signers' is a @⌈N\/8⌉@-byte bitfield over the committee where bit @i@
-- is set iff voter index @i@ signed.
data LeiosCert = LeiosCert
  { slotNo :: !SlotNo
  , endorserBlockHash :: !EbHash
  , signers :: !ByteString
  , aggregatedSignature :: !LeiosSignature
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

-- | Plain CBOR encoder for 'LeiosCert', matching the CDDL above. Use this
-- (rather than a 'ToCBOR'/'EncCBOR' class instance) at call sites so we
-- don't need orphan CBOR instances for the underlying BLS 'SigDSIGN'.
encodeLeiosCert :: LeiosCert -> Encoding
encodeLeiosCert cert =
  encodeListLen 4
    <> toCBOR (slotNo cert)
    <> encodeEbHash (endorserBlockHash cert)
    <> encodeBytes (signers cert)
    <> encodeSigDSIGN (aggregatedSignature cert)

decodeLeiosCert :: Decoder s LeiosCert
decodeLeiosCert = do
  enforceSize "LeiosCert" 4
  LeiosCert
    <$> fromCBOR
    <*> decodeEbHash
    <*> decodeBytes
    <*> decodeSigDSIGN
