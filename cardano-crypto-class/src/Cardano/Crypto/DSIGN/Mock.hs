{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementation of digital signatures.
module Cardano.Crypto.DSIGN.Mock
  ( MockDSIGN
  , SignKeyDSIGN (..)
  , VerKeyDSIGN (..)
  , SigDSIGN (..)
  , verKeyIdFromSigned
  , mockSign
  , mockSigned
  )
where

import Data.Word (Word64)
import GHC.Generics (Generic)
import GHC.Stack

import Cardano.Prelude (NoUnexpectedThunks, Proxy(..))
import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed
import Cardano.Crypto.Hash
import Cardano.Crypto.Util


data MockDSIGN

instance DSIGNAlgorithm MockDSIGN where
    type SeedSizeDSIGN MockDSIGN = 8

    --
    -- Key and signature types
    --

    newtype VerKeyDSIGN MockDSIGN = VerKeyMockDSIGN Word64
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (Num, NoUnexpectedThunks)

    newtype SignKeyDSIGN MockDSIGN = SignKeyMockDSIGN Word64
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (Num, NoUnexpectedThunks)

    data SigDSIGN MockDSIGN = SigMockDSIGN !(Hash ShortHash ()) !Word64
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    --
    -- Metadata and basic key operations
    --

    algorithmNameDSIGN _ = "mock"

    deriveVerKeyDSIGN (SignKeyMockDSIGN n) = VerKeyMockDSIGN n

    --
    -- Core algorithm operations
    --

    type Signable MockDSIGN = ToCBOR

    signDSIGN () a sk = mockSign a sk

    verifyDSIGN () (VerKeyMockDSIGN n) a s =
      if s == mockSign a (SignKeyMockDSIGN n)
        then Right ()
        else Left $ show $ MockVerificationFailure {
                 vErrVerKey    = VerKeyMockDSIGN n
               , vErrSignature = s
               , vErrCallStack = prettyCallStack callStack
               }

    --
    -- Key generation
    --

    genKeyDSIGN seed   =
      SignKeyMockDSIGN (runMonadRandomWithSeed seed getRandomWord64)


    --
    -- raw serialise/deserialise
    --

    sizeVerKeyDSIGN  _ = 8 -- for 64 bit Int
    sizeSignKeyDSIGN _ = 8
    sizeSigDSIGN     _ = sizeHash (Proxy :: Proxy ShortHash)
                       + 8

    rawSerialiseVerKeyDSIGN  (VerKeyMockDSIGN  k) = writeBinaryWord64 k
    rawSerialiseSignKeyDSIGN (SignKeyMockDSIGN k) = writeBinaryWord64 k
    rawSerialiseSigDSIGN     (SigMockDSIGN   h k) = getHash h
                                                 <> writeBinaryWord64 k

    rawDeserialiseVerKeyDSIGN bs
      | [kb] <- splitsAt [8] bs
      , let k = readBinaryWord64 kb
      = Just $! VerKeyMockDSIGN k

      | otherwise
      = Nothing

    rawDeserialiseSignKeyDSIGN bs
      | [kb] <- splitsAt [8] bs
      , let k = readBinaryWord64 kb
      = Just $! SignKeyMockDSIGN k

      | otherwise
      = Nothing

    rawDeserialiseSigDSIGN bs
      | [hb, kb] <- splitsAt [4, 8] bs
      , Just h   <- hashFromBytes hb
      , let k = readBinaryWord64 kb
      = Just $! SigMockDSIGN h k

      | otherwise
      = Nothing


instance ToCBOR (VerKeyDSIGN MockDSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN MockDSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN MockDSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr

instance FromCBOR (SignKeyDSIGN MockDSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN MockDSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN MockDSIGN) where
  fromCBOR = decodeSigDSIGN


-- | Debugging: provide information about the verification failure
--
-- We don't include the actual value here as that would require propagating a
-- 'Show' constraint.
data VerificationFailure
  = MockVerificationFailure
      { vErrVerKey :: VerKeyDSIGN MockDSIGN
      , vErrSignature :: SigDSIGN MockDSIGN
      , vErrCallStack :: String
      }
  deriving Show

mockSign :: ToCBOR a => a -> SignKeyDSIGN MockDSIGN -> SigDSIGN MockDSIGN
mockSign a (SignKeyMockDSIGN n) = SigMockDSIGN (castHash (hash a)) n

mockSigned :: ToCBOR a => a -> SignKeyDSIGN MockDSIGN -> SignedDSIGN MockDSIGN a
mockSigned a k = SignedDSIGN (mockSign a k)

-- | Get the id of the signer from a signature. Used for testing.
verKeyIdFromSigned :: SignedDSIGN MockDSIGN a -> Word64
verKeyIdFromSigned (SignedDSIGN (SigMockDSIGN _ i)) = i
