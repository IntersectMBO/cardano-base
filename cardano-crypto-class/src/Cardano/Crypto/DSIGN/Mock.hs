{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ConstraintKinds #-}
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

import Cardano.Binary
  ( FromCBOR (..)
  , ToCBOR (..)
  , decodeListLenOf
  , encodeListLen
  )
import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed
import Cardano.Crypto.Hash
import Cardano.Crypto.Util (nonNegIntR)
import Cardano.Prelude (NoUnexpectedThunks, Proxy(..))
import GHC.Generics (Generic)
import GHC.Stack

data MockDSIGN

instance DSIGNAlgorithm MockDSIGN where

    --
    -- Key and signature types
    --

    newtype VerKeyDSIGN MockDSIGN = VerKeyMockDSIGN Int
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (Num, ToCBOR, FromCBOR, NoUnexpectedThunks)

    newtype SignKeyDSIGN MockDSIGN = SignKeyMockDSIGN Int
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (Num, ToCBOR, FromCBOR, NoUnexpectedThunks)

    data SigDSIGN MockDSIGN = SigMockDSIGN !ByteString !Int
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    --
    -- Metadata and basic key operations
    --

    deriveVerKeyDSIGN (SignKeyMockDSIGN n) = VerKeyMockDSIGN n

    abstractSizeVKey _ = 8 -- for 64 bit Int
    abstractSizeSig  _ = 1
                       + (byteCount (Proxy :: Proxy ShortHash))
                       + 8 -- length tag + length
                           -- short hash + 64 bit
                           -- Int

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

    seedSizeDSIGN _    = 4
    genKeyDSIGN seed   =
      SignKeyMockDSIGN (runMonadRandomWithSeed seed nonNegIntR)

    --
    -- CBOR encoding/decoding
    --

    encodeVerKeyDSIGN  = toCBOR
    encodeSignKeyDSIGN = toCBOR
    encodeSigDSIGN     = toCBOR

    decodeVerKeyDSIGN  = fromCBOR
    decodeSignKeyDSIGN = fromCBOR
    decodeSigDSIGN     = fromCBOR


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
mockSign a (SignKeyMockDSIGN n) = SigMockDSIGN (getHash $ hash @ShortHash a) n

mockSigned :: ToCBOR a => a -> SignKeyDSIGN MockDSIGN -> SignedDSIGN MockDSIGN a
mockSigned a k = SignedDSIGN (mockSign a k)

instance ToCBOR (SigDSIGN MockDSIGN) where
  toCBOR (SigMockDSIGN b i) = encodeListLen 2 <> toCBOR b <> toCBOR i

instance FromCBOR (SigDSIGN MockDSIGN) where
  fromCBOR = SigMockDSIGN <$ decodeListLenOf 2 <*> fromCBOR <*> fromCBOR

-- | Get the id of the signer from a signature. Used for testing.
verKeyIdFromSigned :: SignedDSIGN MockDSIGN a -> Int
verKeyIdFromSigned (SignedDSIGN (SigMockDSIGN _ i)) = i
