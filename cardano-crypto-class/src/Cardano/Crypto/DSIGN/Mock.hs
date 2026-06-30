{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Mock implementation of digital signatures.
module Cardano.Crypto.DSIGN.Mock (
  MockDSIGN,
  SignKeyDSIGN (..),
  VerKeyDSIGN (..),
  SigDSIGN (..),
  mockSign,
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import Control.DeepSeq (NFData)
import Data.Proxy (Proxy (..))
import Data.Word (Word64)
import GHC.Generics (Generic)
import GHC.Stack
import GHC.TypeLits (type (+))
import NoThunks.Class (NoThunks)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.Util
import qualified Data.ByteString as BS

data MockDSIGN

instance DSIGNAlgorithm MockDSIGN where
  type SeedSizeDSIGN MockDSIGN = 8

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN MockDSIGN = VerKeyMockDSIGN Word64
    deriving stock (Show, Eq, Generic)
    deriving newtype (Num, NoThunks, NFData)

  newtype SignKeyDSIGN MockDSIGN = SignKeyMockDSIGN Word64
    deriving stock (Show, Eq, Generic)
    deriving newtype (Num, NoThunks, NFData)

  data SigDSIGN MockDSIGN = SigMockDSIGN !(Hash ShortHash ()) !Word64
    deriving stock (Show, Eq, Ord, Generic)
    deriving anyclass (NoThunks, NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "mock"

  deriveVerKeyDSIGN (SignKeyMockDSIGN n) = VerKeyMockDSIGN n

  --
  -- Core algorithm operations
  --

  type Signable MockDSIGN = SignableRepresentation

  signDSIGN () a sk = mockSign a sk

  verifyDSIGN () (VerKeyMockDSIGN n) a s =
    if s == mockSign a (SignKeyMockDSIGN n)
      then Right ()
      else
        Left $
          show $
            MockVerificationFailure
              { vErrVerKey = VerKeyMockDSIGN n
              , vErrSignature = s
              , vErrCallStack = prettyCallStack callStack
              }

  --
  -- Key generation
  --

  genKeyDSIGN seed =
    SignKeyMockDSIGN (runMonadRandomWithSeed seed getRandomWord64)

instance FixedSizeCodec (VerKeyDSIGN MockDSIGN) where
  type FixedSize (VerKeyDSIGN MockDSIGN) = 8 -- for 64 bit int
  rawEncodeFixedSized (VerKeyMockDSIGN k) = writeBinaryWord64 k
  rawDecodeFixedSized bs = do
    guardFixedSized (Proxy @(VerKeyDSIGN MockDSIGN)) bs
    pure $! VerKeyMockDSIGN (readBinaryWord64 bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN MockDSIGN) where
  type FixedSize (SignKeyDSIGN MockDSIGN) = 8
  rawEncodeFixedSized (SignKeyMockDSIGN k) = writeBinaryWord64 k
  rawDecodeFixedSized bs = do
    guardFixedSized (Proxy @(SignKeyDSIGN MockDSIGN)) bs
    pure $! SignKeyMockDSIGN (readBinaryWord64 bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN MockDSIGN) where
  type FixedSize (SigDSIGN MockDSIGN) = HashSize ShortHash + 8
  rawEncodeFixedSized (SigMockDSIGN h k) = hashToBytes h <> writeBinaryWord64 k
  rawDecodeFixedSized bs = do
    guardFixedSized (Proxy @(SigDSIGN MockDSIGN)) bs
    let
      (hb, kb) = BS.splitAt (fromIntegral @Word @Int $ hashSize (Proxy :: Proxy ShortHash)) bs
    h <- hashFromByteStringM hb
    pure $! SigMockDSIGN h (readBinaryWord64 kb)
  {-# INLINE rawDecodeFixedSized #-}

instance ToCBOR (VerKeyDSIGN MockDSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN MockDSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN MockDSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN MockDSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN MockDSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN MockDSIGN) where
  fromCBOR = decodeFixedSized

-- | Debugging: provide information about the verification failure
--
-- We don't include the actual value here as that would require propagating a
-- 'Show' constraint.
data VerificationFailure = MockVerificationFailure
  { vErrVerKey :: VerKeyDSIGN MockDSIGN
  , vErrSignature :: SigDSIGN MockDSIGN
  , vErrCallStack :: String
  }
  deriving (Show)

mockSign ::
  SignableRepresentation a =>
  a ->
  SignKeyDSIGN MockDSIGN ->
  SigDSIGN MockDSIGN
mockSign a (SignKeyMockDSIGN n) =
  SigMockDSIGN (castHash (hashWith getSignableRepresentation a)) n
