{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementations of verifiable random functions.
module Cardano.Crypto.VRF.Mock
  ( MockVRF
  , VerKeyVRF (..)
  , SignKeyVRF (..)
  )
where

import Cardano.Binary (FromCBOR, ToCBOR (..), FromCBOR(..))
import Cardano.Crypto.Hash
import Cardano.Crypto.Util (mockNonNegIntR)
import Cardano.Crypto.Seed
import Cardano.Crypto.VRF.Class
import Cardano.Prelude (NoUnexpectedThunks)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import Numeric.Natural (Natural)

data MockVRF

instance VRFAlgorithm MockVRF where

  --
  -- Key and signature types
  --

  newtype VerKeyVRF MockVRF = VerKeyMockVRF Int
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  newtype SignKeyVRF MockVRF = SignKeyMockVRF Int
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  newtype CertVRF MockVRF = CertMockVRF Int
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF _ = "mock"

  deriveVerKeyVRF (SignKeyMockVRF n) = VerKeyMockVRF n

  --
  -- Core algorithm operations
  --

  type Signable MockVRF = ToCBOR

  evalVRF () a sk = return $ evalVRF' a sk

  verifyVRF () (VerKeyMockVRF n) a c = evalVRF' a (SignKeyMockVRF n) == c

  maxVRF _ = 2 ^ (8 * sizeHash (Proxy :: Proxy MD5)) - 1

  --
  -- Key generation
  --

  seedSizeVRF _  = 8
  genKeyVRF seed = SignKeyMockVRF sk
    where
      sk = runMonadRandomWithSeed seed mockNonNegIntR

  --
  -- CBOR encoding/decoding
  --

  encodeVerKeyVRF  = toCBOR
  decodeVerKeyVRF  = fromCBOR
  encodeSignKeyVRF = toCBOR
  decodeSignKeyVRF = fromCBOR
  encodeCertVRF    = toCBOR
  decodeCertVRF    = fromCBOR


evalVRF' :: ToCBOR a => a -> SignKeyVRF MockVRF -> (Natural, CertVRF MockVRF)
evalVRF' a sk@(SignKeyMockVRF n) =
  let y = fromHash $ hashWithSerialiser @MD5 id $ toCBOR a <> toCBOR sk
  in (y, CertMockVRF n)
