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

import Cardano.Binary (FromCBOR, ToCBOR (..))
import Cardano.Crypto.Hash
import Cardano.Crypto.Util (nonNegIntR)
import Cardano.Crypto.VRF.Class
import Cardano.Prelude (NoUnexpectedThunks)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import Numeric.Natural (Natural)

data MockVRF

instance VRFAlgorithm MockVRF where

  type Signable MockVRF = ToCBOR

  newtype VerKeyVRF MockVRF = VerKeyMockVRF Int
    deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)
  newtype SignKeyVRF MockVRF = SignKeyMockVRF Int
    deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)
  newtype CertVRF MockVRF = CertMockVRF Int
    deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  maxVRF _ = 2 ^ (8 * byteCount (Proxy :: Proxy MD5)) - 1
  genKeyVRF = SignKeyMockVRF <$> nonNegIntR
  deriveVerKeyVRF (SignKeyMockVRF n) = VerKeyMockVRF n
  encodeVerKeyVRF = toCBOR
  evalVRF a sk = return $ evalVRF' a sk
  verifyVRF (VerKeyMockVRF n) a c = evalVRF' a (SignKeyMockVRF n) == c

evalVRF' :: ToCBOR a => a -> SignKeyVRF MockVRF -> (Natural, CertVRF MockVRF)
evalVRF' a sk@(SignKeyMockVRF n) =
  let y = fromHash $ hashWithSerialiser @MD5 id $ toCBOR a <> toCBOR sk
  in (y, CertMockVRF n)
