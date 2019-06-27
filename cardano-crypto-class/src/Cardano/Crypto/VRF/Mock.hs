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

import Cardano.Binary (Encoding, FromCBOR, ToCBOR (..))
import Cardano.Crypto.Hash
import Cardano.Crypto.Util (nonNegIntR)
import Cardano.Crypto.VRF.Class
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import Numeric.Natural (Natural)

data MockVRF

instance VRFAlgorithm MockVRF where
  newtype VerKeyVRF MockVRF = VerKeyMockVRF Int
    deriving (Show, Eq, Ord, Generic, ToCBOR, FromCBOR)
  newtype SignKeyVRF MockVRF = SignKeyMockVRF Int
    deriving (Show, Eq, Ord, Generic, ToCBOR, FromCBOR)
  newtype CertVRF MockVRF = CertMockVRF Int
    deriving (Show, Eq, Ord, Generic, ToCBOR, FromCBOR)
  maxVRF _ = 2 ^ (8 * byteCount (Proxy :: Proxy MD5)) - 1
  genKeyVRF = SignKeyMockVRF <$> nonNegIntR
  deriveVerKeyVRF (SignKeyMockVRF n) = VerKeyMockVRF n
  evalVRF toEnc a sk = return $ evalVRF' toEnc a sk
  verifyVRF toEnc (VerKeyMockVRF n) a c = evalVRF' toEnc a (SignKeyMockVRF n) == c

evalVRF' :: (a -> Encoding) -> a -> SignKeyVRF MockVRF -> (Natural, CertVRF MockVRF)
evalVRF' toEnc a sk@(SignKeyMockVRF n) =
  let y = fromHash $ hashWithSerialiser @MD5 id $ toEnc a <> toCBOR sk
  in (y, CertMockVRF n)
