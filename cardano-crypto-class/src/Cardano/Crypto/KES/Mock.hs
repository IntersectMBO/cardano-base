{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Mock
  ( MockKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..), decodeListLen, encodeListLen)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util (nonNegIntR)
import GHC.Generics (Generic)
import Numeric.Natural (Natural)

data MockKES

type H = MD5

instance KESAlgorithm MockKES where

    newtype VerKeyKES MockKES = VerKeyMockKES Int
        deriving (Show, Eq, Ord, Generic, ToCBOR, FromCBOR)

    newtype SignKeyKES MockKES = SignKeyMockKES (VerKeyKES MockKES, Natural, Natural)
        deriving (Show, Eq, Ord, Generic, ToCBOR, FromCBOR)

    data SigKES MockKES = SigMockKES Natural (SignKeyKES MockKES)
        deriving (Show, Eq, Ord, Generic)

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR

    genKeyKES duration = do
        vk <- VerKeyMockKES <$> nonNegIntR
        return $ SignKeyMockKES (vk, 0, duration)

    deriveVerKeyKES (SignKeyMockKES (vk, _, _)) = vk

    signKES toEnc j a (SignKeyMockKES (vk, k, t))
        | j >= k && j < t = return $ Just
            ( SigMockKES (fromHash $ hashWithSerialiser @H toEnc a) (SignKeyMockKES (vk, j, t))
            , SignKeyMockKES (vk, j + 1, t)
            )
        | otherwise       = return Nothing

    verifyKES toEnc vk j a (SigMockKES h (SignKeyMockKES (vk', j', _))) =
        if    j  == j'
           && vk == vk'
           && fromHash (hashWithSerialiser @H toEnc a) == h
          then Right ()
          else Left "KES verification failed"

instance ToCBOR (SigKES MockKES) where
  toCBOR (SigMockKES evolution key) =
    encodeListLen 2 <>
      toCBOR evolution <>
      toCBOR key

instance FromCBOR (SigKES MockKES) where
  fromCBOR =
    SigMockKES <$
      decodeListLen <*>
      fromCBOR <*>
      fromCBOR
