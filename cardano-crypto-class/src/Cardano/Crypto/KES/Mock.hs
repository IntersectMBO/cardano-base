{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
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
import Cardano.Prelude (NoUnexpectedThunks)
import GHC.Generics (Generic)
import Numeric.Natural (Natural)
import Control.Exception (assert)

data MockKES

type H = MD5

-- | Mock key evolving signatures.
--
-- What is the difference between Mock KES and Simple KES
-- (@Cardano.Crypto.KES.Simple@), you may ask? Simple KES satisfies the outward
-- appearance of a KES scheme through assembling a pre-generated list of keys
-- and iterating through them. Mock KES, on the other hand, pretends to be KES
-- but in fact does no key evolution whatsoever.
--
-- Simple KES is appropriate for testing, since it will for example reject old
-- keys. Mock KES is more suitable for a basic testnet, since it doesn't suffer
-- from the performance implications of shuffling a giant list of keys around
instance KESAlgorithm MockKES where

    type Signable MockKES = ToCBOR

    newtype VerKeyKES MockKES = VerKeyMockKES Int
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (NoUnexpectedThunks, ToCBOR, FromCBOR)

    data SignKeyKES MockKES = SignKeyMockKES !(VerKeyKES MockKES) !Natural !Natural
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    data SigKES MockKES = SigMockKES !Natural !(SignKeyKES MockKES)
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR

    genKeyKES duration = do
        vk <- VerKeyMockKES <$> nonNegIntR
        return $ SignKeyMockKES vk 0 duration

    deriveVerKeyKES (SignKeyMockKES vk _ _) = vk

    updateKES () (SignKeyMockKES vk k t) to =
      assert (to >= k) $
         if to < t then (pure $ Just (SignKeyMockKES vk to t))
         else pure Nothing

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () j a (SignKeyMockKES vk k t)
        | j == k && j < t = return $ Just
            ( SigMockKES (fromHash $ hash @H a) (SignKeyMockKES vk j t))
        | otherwise       = return Nothing

    verifyKES () vk j a (SigMockKES h (SignKeyMockKES vk' j' _)) =
        if    j  == j'
           && vk == vk'
           && fromHash (hash @H a) == h
          then Right ()
          else Left "KES verification failed"

    currentPeriodKES () (SignKeyMockKES _ k _) = k

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

instance ToCBOR (SignKeyKES MockKES) where
  toCBOR (SignKeyMockKES vk k t) =
    encodeListLen 3 <>
      toCBOR vk <>
      toCBOR k <>
      toCBOR t

instance FromCBOR (SignKeyKES MockKES) where
  fromCBOR =
    SignKeyMockKES <$
      decodeListLen <*>
      fromCBOR <*>
      fromCBOR <*>
      fromCBOR
