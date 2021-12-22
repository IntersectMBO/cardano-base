{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Mock
  ( MockKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import Data.Word (Word64)
import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)
import GHC.TypeNats (Nat, KnownNat, natVal)
import NoThunks.Class (NoThunks)

import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util
import Cardano.Crypto.MonadSodium (mlsbToByteString)

data MockKES (t :: Nat)

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
instance KnownNat t => KESAlgorithm (MockKES t) where
    type SeedSizeKES (MockKES t) = 8

    --
    -- Key and signature types
    --

    newtype VerKeyKES (MockKES t) = VerKeyMockKES Word64
        deriving stock   (Show, Eq, Generic)
        deriving newtype (NoThunks)

    data SignKeyKES (MockKES t) =
           SignKeyMockKES !(VerKeyKES (MockKES t)) !Period
        deriving stock    (Show, Eq, Generic)
        deriving anyclass (NoThunks)

    data SigKES (MockKES t) =
           SigMockKES !(Hash ShortHash ()) !(SignKeyKES (MockKES t))
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoThunks)

    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "mock_" ++ show (totalPeriodsKES proxy)

    sizeVerKeyKES  _ = 8
    sizeSignKeyKES _ = 16
    sizeSigKES     _ = 24


    --
    -- Core algorithm operations
    --

    type Signable (MockKES t) = SignableRepresentation

    verifyKES () vk t a (SigMockKES h (SignKeyMockKES vk' t'))
      | vk /= vk'
      = Left "KES verification failed"

      | t' == t
      , castHash (hashWith getSignableRepresentation a) == h
      = Right ()

      | otherwise
      = Left "KES verification failed"

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @ t))

    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyKES (VerKeyMockKES vk) =
        writeBinaryWord64 vk

    rawSerialiseSigKES (SigMockKES h sk) =
        hashToBytes h
     <> rawSerialiseSignKeyMockKES sk

    rawDeserialiseVerKeyKES bs
      | [vkb] <- splitsAt [8] bs
      , let vk = readBinaryWord64 vkb
      = Just $! VerKeyMockKES vk

      | otherwise
      = Nothing

    rawDeserialiseSigKES bs
      | [hb, skb] <- splitsAt [8, 16] bs
      , Just h    <- hashFromBytes hb
      , Just sk   <- rawDeserialiseSignKeyMockKES skb
      = Just $! SigMockKES h sk
      | otherwise
      = Nothing

instance (Monad m, KnownNat t) => KESSignAlgorithm m (MockKES t) where
    deriveVerKeyKES (SignKeyMockKES vk _) = return vk

    updateKES () (SignKeyMockKES vk t') t =
        assert (t == t') $
         if t+1 < totalPeriodsKES (Proxy @ (MockKES t))
           then return $ Just (SignKeyMockKES vk (t+1))
           else return Nothing

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () t a (SignKeyMockKES vk t') =
        assert (t == t') $
        return $
        SigMockKES (castHash (hashWith getSignableRepresentation a))
                   (SignKeyMockKES vk t)

    --
    -- Key generation
    --

    genKeyKES seed = do
        let vk = VerKeyMockKES (runMonadRandomWithSeed (mkSeedFromBytes $ mlsbToByteString seed) getRandomWord64)
        return $ SignKeyMockKES vk 0

    rawSerialiseSignKeyKES sk =
      return $ rawSerialiseSignKeyMockKES sk

    rawDeserialiseSignKeyKES bs =
      return $ rawDeserialiseSignKeyMockKES bs

rawDeserialiseSignKeyMockKES :: KnownNat t
                             => ByteString
                             -> Maybe (SignKeyKES (MockKES t))
rawDeserialiseSignKeyMockKES bs
    | [vkb, tb] <- splitsAt [8, 8] bs
    , Just vk   <- rawDeserialiseVerKeyKES vkb
    , let t      = fromIntegral (readBinaryWord64 tb)
    = Just $! SignKeyMockKES vk t
    | otherwise
    = Nothing

rawSerialiseSignKeyMockKES :: KnownNat t
                           => SignKeyKES (MockKES t)
                           -> ByteString
rawSerialiseSignKeyMockKES (SignKeyMockKES vk t) =
    rawSerialiseVerKeyKES vk
 <> writeBinaryWord64 (fromIntegral t)

instance KnownNat t => ToCBOR (VerKeyKES (MockKES t)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance KnownNat t => FromCBOR (VerKeyKES (MockKES t)) where
  fromCBOR = decodeVerKeyKES

instance KnownNat t => ToCBOR (SigKES (MockKES t)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance KnownNat t => FromCBOR (SigKES (MockKES t)) where
  fromCBOR = decodeSigKES
