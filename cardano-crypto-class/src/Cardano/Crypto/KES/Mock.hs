{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE StandaloneDeriving #-}

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
import Control.Monad.Class.MonadST (MonadST (..))

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util
import Cardano.Crypto.MLockedSeed
import Cardano.Crypto.MonadMLock
  ( MonadMLock (..)
  , MonadUnmanagedMemory (..)
  , MonadByteStringMemory (..)
  , useByteStringAsCStringLen
  , packByteStringCStringLen
  , mlsbToByteString
  )
import Cardano.Crypto.DirectSerialise

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

    data SigKES (MockKES t) =
           SigMockKES !(Hash ShortHash ()) !(MockSignKeyKES t)
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoThunks)

    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "mock_" ++ show (totalPeriodsKES proxy)

    type SizeVerKeyKES  (MockKES t) = 8
    type SizeSignKeyKES (MockKES t) = 16
    type SizeSigKES     (MockKES t) = 24


    --
    -- Core algorithm operations
    --

    type Signable (MockKES t) = SignableRepresentation

    verifyKES () vk t a (SigMockKES h (MockSignKeyKES vk' t'))
      | vk /= vk'
      = Left "KES verification failed"

      | t' == t
      , castHash (hashWith getSignableRepresentation a) == h
      = Right ()

      | otherwise
      = Left "KES verification failed"

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @t))

    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyKES (VerKeyMockKES vk) =
        writeBinaryWord64 vk

    rawSerialiseSigKES (SigMockKES h sk) =
        hashToBytes h
     <> rawSerialiseSignKeyMockKES (SignKeyMockKES sk)

    rawDeserialiseVerKeyKES bs
      | [vkb] <- splitsAt [8] bs
      , let vk = readBinaryWord64 vkb
      = Just $! VerKeyMockKES vk

      | otherwise
      = Nothing

    rawDeserialiseSigKES bs
      | [hb, skb] <- splitsAt [8, 16] bs
      , Just h    <- hashFromBytes hb
      , Just (SignKeyMockKES sk)   <- rawDeserialiseSignKeyMockKES skb
      = Just $! SigMockKES h sk
      | otherwise
      = Nothing

data MockSignKeyKES t =
       MockSignKeyKES !(VerKeyKES (MockKES t)) !Period
    deriving stock    (Show, Eq, Generic, Ord)
    deriving anyclass (NoThunks)

deriving newtype instance NoThunks (SignKeyKES m (MockKES t))

deriving newtype instance Eq (SignKeyKES m (MockKES t))

instance (MonadST m, MonadMLock m, KnownNat t) => KESSignAlgorithm m (MockKES t) where
    newtype SignKeyKES m (MockKES t) = SignKeyMockKES (MockSignKeyKES t)

    deriveVerKeyKES (SignKeyMockKES (MockSignKeyKES vk _)) = return $! vk

    updateKES () (SignKeyMockKES (MockSignKeyKES vk t')) t =
        assert (t == t') $!
         if t+1 < totalPeriodsKES (Proxy @(MockKES t))
           then return $! Just $! SignKeyMockKES $! MockSignKeyKES vk (t+1)
           else return Nothing

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () t a (SignKeyMockKES (MockSignKeyKES vk t')) =
        assert (t == t') $!
        return $!
        SigMockKES (castHash (hashWith getSignableRepresentation a))
                   (MockSignKeyKES vk t)

    --
    -- Key generation
    --

    genKeyKES seed = do
        pureSeed <- mkSeedFromBytes <$> mlsbToByteString (mlockedSeedMLSB seed)
        let vk = VerKeyMockKES (runMonadRandomWithSeed pureSeed getRandomWord64)
        return $! SignKeyMockKES $! MockSignKeyKES vk 0

    forgetSignKeyKES = const $ return ()

instance (MonadST m, MonadMLock m, KnownNat t) => UnsoundKESSignAlgorithm m (MockKES t) where
    rawSerialiseSignKeyKES sk =
      return $ rawSerialiseSignKeyMockKES sk

    rawDeserialiseSignKeyKES bs =
      return $ rawDeserialiseSignKeyMockKES bs

rawDeserialiseSignKeyMockKES :: KnownNat t
                             => ByteString
                             -> Maybe (SignKeyKES m (MockKES t))
rawDeserialiseSignKeyMockKES bs
    | [vkb, tb] <- splitsAt [8, 8] bs
    , Just vk   <- rawDeserialiseVerKeyKES vkb
    , let t      = fromIntegral (readBinaryWord64 tb)
    = Just $! SignKeyMockKES $! MockSignKeyKES vk t
    | otherwise
    = Nothing

rawSerialiseSignKeyMockKES :: KnownNat t
                           => SignKeyKES m (MockKES t)
                           -> ByteString
rawSerialiseSignKeyMockKES (SignKeyMockKES (MockSignKeyKES vk t)) =
    rawSerialiseVerKeyKES vk
 <> writeBinaryWord64 (fromIntegral t)

instance (MonadByteStringMemory m, KnownNat t) => DirectSerialise m (SignKeyKES m (MockKES t)) where
  directSerialise put sk = do
    let bs = rawSerialiseSignKeyMockKES sk
    useByteStringAsCStringLen bs $ \(cstr, len) -> put cstr (fromIntegral len)

instance (MonadMLock m, MonadST m, KnownNat t) => DirectDeserialise m (SignKeyKES m (MockKES t)) where
  directDeserialise pull = do
    let len = fromIntegral $ sizeSignKeyKES (Proxy @(MockKES t))
    bs <- allocaBytes len $ \cstr -> do
        pull cstr (fromIntegral len)
        packByteStringCStringLen (cstr, len)
    maybe (error "directDeserialise @(SignKeyKES (MockKES t))") return $
        rawDeserialiseSignKeyMockKES bs

instance (MonadByteStringMemory m, KnownNat t) => DirectSerialise m (VerKeyKES (MockKES t)) where
  directSerialise put sk = do
    let bs = rawSerialiseVerKeyKES sk
    useByteStringAsCStringLen bs $ \(cstr, len) -> put cstr (fromIntegral len)

instance (MonadMLock m, MonadST m, KnownNat t) => DirectDeserialise m (VerKeyKES (MockKES t)) where
  directDeserialise pull = do
    let len = fromIntegral $ sizeVerKeyKES (Proxy @(MockKES t))
    bs <- allocaBytes len $ \cstr -> do
        pull cstr (fromIntegral len)
        packByteStringCStringLen (cstr, len)
    maybe (error "directDeserialise @(VerKeyKES (MockKES t))") return $
        rawDeserialiseVerKeyKES bs

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
