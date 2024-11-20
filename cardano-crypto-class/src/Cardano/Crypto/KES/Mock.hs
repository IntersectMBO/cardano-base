{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Mock (
  MockKES,
  VerKeyKES (..),
  SignKeyKES (..),
  UnsoundPureSignKeyKES (..),
  SigKES (..),
)
where

import qualified Data.ByteString.Internal as BS
import Data.Proxy (Proxy (..))
import Data.Word (Word64)
import Foreign.Ptr (castPtr)
import GHC.Generics (Generic)
import GHC.TypeNats (KnownNat, Nat, natVal)
import NoThunks.Class (NoThunks)

import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.Hash
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Libsodium (
  mlsbToByteString,
 )
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Libsodium.Memory (
  ForeignPtr (..),
  mallocForeignPtrBytes,
  unpackByteStringCStringLen,
  withForeignPtr,
 )
import Cardano.Crypto.Seed
import Cardano.Crypto.Util

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
    deriving stock (Show, Eq, Generic)
    deriving newtype (NoThunks)

  data SigKES (MockKES t)
    = SigMockKES !(Hash ShortHash ()) !(SignKeyKES (MockKES t))
    deriving stock (Show, Eq, Generic)
    deriving anyclass (NoThunks)

  data SignKeyKES (MockKES t)
    = SignKeyMockKES !(VerKeyKES (MockKES t)) !Period
    deriving stock (Show, Eq, Generic)
    deriving anyclass (NoThunks)

  --
  -- Metadata and basic key operations
  --

  algorithmNameKES proxy = "mock_" ++ show (totalPeriodsKES proxy)

  type SizeVerKeyKES (MockKES t) = 8
  type SizeSignKeyKES (MockKES t) = 16
  type SizeSigKES (MockKES t) = 24

  --
  -- Core algorithm operations
  --

  type Signable (MockKES t) = SignableRepresentation

  verifyKES () vk t a (SigMockKES h (SignKeyMockKES vk' t'))
    | vk /= vk' =
        Left "KES verification failed"
    | t' == t
    , castHash (hashWith getSignableRepresentation a) == h =
        Right ()
    | otherwise =
        Left "KES verification failed"

  totalPeriodsKES _ = fromIntegral (natVal (Proxy @t))

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
    , let vk = readBinaryWord64 vkb =
        Just $! VerKeyMockKES vk
    | otherwise =
        Nothing

  rawDeserialiseSigKES bs
    | [hb, skb] <- splitsAt [8, 16] bs
    , Just h <- hashFromBytes hb
    , Just sk <- rawDeserialiseSignKeyMockKES skb =
        Just $! SigMockKES h sk
    | otherwise =
        Nothing

  deriveVerKeyKES (SignKeyMockKES vk _) = return $! vk

  updateKESWith _allocator () (SignKeyMockKES vk t') t =
    assert (t == t') $!
      if t + 1 < totalPeriodsKES (Proxy @(MockKES t))
        then return $! Just $! SignKeyMockKES vk (t + 1)
        else return Nothing

  -- \| Produce valid signature only with correct key, i.e., same iteration and
  -- allowed KES period.
  signKES () t a (SignKeyMockKES vk t') =
    assert (t == t') $!
      return $!
        SigMockKES
          (castHash (hashWith getSignableRepresentation a))
          (SignKeyMockKES vk t)

  --
  -- Key generation
  --

  genKeyKESWith _allocator seed = do
    seedBS <- mlsbToByteString $ mlockedSeedMLSB seed
    let vk = VerKeyMockKES (runMonadRandomWithSeed (mkSeedFromBytes seedBS) getRandomWord64)
    return $! SignKeyMockKES vk 0

  forgetSignKeyKESWith _ = const $ return ()

instance KnownNat t => UnsoundPureKESAlgorithm (MockKES t) where
  --
  -- Key and signature types
  --

  data UnsoundPureSignKeyKES (MockKES t)
    = UnsoundPureSignKeyMockKES !(VerKeyKES (MockKES t)) !Period
    deriving stock (Show, Eq, Generic)
    deriving anyclass (NoThunks)

  unsoundPureDeriveVerKeyKES (UnsoundPureSignKeyMockKES vk _) = vk

  unsoundPureUpdateKES () (UnsoundPureSignKeyMockKES vk t') t =
    assert (t == t') $!
      if t + 1 < totalPeriodsKES (Proxy @(MockKES t))
        then Just $! UnsoundPureSignKeyMockKES vk (t + 1)
        else Nothing

  -- \| Produce valid signature only with correct key, i.e., same iteration and
  -- allowed KES period.
  unsoundPureSignKES () t a (UnsoundPureSignKeyMockKES vk t') =
    assert (t == t') $!
      SigMockKES
        (castHash (hashWith getSignableRepresentation a))
        (SignKeyMockKES vk t)

  --
  -- Key generation
  --

  unsoundPureGenKeyKES seed =
    let vk = VerKeyMockKES (runMonadRandomWithSeed seed getRandomWord64)
     in UnsoundPureSignKeyMockKES vk 0

  unsoundPureSignKeyKESToSoundSignKeyKES (UnsoundPureSignKeyMockKES vk t) =
    return $ SignKeyMockKES vk t

  rawSerialiseUnsoundPureSignKeyKES (UnsoundPureSignKeyMockKES vk t) =
    rawSerialiseSignKeyMockKES (SignKeyMockKES vk t)

  rawDeserialiseUnsoundPureSignKeyKES bs = do
    SignKeyMockKES vt t <- rawDeserialiseSignKeyMockKES bs
    return $ UnsoundPureSignKeyMockKES vt t

instance KnownNat t => UnsoundKESAlgorithm (MockKES t) where
  rawSerialiseSignKeyKES sk =
    return $ rawSerialiseSignKeyMockKES sk

  rawDeserialiseSignKeyKESWith _alloc bs =
    return $ rawDeserialiseSignKeyMockKES bs

rawDeserialiseSignKeyMockKES ::
  KnownNat t =>
  ByteString ->
  Maybe (SignKeyKES (MockKES t))
rawDeserialiseSignKeyMockKES bs
  | [vkb, tb] <- splitsAt [8, 8] bs
  , Just vk <- rawDeserialiseVerKeyKES vkb
  , let t = fromIntegral (readBinaryWord64 tb) =
      Just $! SignKeyMockKES vk t
  | otherwise =
      Nothing

rawSerialiseSignKeyMockKES ::
  KnownNat t =>
  SignKeyKES (MockKES t) ->
  ByteString
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

instance KnownNat t => ToCBOR (UnsoundPureSignKeyKES (MockKES t)) where
  toCBOR = encodeUnsoundPureSignKeyKES
  encodedSizeExpr _size _skProxy = encodedSignKeyKESSizeExpr (Proxy :: Proxy (SignKeyKES (MockKES t)))

instance KnownNat t => FromCBOR (UnsoundPureSignKeyKES (MockKES t)) where
  fromCBOR = decodeUnsoundPureSignKeyKES

instance KnownNat t => DirectSerialise (SignKeyKES (MockKES t)) where
  directSerialise put sk = do
    let bs = rawSerialiseSignKeyMockKES sk
    unpackByteStringCStringLen bs $ \(cstr, len) -> put cstr (fromIntegral len)

instance KnownNat t => DirectDeserialise (SignKeyKES (MockKES t)) where
  directDeserialise pull = do
    let len = fromIntegral $ sizeSignKeyKES (Proxy @(MockKES t))
    fptr <- mallocForeignPtrBytes len
    withForeignPtr fptr $ \ptr ->
      pull (castPtr ptr) (fromIntegral len)
    let bs = BS.fromForeignPtr (unsafeRawForeignPtr fptr) 0 len
    maybe (error "directDeserialise @(SignKeyKES (MockKES t))") return $
      rawDeserialiseSignKeyMockKES bs

instance KnownNat t => DirectSerialise (VerKeyKES (MockKES t)) where
  directSerialise push sk = do
    let bs = rawSerialiseVerKeyKES sk
    unpackByteStringCStringLen bs $ \(cstr, len) -> push cstr (fromIntegral len)

instance KnownNat t => DirectDeserialise (VerKeyKES (MockKES t)) where
  directDeserialise pull = do
    let len = fromIntegral $ sizeVerKeyKES (Proxy @(MockKES t))
    fptr <- mallocForeignPtrBytes len
    withForeignPtr fptr $ \ptr ->
      pull (castPtr ptr) (fromIntegral len)
    let bs = BS.fromForeignPtr (unsafeRawForeignPtr fptr) 0 len
    maybe (error "directDeserialise @(VerKeyKES (MockKES t))") return $
      rawDeserialiseVerKeyKES bs
