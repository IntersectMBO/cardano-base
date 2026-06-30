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
{-# LANGUAGE UndecidableInstances #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Mock (
  MockKES,
  VerKeyKES (..),
  SignKeyKES (..),
  UnsoundPureSignKeyKES (..),
  SigKES (..),
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import qualified Data.ByteString.Internal as BS
import Data.Proxy (Proxy (..))
import Data.Word (Word64)
import Foreign.Ptr (castPtr)
import GHC.Generics (Generic)
import GHC.TypeNats (KnownNat, Nat)
import NoThunks.Class (NoThunks)

import Control.DeepSeq (NFData)
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
import qualified Data.ByteString as BS
import Foreign.C.Types (CSize)

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
    deriving newtype (NFData, NoThunks)

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

  type TotalPeriodsKES (MockKES t) = t

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

instance KnownNat t => UnsoundKESAlgorithm (MockKES t) where
  rawSerialiseSignKeyKES sk =
    return $ rawEncodeFixedSized sk

  rawDeserialiseSignKeyKESWith _alloc bs =
    return $ rawDecodeFixedSized bs

instance KnownNat t => FixedSizeCodec (SignKeyKES (MockKES t)) where
  type FixedSize (SignKeyKES (MockKES t)) = 16
  rawEncodeFixedSized (SignKeyMockKES vk t) =
    rawEncodeFixedSized vk
      <> writeBinaryWord64 (fromIntegral @Period @Word64 t)
  rawDecodeFixedSized bs = do
    guardFixedSized (Proxy @(SignKeyKES (MockKES t))) bs
    let (vkb, tb) = BS.splitAt 8 bs
    vk <- case rawDecodeFixedSized vkb of
      Just x -> pure x
      Nothing -> fail "rawDeserialiseSignKeyMockKES: Failed to deserialise VerKeyKES"
    let t = fromIntegral @Word64 @Period (readBinaryWord64 tb)
    pure $! SignKeyMockKES vk t

instance KnownNat t => FixedSizeCodec (VerKeyKES (MockKES t)) where
  type FixedSize (VerKeyKES (MockKES t)) = 8
  rawEncodeFixedSized (VerKeyMockKES vk) =
    writeBinaryWord64 vk
  rawDecodeFixedSized bs = do
    guardFixedSized (Proxy @(VerKeyKES (MockKES t))) bs
    let vk = readBinaryWord64 bs
    return $! VerKeyMockKES vk
  {-# INLINE rawDecodeFixedSized #-}

instance KnownNat t => FixedSizeCodec (SigKES (MockKES t)) where
  type FixedSize (SigKES (MockKES t)) = 24
  rawEncodeFixedSized (SigMockKES h sk) =
    hashToBytes h
      <> rawEncodeFixedSized sk
  rawDecodeFixedSized bs = do
    guardFixedSized (Proxy @(SigKES (MockKES t))) bs
    let (hb, skb) = BS.splitAt 8 bs
    h <- case hashFromBytes hb of
      Just x -> pure x
      Nothing -> fail "SigKES (MockKES t): Failed to decode hash"
    sk <- rawDecodeFixedSized skb
    return $! SigMockKES h sk
  {-# INLINE rawDecodeFixedSized #-}

instance KnownNat t => FixedSizeCodec (UnsoundPureSignKeyKES (MockKES t)) where
  type FixedSize (UnsoundPureSignKeyKES (MockKES t)) = FixedSize (SignKeyKES (MockKES t))
  rawEncodeFixedSized (UnsoundPureSignKeyMockKES vk t) =
    rawEncodeFixedSized (SignKeyMockKES vk t)
  rawDecodeFixedSized bs = do
    SignKeyMockKES vt t <- rawDecodeFixedSized bs
    return $! UnsoundPureSignKeyMockKES vt t
  {-# INLINE rawDecodeFixedSized #-}

instance KnownNat t => ToCBOR (VerKeyKES (MockKES t)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance KnownNat t => FromCBOR (VerKeyKES (MockKES t)) where
  fromCBOR = decodeFixedSized

instance KnownNat t => ToCBOR (SigKES (MockKES t)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance KnownNat t => FromCBOR (SigKES (MockKES t)) where
  fromCBOR = decodeFixedSized

instance KnownNat t => ToCBOR (UnsoundPureSignKeyKES (MockKES t)) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size _skProxy = encodedSignKeyKESSizeExpr (Proxy :: Proxy (SignKeyKES (MockKES t)))

instance KnownNat t => FromCBOR (UnsoundPureSignKeyKES (MockKES t)) where
  fromCBOR = decodeFixedSized

instance KnownNat t => DirectSerialise (SignKeyKES (MockKES t)) where
  directSerialise put sk = do
    let bs = rawEncodeFixedSized sk
    unpackByteStringCStringLen bs $ \(cstr, len) -> put cstr (fromIntegral @Int @CSize len)

instance KnownNat t => DirectDeserialise (SignKeyKES (MockKES t)) where
  directDeserialise pull = do
    let len = fromIntegral @Word @Int $ signKeySizeKES (Proxy @(MockKES t))
    fptr <- mallocForeignPtrBytes len
    withForeignPtr fptr $ \ptr ->
      pull (castPtr ptr) (fromIntegral @Int @CSize len)
    let bs = BS.fromForeignPtr (unsafeRawForeignPtr fptr) 0 len
    maybe (error "directDeserialise @(SignKeyKES (MockKES t))") return $
      rawDecodeFixedSized bs

instance KnownNat t => DirectSerialise (VerKeyKES (MockKES t)) where
  directSerialise push sk = do
    let bs = rawEncodeFixedSized sk
    unpackByteStringCStringLen bs $ \(cstr, len) -> push cstr (fromIntegral @Int @CSize len)

instance KnownNat t => DirectDeserialise (VerKeyKES (MockKES t)) where
  directDeserialise pull = do
    let len = fromIntegral @Word @Int $ fixedSize (Proxy @(VerKeyKES (MockKES t)))
    fptr <- mallocForeignPtrBytes len
    withForeignPtr fptr $ \ptr ->
      pull (castPtr ptr) (fromIntegral @Int @CSize len)
    let bs = BS.fromForeignPtr (unsafeRawForeignPtr fptr) 0 len
    maybe (error "directDeserialise @(VerKeyKES (MockKES t))") return $
      rawDecodeFixedSized bs
