{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE TypeApplications #-}
-- Needed to ensure that our hash is the right size
{-# OPTIONS_GHC -Wno-redundant-constraints #-}
-- According to the documentation for unsafePerformIO:
-- 
-- > Make sure that the either you switch off let-floating 
-- > (-fno-full-laziness), or that the call to unsafePerformIO cannot float 
-- > outside a lambda.
--
-- If we do not switch off let-floating, our calls to unsafeDupablePerformIO for
-- FFI functions become nondeterministic in their behaviour when run with
-- parallelism enabled (such as -with-rtsopts=-N), possibly yielding wrong
-- answers on a range of tasks, including serialization.
{-# OPTIONS_GHC -fno-full-laziness #-}

module Cardano.Crypto.DSIGN.EcdsaSecp256k1 (
  MessageHash,
  toMessageHash,
  fromMessageHash,
  hashAndPack,
  EcdsaSecp256k1DSIGN,
  VerKeyDSIGN (..),
  SignKeyDSIGN (..),
  SigDSIGN (..)
  ) where

import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Storable (poke, peek)
import Foreign.C.Types (CSize)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (castPtr, nullPtr, Ptr)
import Control.Monad (when, void, unless)
import Cardano.Crypto.Hash.Class (HashAlgorithm (SizeHash, digest))
import Data.Proxy (Proxy)
import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (toCBOR, encodedSizeExpr))
import Data.ByteString (ByteString)
import Crypto.Random (getRandomBytes)
import Cardano.Crypto.Seed (runMonadRandomWithSeed)
import Data.Kind (Type)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import NoThunks.Class (NoThunks)
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (VerKeyDSIGN, 
                  SignKeyDSIGN, 
                  SigDSIGN,
                  SeedSizeDSIGN, 
                  SizeSigDSIGN, 
                  SizeSignKeyDSIGN, 
                  SizeVerKeyDSIGN, 
                  algorithmNameDSIGN,
                  deriveVerKeyDSIGN, 
                  signDSIGN, 
                  verifyDSIGN, 
                  genKeyDSIGN, 
                  rawSerialiseSigDSIGN,
                  Signable, 
                  rawSerialiseVerKeyDSIGN, 
                  rawSerialiseSignKeyDSIGN, 
                  rawDeserialiseVerKeyDSIGN,
                  rawDeserialiseSignKeyDSIGN, 
                  rawDeserialiseSigDSIGN), 
  encodeVerKeyDSIGN, 
  encodedVerKeyDSIGNSizeExpr, 
  decodeVerKeyDSIGN, 
  encodeSignKeyDSIGN, 
  encodedSignKeyDESIGNSizeExpr, 
  decodeSignKeyDSIGN, 
  encodeSigDSIGN, 
  encodedSigDSIGNSizeExpr, 
  decodeSigDSIGN
  )
import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_ECDSA_PRIVKEY_BYTES,
  SECP256K1_ECDSA_SIGNATURE_BYTES,
  SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL,
  SECP256K1_ECDSA_PUBKEY_BYTES,
  SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL,
  )
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbUseAsSizedPtr,
  psbCreateSized,
  psbFromByteStringCheck,
  psbToByteString,
  psbCreateLen,
  psbCreateSizedResult,
  psbUseAsCPtrLen,
  )
import System.IO.Unsafe (unsafeDupablePerformIO)
import Cardano.Crypto.SECP256K1.C (
  secpEcPubkeyCreate,
  secpCtxPtr,
  secpEcdsaSign,
  secpEcdsaVerify,
  secpEcdsaSignatureSerializeCompact,
  secpEcPubkeySerialize,
  secpEcCompressed,
  secpEcdsaSignatureParseCompact,
  secpEcPubkeyParse,
  )

-- | As ECDSA signatures on the SECP256k1 curve sign 32-byte hashes, rather than
-- whole messages, we provide a helper (opaque) newtype to ensure that the size
-- of the input for signing and verification is strictly bounded.
newtype MessageHash = MH (PinnedSizedBytes 32)
  deriving Eq via (PinnedSizedBytes 32)
  deriving stock Show

-- | Take a blob of bytes (which is presumed to be a 32-byte hash), verify its
-- length, and package it into a 'MessageHash' if that length is exactly 32.
toMessageHash :: ByteString -> Maybe MessageHash
toMessageHash bs = MH <$> psbFromByteStringCheck bs

-- | Turn a 'MessageHash' into its bytes without a length marker.
fromMessageHash :: MessageHash -> ByteString
fromMessageHash (MH psb) = psbToByteString psb

-- | A helper to use with the 'HashAlgorithm' API, as this can ensure sizing.
hashAndPack :: forall (h :: Type) . 
  (HashAlgorithm h, SizeHash h ~ 32) => 
  Proxy h -> ByteString -> MessageHash
hashAndPack p bs = case psbFromByteStringCheck . digest p $ bs of 
  Nothing -> error $ "hashAndPack: unexpected mismatch of guaranteed hash length\n" <>
                     "Please report this, it's a bug!"
  Just psb -> MH psb

data EcdsaSecp256k1DSIGN

instance DSIGNAlgorithm EcdsaSecp256k1DSIGN where
    type SeedSizeDSIGN EcdsaSecp256k1DSIGN = SECP256K1_ECDSA_PRIVKEY_BYTES
    type SizeSigDSIGN EcdsaSecp256k1DSIGN = SECP256K1_ECDSA_SIGNATURE_BYTES
    type SizeSignKeyDSIGN EcdsaSecp256k1DSIGN = SECP256K1_ECDSA_PRIVKEY_BYTES
    type SizeVerKeyDSIGN EcdsaSecp256k1DSIGN = SECP256K1_ECDSA_PUBKEY_BYTES
    type Signable EcdsaSecp256k1DSIGN = ((~) MessageHash)
    newtype VerKeyDSIGN EcdsaSecp256k1DSIGN = 
      VerKeyEcdsaSecp256k1 (PinnedSizedBytes SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL)
      deriving newtype (Eq, NFData)
      deriving stock (Show, Generic)
      deriving anyclass (NoThunks)
    newtype SignKeyDSIGN EcdsaSecp256k1DSIGN = 
      SignKeyEcdsaSecp256k1 (PinnedSizedBytes SECP256K1_ECDSA_PRIVKEY_BYTES)
      deriving newtype (Eq, NFData)
      deriving stock (Show, Generic)
      deriving anyclass (NoThunks)
    newtype SigDSIGN EcdsaSecp256k1DSIGN = 
      SigEcdsaSecp256k1 (PinnedSizedBytes SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL)
      deriving newtype (Eq, NFData)
      deriving stock (Show, Generic)
      deriving anyclass (NoThunks)
    algorithmNameDSIGN _ = "ecdsa-secp256k1"
    {-# NOINLINE deriveVerKeyDSIGN #-}
    deriveVerKeyDSIGN (SignKeyEcdsaSecp256k1 skBytes) = 
      VerKeyEcdsaSecp256k1 <$> unsafeDupablePerformIO . psbUseAsSizedPtr skBytes $ 
        \skp -> psbCreateSized $ \vkp -> 
          withForeignPtr secpCtxPtr $ \ctx -> do
            res <- secpEcPubkeyCreate ctx vkp skp
            when (res /= 1) 
                 (error "deriveVerKeyDSIGN: Failed to derive VerKeyDSIGN EcdsaSecp256k1DSIGN")
    {-# NOINLINE signDSIGN #-}
    signDSIGN () (MH psb) (SignKeyEcdsaSecp256k1 skBytes) = 
      SigEcdsaSecp256k1 <$> unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \psp -> do
        psbUseAsSizedPtr skBytes $ \skp ->
          psbCreateSized $ \sigp -> 
            withForeignPtr secpCtxPtr $ \ctx -> do
              -- The two nullPtr arguments correspond to nonces and extra nonce
              -- data. We use neither, so we pass nullPtrs to indicate this to the
              -- C API.
              res <- secpEcdsaSign ctx sigp psp skp nullPtr nullPtr
              when (res /= 1) 
                   (error "signDSIGN: Failed to sign EcdsaSecp256k1DSIGN message")
    {-# NOINLINE verifyDSIGN #-}
    verifyDSIGN () (VerKeyEcdsaSecp256k1 vkBytes) (MH psb) (SigEcdsaSecp256k1 sigBytes) = 
      unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \psp -> do
        psbUseAsSizedPtr sigBytes $ \sigp -> 
          psbUseAsSizedPtr vkBytes $ \vkp -> 
            withForeignPtr secpCtxPtr $ \ctx -> do
              let res = secpEcdsaVerify ctx sigp psp vkp
              pure $ case res of 
                0 -> Left "verifyDSIGN: Incorrect or unparseable SigDSIGN EcdsaSecp256k1DSIGN"
                _ -> Right ()
    genKeyDSIGN seed = runMonadRandomWithSeed seed $ do
      bs <- getRandomBytes 32
      case psbFromByteStringCheck bs of 
        Nothing -> error "genKeyDSIGN: Failed to generate SignKeyDSIGN EcdsaSecp256k1DSIGN unexpectedly"
        Just psb -> pure $ SignKeyEcdsaSecp256k1 psb
    {-# NOINLINE rawSerialiseSigDSIGN #-}
    rawSerialiseSigDSIGN (SigEcdsaSecp256k1 psb) = 
      psbToByteString @SECP256K1_ECDSA_SIGNATURE_BYTES . unsafeDupablePerformIO $ do
        psbUseAsSizedPtr psb $ \psp -> 
          psbCreateSized $ \dstp ->
            withForeignPtr secpCtxPtr $ \ctx -> 
              void $ secpEcdsaSignatureSerializeCompact ctx dstp psp
    {-# NOINLINE rawSerialiseVerKeyDSIGN #-}
    rawSerialiseVerKeyDSIGN (VerKeyEcdsaSecp256k1 psb) = 
      psbToByteString . unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \psp ->
        psbCreateLen @SECP256K1_ECDSA_PUBKEY_BYTES $ \ptr len -> do
          let dstp = castPtr ptr
          -- This is necessary because of how the C API handles checking writes:
          -- maximum permissible length is given as a pointer, which is
          -- overwritten to indicate the number of bytes we actually wrote; if
          -- we get a mismatch, then the serialization failed. While an odd
          -- choice, we have to go with it.
          alloca $ \(lenPtr :: Ptr CSize) -> do
            poke lenPtr len
            withForeignPtr secpCtxPtr $ \ctx -> do
              void $ secpEcPubkeySerialize ctx dstp lenPtr psp secpEcCompressed
              writtenLen <- peek lenPtr
              unless (writtenLen == len) 
                     (error "rawSerializeVerKeyDSIGN: Did not write correct length for VerKeyDSIGN EcdsaSecp256k1DSIGN")
    rawSerialiseSignKeyDSIGN (SignKeyEcdsaSecp256k1 psb) = psbToByteString psb
    {-# NOINLINE rawDeserialiseSigDSIGN #-}
    rawDeserialiseSigDSIGN bs = 
      SigEcdsaSecp256k1 <$> (psbFromByteStringCheck bs >>= go)
      where
        go :: 
          PinnedSizedBytes SECP256K1_ECDSA_SIGNATURE_BYTES -> 
          Maybe (PinnedSizedBytes SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL)
        go psb = unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \psp -> do
          (sigPsb, res) <- psbCreateSizedResult $ \sigp ->
            withForeignPtr secpCtxPtr $ \ctx -> 
              secpEcdsaSignatureParseCompact ctx sigp psp
          pure $ case res of 
            1 -> pure sigPsb
            _ -> Nothing
    {-# NOINLINE rawDeserialiseVerKeyDSIGN #-}
    rawDeserialiseVerKeyDSIGN bs = 
      VerKeyEcdsaSecp256k1 <$> (psbFromByteStringCheck bs >>= go)
      where
        go :: 
          PinnedSizedBytes SECP256K1_ECDSA_PUBKEY_BYTES -> 
          Maybe (PinnedSizedBytes SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL)
        go psb = unsafeDupablePerformIO . psbUseAsCPtrLen psb $ \p srcLen -> do
          let srcp = castPtr p
          (vkPsb, res) <- psbCreateSizedResult $ \vkp ->
            withForeignPtr secpCtxPtr $ \ctx -> 
              secpEcPubkeyParse ctx vkp srcp srcLen
          pure $ case res of 
            1 -> pure vkPsb
            _ -> Nothing
    rawDeserialiseSignKeyDSIGN bs = 
      SignKeyEcdsaSecp256k1 <$> psbFromByteStringCheck bs

instance ToCBOR (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
    toCBOR = encodeVerKeyDSIGN
    encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
    fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
    toCBOR = encodeSignKeyDSIGN
    encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr

instance FromCBOR (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
    fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN EcdsaSecp256k1DSIGN) where
    toCBOR = encodeSigDSIGN
    encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN EcdsaSecp256k1DSIGN) where
    fromCBOR = decodeSigDSIGN
