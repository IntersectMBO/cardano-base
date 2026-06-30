{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
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
  SigDSIGN (..),
) where

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
 )
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (
    SeedSizeDSIGN,
    SigDSIGN,
    SignKeyDSIGN,
    Signable,
    VerKeyDSIGN,
    algorithmNameDSIGN,
    deriveVerKeyDSIGN,
    genKeyDSIGN,
    signDSIGN,
    verifyDSIGN
  ),
  encodedSigDSIGNSizeExpr,
  encodedSignKeyDSIGNSizeExpr,
  encodedVerKeyDSIGNSizeExpr,
 )
import Cardano.Crypto.Hash.Class (HashAlgorithm (HashSize, digest))
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreateLen,
  psbCreateSized,
  psbCreateSizedResult,
  psbFromByteStringM,
  psbToByteString,
  psbUseAsCPtrLen,
  psbUseAsSizedPtr,
 )
import Cardano.Crypto.SECP256K1.C (
  secpCtxPtr,
  secpEcCompressed,
  secpEcPubkeyCreate,
  secpEcPubkeyParse,
  secpEcPubkeySerialize,
  secpEcdsaSign,
  secpEcdsaSignatureParseCompact,
  secpEcdsaSignatureSerializeCompact,
  secpEcdsaVerify,
 )
import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_ECDSA_MESSAGE_BYTES,
  SECP256K1_ECDSA_PRIVKEY_BYTES,
  SECP256K1_ECDSA_PUBKEY_BYTES,
  SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL,
  SECP256K1_ECDSA_SIGNATURE_BYTES,
  SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL,
 )
import Cardano.Crypto.Seed (runMonadRandomWithSeed)
import Control.DeepSeq (NFData)
import Control.Monad (unless, void, when)
import Crypto.Random (getRandomBytes)
import Data.ByteString (ByteString)
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Foreign.C.Types (CSize)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek, poke)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | As ECDSA signatures on the SECP256k1 curve sign 32-byte hashes, rather than
-- whole messages, we provide a helper (opaque) newtype to ensure that the size
-- of the input for signing and verification is strictly bounded.
--
-- = Important note
--
-- If you are verifying a message using the algorithm provided here, you should
-- hash the message yourself before verifying. Specifically, the sender should
-- give you the message itself to verify, rather than the hash of the message
-- used to compute the signature.
newtype MessageHash = MH (PinnedSizedBytes SECP256K1_ECDSA_MESSAGE_BYTES)
  deriving (Eq) via (PinnedSizedBytes SECP256K1_ECDSA_MESSAGE_BYTES)
  deriving stock (Show)
  deriving newtype (ToCBOR, FromCBOR)

instance FixedSizeCodec MessageHash where
  type FixedSize MessageHash = SECP256K1_ECDSA_MESSAGE_BYTES
  rawEncodeFixedSized (MH psb) = rawEncodeFixedSized psb
  rawDecodeFixedSized bs = MH <$> rawDecodeFixedSized bs

-- | Take a blob of bytes (which is presumed to be a 32-byte hash), verify its
-- length, and package it into a 'MessageHash' if that length is exactly 32.
toMessageHash :: ByteString -> Maybe MessageHash
toMessageHash = rawDecodeFixedSized
{-# DEPRECATED toMessageHash "Use `rawDecodeFixedSized` instead" #-}

-- | Turn a 'MessageHash' into its bytes without a length marker.
fromMessageHash :: MessageHash -> ByteString
fromMessageHash = rawEncodeFixedSized
{-# DEPRECATED fromMessageHash "Use rawEncodeFixedSized instead" #-}

-- | A helper to use with the 'HashAlgorithm' API, as this can ensure sizing.
hashAndPack ::
  forall (h :: Type).
  (HashAlgorithm h, HashSize h ~ SECP256K1_ECDSA_MESSAGE_BYTES) =>
  Proxy h ->
  ByteString ->
  MessageHash
hashAndPack p bs = case rawDecodeFixedSized . digest p $ bs of
  Nothing ->
    error $
      "hashAndPack: unexpected mismatch of guaranteed hash length\n"
        <> "Please report this, it's a bug!"
  Just psb -> MH psb

data EcdsaSecp256k1DSIGN

instance DSIGNAlgorithm EcdsaSecp256k1DSIGN where
  type SeedSizeDSIGN EcdsaSecp256k1DSIGN = SECP256K1_ECDSA_PRIVKEY_BYTES
  type Signable EcdsaSecp256k1DSIGN = ((~) MessageHash)
  newtype VerKeyDSIGN EcdsaSecp256k1DSIGN
    = VerKeyEcdsaSecp256k1 (PinnedSizedBytes SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL)
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SignKeyDSIGN EcdsaSecp256k1DSIGN
    = SignKeyEcdsaSecp256k1 (PinnedSizedBytes SECP256K1_ECDSA_PRIVKEY_BYTES)
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SigDSIGN EcdsaSecp256k1DSIGN
    = SigEcdsaSecp256k1 (PinnedSizedBytes SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL)
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
          when
            (res /= 1)
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
            when
              (res /= 1)
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
    case rawDecodeFixedSized bs of
      Nothing -> error "genKeyDSIGN: Failed to generate SignKeyDSIGN EcdsaSecp256k1DSIGN unexpectedly"
      Just psb -> pure $ SignKeyEcdsaSecp256k1 psb

instance FixedSizeCodec (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
  type FixedSize (VerKeyDSIGN EcdsaSecp256k1DSIGN) = SECP256K1_ECDSA_PUBKEY_BYTES
  {-# NOINLINE rawEncodeFixedSized #-}
  rawEncodeFixedSized (VerKeyEcdsaSecp256k1 psb) =
    psbToByteString . unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \psp ->
      psbCreateLen @SECP256K1_ECDSA_PUBKEY_BYTES $ \ptr len -> do
        let dstp = castPtr ptr
        alloca $ \(lenPtr :: Ptr CSize) -> do
          poke lenPtr len
          withForeignPtr secpCtxPtr $ \ctx -> do
            ret <- secpEcPubkeySerialize ctx dstp lenPtr psp secpEcCompressed
            writtenLen <- peek lenPtr
            unless
              (writtenLen == len)
              (error "rawEncodeFixedSized @(VerKeyDSIGN EcdsaSecp256k1DSIGN): Did not write correct length")
            unless
              (ret == 1)
              (error "rawEncodeFixedSized @(VerKeyDSIGN EcdsaSecp256k1DSIGN): Failed for unknown reason")
  {-# NOINLINE rawDecodeFixedSized #-}
  rawDecodeFixedSized bs = do
    psb <- psbFromByteStringM (Proxy @(VerKeyDSIGN EcdsaSecp256k1DSIGN)) bs
    VerKeyEcdsaSecp256k1 <$> go psb
    where
      go ::
        MonadFail m =>
        PinnedSizedBytes SECP256K1_ECDSA_PUBKEY_BYTES ->
        m (PinnedSizedBytes SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL)
      go psb = unsafeDupablePerformIO . psbUseAsCPtrLen psb $ \p srcLen -> do
        let srcp = castPtr p
        (vkPsb, res) <- psbCreateSizedResult $ \vkp ->
          withForeignPtr secpCtxPtr $ \ctx ->
            secpEcPubkeyParse ctx vkp srcp srcLen
        pure $ case res of
          1 -> pure vkPsb
          _ -> fail "VerKeyDSIGN SchnorrSecp256k1DSIGN: deserialisation failed"

instance FixedSizeCodec (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
  type FixedSize (SignKeyDSIGN EcdsaSecp256k1DSIGN) = SECP256K1_ECDSA_PRIVKEY_BYTES
  rawEncodeFixedSized (SignKeyEcdsaSecp256k1 psb) = psbToByteString psb
  rawDecodeFixedSized bs = SignKeyEcdsaSecp256k1 <$> rawDecodeFixedSized bs

instance FixedSizeCodec (SigDSIGN EcdsaSecp256k1DSIGN) where
  type FixedSize (SigDSIGN EcdsaSecp256k1DSIGN) = SECP256K1_ECDSA_SIGNATURE_BYTES
  {-# NOINLINE rawEncodeFixedSized #-}
  rawEncodeFixedSized (SigEcdsaSecp256k1 psb) =
    psbToByteString @SECP256K1_ECDSA_SIGNATURE_BYTES . unsafeDupablePerformIO $ do
      psbUseAsSizedPtr psb $ \psp ->
        psbCreateSized $ \dstp ->
          withForeignPtr secpCtxPtr $ \ctx ->
            void $ secpEcdsaSignatureSerializeCompact ctx dstp psp
  {-# NOINLINE rawDecodeFixedSized #-}
  rawDecodeFixedSized bs = do
    psb <- psbFromByteStringM (Proxy @(SigDSIGN EcdsaSecp256k1DSIGN)) bs
    SigEcdsaSecp256k1 <$> go psb
    where
      go ::
        MonadFail m =>
        PinnedSizedBytes SECP256K1_ECDSA_SIGNATURE_BYTES ->
        m (PinnedSizedBytes SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL)
      go psb = unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \psp -> do
        (sigPsb, res) <- psbCreateSizedResult $ \sigp ->
          withForeignPtr secpCtxPtr $ \ctx ->
            secpEcdsaSignatureParseCompact ctx sigp psp
        pure $ case res of
          1 -> pure sigPsb
          _ -> fail "SigDSIGN: deserialisation failed"

instance ToCBOR (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN EcdsaSecp256k1DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN EcdsaSecp256k1DSIGN) where
  fromCBOR = decodeFixedSized
