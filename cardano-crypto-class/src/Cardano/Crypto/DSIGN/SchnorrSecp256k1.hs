{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
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

module Cardano.Crypto.DSIGN.SchnorrSecp256k1 (
  SchnorrSecp256k1DSIGN,
  VerKeyDSIGN,
  SignKeyDSIGN,
  SigDSIGN,
) where

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  fixedSize,
 )
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (
    SeedSizeDSIGN,
    SigDSIGN,
    SigSizeDSIGN,
    SignKeyDSIGN,
    SignKeySizeDSIGN,
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
  seedSizeDSIGN,
 )
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreate,
  psbCreateSized,
  psbCreateSizedResult,
  psbToByteString,
  psbUseAsSizedPtr,
 )
import Cardano.Crypto.SECP256K1.C (
  secpCtxPtr,
  secpKeyPairCreate,
  secpKeyPairXOnlyPub,
  secpSchnorrSigSignCustom,
  secpSchnorrSigVerify,
  secpXOnlyPubkeyParse,
  secpXOnlyPubkeySerialize,
 )
import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_SCHNORR_PRIVKEY_BYTES,
  SECP256K1_SCHNORR_PUBKEY_BYTES,
  SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL,
  SECP256K1_SCHNORR_SIGNATURE_BYTES,
 )
import Cardano.Crypto.Seed (getBytesFromSeedT)
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Cardano.Foreign (allocaSized)
import Control.DeepSeq (NFData)
import Control.Monad (when)
import Data.ByteString (useAsCStringLen)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Primitive.Ptr (copyPtr)
import Data.Proxy (Proxy (Proxy))
import Foreign.C.Types (CSize)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (castPtr, nullPtr)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

data SchnorrSecp256k1DSIGN

instance DSIGNAlgorithm SchnorrSecp256k1DSIGN where
  type SeedSizeDSIGN SchnorrSecp256k1DSIGN = SECP256K1_SCHNORR_PRIVKEY_BYTES
  type Signable SchnorrSecp256k1DSIGN = SignableRepresentation
  newtype VerKeyDSIGN SchnorrSecp256k1DSIGN
    = VerKeySchnorrSecp256k1 (PinnedSizedBytes SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL)
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SignKeyDSIGN SchnorrSecp256k1DSIGN
    = SignKeySchnorrSecp256k1 (PinnedSizedBytes (SignKeySizeDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SigDSIGN SchnorrSecp256k1DSIGN
    = SigSchnorrSecp256k1 (PinnedSizedBytes (SigSizeDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  algorithmNameDSIGN _ = "schnorr-secp256k1"
  {-# NOINLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeySchnorrSecp256k1 psb) =
    unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \skp ->
      allocaSized $ \kpp ->
        withForeignPtr secpCtxPtr $ \ctx -> do
          res <- secpKeyPairCreate ctx kpp skp
          when
            (res /= 1)
            (error "deriveVerKeyDSIGN: Failed to create keypair for SchnorrSecp256k1DSIGN")
          xonlyPSB <- psbCreateSized $ \xonlyp -> do
            res' <- secpKeyPairXOnlyPub ctx xonlyp nullPtr kpp
            when
              (res' /= 1)
              (error "deriveVerKeyDSIGN: could not extract xonly pubkey for SchnorrSecp256k1DSIGN")
          pure . VerKeySchnorrSecp256k1 $ xonlyPSB
  {-# NOINLINE signDSIGN #-}
  signDSIGN () msg (SignKeySchnorrSecp256k1 skpsb) =
    unsafeDupablePerformIO . psbUseAsSizedPtr skpsb $ \skp -> do
      let bs = getSignableRepresentation msg
      allocaSized $ \kpp ->
        withForeignPtr secpCtxPtr $ \ctx -> do
          res <- secpKeyPairCreate ctx kpp skp
          when (res /= 1) (error "signDSIGN: Failed to create keypair for SchnorrSecp256k1DSIGN")
          sigPSB <- psbCreateSized $ \sigp -> useAsCStringLen bs $ \(msgp, msgLen) -> do
            res' <-
              secpSchnorrSigSignCustom
                ctx
                sigp
                (castPtr msgp)
                (fromIntegral @Int @CSize msgLen)
                kpp
                nullPtr
            when (res' /= 1) (error "signDSIGN: Failed to sign SchnorrSecp256k1DSIGN message")
          pure . SigSchnorrSecp256k1 $ sigPSB
  {-# NOINLINE verifyDSIGN #-}
  verifyDSIGN () (VerKeySchnorrSecp256k1 pubkeyPSB) msg (SigSchnorrSecp256k1 sigPSB) =
    unsafeDupablePerformIO . psbUseAsSizedPtr pubkeyPSB $ \pkp ->
      psbUseAsSizedPtr sigPSB $ \sigp -> do
        let bs = getSignableRepresentation msg
        res <- useAsCStringLen bs $ \(msgp, msgLen) ->
          withForeignPtr secpCtxPtr $ \ctx ->
            pure $
              secpSchnorrSigVerify
                ctx
                sigp
                (castPtr msgp)
                (fromIntegral @Int @CSize msgLen)
                pkp
        pure $
          if res == 0
            then Left "SigDSIGN SchnorrSecp256k1DSIGN failed to verify."
            else pure ()
  {-# NOINLINE genKeyDSIGN #-}
  genKeyDSIGN seed =
    SignKeySchnorrSecp256k1 $
      let (bs, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @SchnorrSecp256k1DSIGN)) seed
       in unsafeDupablePerformIO $
            psbCreate $ \skp ->
              useAsCStringLen bs $ \(bsp, sz) ->
                copyPtr skp (castPtr bsp) sz

instance FixedSizeCodec (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  type FixedSize (VerKeyDSIGN SchnorrSecp256k1DSIGN) = SECP256K1_SCHNORR_PUBKEY_BYTES
  {-# NOINLINE rawEncodeFixedSized #-}
  rawEncodeFixedSized (VerKeySchnorrSecp256k1 vkPSB) =
    unsafeDupablePerformIO . psbUseAsSizedPtr vkPSB $ \pkbPtr -> do
      res <- psbCreateSized $ \bsPtr ->
        withForeignPtr secpCtxPtr $ \ctx -> do
          res' <- secpXOnlyPubkeySerialize ctx bsPtr pkbPtr
          when
            (res' /= 1)
            (error "rawEncodeFixedSized @(VerKeyDSIGN SchnorrSecp256k1DSIGN): Failed to serialise")
      pure . psbToByteString $ res
  {-# NOINLINE rawDecodeFixedSized #-}
  rawDecodeFixedSized bs = do
    let
      expectedSize =
        fromIntegral @Word @Int . fixedSize $ Proxy @(VerKeyDSIGN SchnorrSecp256k1DSIGN)
    unsafeDupablePerformIO . unsafeUseAsCStringLen bs $ \case
      (ptr, len)
        | len /= expectedSize ->
            pure . fail $
              "VerKeyDSIGN SchnorrSecp256k1DSIGN: wrong length, expected "
                <> show expectedSize
                <> " bytes but got "
                <> show len
        | otherwise -> do
            let dataPtr = castPtr ptr
            (vkPsb, res) <- psbCreateSizedResult $ \outPtr ->
              withForeignPtr secpCtxPtr $ \ctx ->
                secpXOnlyPubkeyParse ctx outPtr dataPtr
            pure $ case res of
              1 -> pure . VerKeySchnorrSecp256k1 $ vkPsb
              _ -> fail "VerKeyDSIGN SchnorrSecp256k1DSIGN: deserialisation failed"

instance FixedSizeCodec (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  type FixedSize (SignKeyDSIGN SchnorrSecp256k1DSIGN) = SECP256K1_SCHNORR_PRIVKEY_BYTES
  rawEncodeFixedSized (SignKeySchnorrSecp256k1 skPSB) = psbToByteString skPSB
  rawDecodeFixedSized bs = SignKeySchnorrSecp256k1 <$> rawDecodeFixedSized bs

instance FixedSizeCodec (SigDSIGN SchnorrSecp256k1DSIGN) where
  type FixedSize (SigDSIGN SchnorrSecp256k1DSIGN) = SECP256K1_SCHNORR_SIGNATURE_BYTES
  rawEncodeFixedSized (SigSchnorrSecp256k1 sigPSB) = psbToByteString sigPSB
  rawDecodeFixedSized bs = SigSchnorrSecp256k1 <$> rawDecodeFixedSized bs

instance ToCBOR (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN SchnorrSecp256k1DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN SchnorrSecp256k1DSIGN) where
  fromCBOR = decodeFixedSized
