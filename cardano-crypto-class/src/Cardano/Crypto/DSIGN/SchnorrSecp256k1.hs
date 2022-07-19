{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE TypeApplications #-}
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
  SigDSIGN
  ) where

import Data.Proxy (Proxy (Proxy))
import Data.ByteString (useAsCStringLen)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import Data.Primitive.Ptr (copyPtr)
import Cardano.Crypto.Seed (getBytesFromSeedT)
import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_SCHNORR_PRIVKEY_BYTES,
  SECP256K1_SCHNORR_SIGNATURE_BYTES,
  SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL,
  SECP256K1_SCHNORR_PUBKEY_BYTES,
  )
import Cardano.Crypto.SECP256K1.C (
  secpKeyPairCreate,
  secpXOnlyPubkeySerialize,
  secpKeyPairXOnlyPub,
  secpXOnlyPubkeyParse,
  secpSchnorrSigVerify,
  secpSchnorrSigSignCustom,
  secpCtxPtr,
  )
import Cardano.Foreign (allocaSized)
import Control.Monad (when)
import System.IO.Unsafe (unsafeDupablePerformIO)
import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (toCBOR, encodedSizeExpr))
import Foreign.Ptr (castPtr, nullPtr)
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
  decodeSigDSIGN,
  seedSizeDSIGN
  )
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbUseAsSizedPtr,
  psbCreateSizedResult,
  psbCreate,
  psbCreateSized,
  psbToByteString,
  psbFromByteStringCheck,
  )
import Data.ByteString.Unsafe (unsafeUseAsCStringLen) 

data SchnorrSecp256k1DSIGN

instance DSIGNAlgorithm SchnorrSecp256k1DSIGN where
  type SeedSizeDSIGN SchnorrSecp256k1DSIGN = SECP256K1_SCHNORR_PRIVKEY_BYTES
  type SizeSigDSIGN SchnorrSecp256k1DSIGN = SECP256K1_SCHNORR_SIGNATURE_BYTES
  type SizeSignKeyDSIGN SchnorrSecp256k1DSIGN = SECP256K1_SCHNORR_PRIVKEY_BYTES
  type SizeVerKeyDSIGN SchnorrSecp256k1DSIGN = SECP256K1_SCHNORR_PUBKEY_BYTES
  type Signable SchnorrSecp256k1DSIGN = SignableRepresentation
  newtype VerKeyDSIGN SchnorrSecp256k1DSIGN =
    VerKeySchnorrSecp256k1 (PinnedSizedBytes SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL)
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SignKeyDSIGN SchnorrSecp256k1DSIGN =
    SignKeySchnorrSecp256k1 (PinnedSizedBytes (SizeSignKeyDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SigDSIGN SchnorrSecp256k1DSIGN =
    SigSchnorrSecp256k1 (PinnedSizedBytes (SizeSigDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  algorithmNameDSIGN _ = "schnorr-secp256k1"
  {-# NOINLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeySchnorrSecp256k1 psb) = 
    unsafeDupablePerformIO . psbUseAsSizedPtr psb $ \skp -> do
      allocaSized $ \kpp -> do
        res <- secpKeyPairCreate secpCtxPtr kpp skp
        when (res /= 1) 
             (error "deriveVerKeyDSIGN: Failed to create keypair for SchnorrSecp256k1DSIGN")
        xonlyPSB <- psbCreateSized $ \xonlyp -> do
                      res' <- secpKeyPairXOnlyPub secpCtxPtr xonlyp nullPtr kpp
                      when (res' /= 1) 
                           (error "deriveVerKeyDSIGN: could not extract xonly pubkey for SchnorrSecp256k1DSIGN")
        pure . VerKeySchnorrSecp256k1 $ xonlyPSB
  {-# NOINLINE signDSIGN #-}
  signDSIGN () msg (SignKeySchnorrSecp256k1 skpsb) = 
    unsafeDupablePerformIO . psbUseAsSizedPtr skpsb $ \skp -> do
      let bs = getSignableRepresentation msg
      allocaSized $ \kpp -> do
        res <- secpKeyPairCreate secpCtxPtr kpp skp
        when (res /= 1) (error "signDSIGN: Failed to create keypair for SchnorrSecp256k1DSIGN")
        sigPSB <- psbCreateSized $ \sigp -> useAsCStringLen bs $ \(msgp, msgLen) -> do
          res' <- secpSchnorrSigSignCustom secpCtxPtr
                                           sigp
                                           (castPtr msgp)
                                           (fromIntegral msgLen)
                                           kpp
                                           nullPtr
          when (res' /= 1) (error "signDSIGN: Failed to sign SchnorrSecp256k1DSIGN message")
        pure . SigSchnorrSecp256k1 $ sigPSB
  {-# NOINLINE verifyDSIGN #-}
  verifyDSIGN () (VerKeySchnorrSecp256k1 pubkeyPSB) msg (SigSchnorrSecp256k1 sigPSB) =
    unsafeDupablePerformIO . psbUseAsSizedPtr pubkeyPSB $ \pkp ->
      psbUseAsSizedPtr sigPSB $ \sigp -> do
        let bs = getSignableRepresentation msg
        res <- useAsCStringLen bs $ \(msgp, msgLen) -> do
          pure $ secpSchnorrSigVerify secpCtxPtr 
                                      sigp
                                      (castPtr msgp) 
                                      (fromIntegral msgLen)
                                      pkp
        pure $ if res == 0
          then Left "SigDSIGN SchnorrSecp256k1DSIGN failed to verify."
          else pure ()
  {-# NOINLINE genKeyDSIGN #-}
  genKeyDSIGN seed = SignKeySchnorrSecp256k1 $
    let (bs, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @SchnorrSecp256k1DSIGN)) seed
    in unsafeDupablePerformIO $
         psbCreate $ \skp ->
           useAsCStringLen bs $ \(bsp, sz) ->
             copyPtr skp (castPtr bsp) sz
  rawSerialiseSigDSIGN (SigSchnorrSecp256k1 sigPSB) = psbToByteString sigPSB
  {-# NOINLINE rawSerialiseVerKeyDSIGN #-}
  rawSerialiseVerKeyDSIGN (VerKeySchnorrSecp256k1 vkPSB) = 
    unsafeDupablePerformIO . psbUseAsSizedPtr vkPSB $ \pkbPtr -> do
      res <- psbCreateSized $ \bsPtr -> do
        res' <- secpXOnlyPubkeySerialize secpCtxPtr bsPtr pkbPtr
        when (res' /= 1) 
             (error "rawSerialiseVerKeyDSIGN: Failed to serialise VerKeyDSIGN SchnorrSecp256k1DSIGN")
      pure . psbToByteString $ res
  rawSerialiseSignKeyDSIGN (SignKeySchnorrSecp256k1 skPSB) = psbToByteString skPSB
  {-# NOINLINE rawDeserialiseVerKeyDSIGN #-}
  rawDeserialiseVerKeyDSIGN bs = 
    unsafeDupablePerformIO . unsafeUseAsCStringLen bs $ \(ptr, _) -> do
      let dataPtr = castPtr ptr
      (vkPsb, res) <- psbCreateSizedResult $ \outPtr -> 
          secpXOnlyPubkeyParse secpCtxPtr outPtr dataPtr
      pure $ case res of 
        1 -> pure . VerKeySchnorrSecp256k1 $ vkPsb
        _ -> Nothing
  rawDeserialiseSignKeyDSIGN bs = 
    SignKeySchnorrSecp256k1 <$> psbFromByteStringCheck bs
  rawDeserialiseSigDSIGN bs = 
    SigSchnorrSecp256k1 <$> psbFromByteStringCheck bs

instance ToCBOR (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr

instance FromCBOR (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN SchnorrSecp256k1DSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN SchnorrSecp256k1DSIGN) where
  fromCBOR = decodeSigDSIGN
