{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
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

import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import Data.Primitive.Ptr (copyPtr)
import Crypto.Random (getRandomBytes)
import Cardano.Crypto.Seed (runMonadRandomWithSeed)
import Data.ByteString.Internal (toForeignPtr)
import Foreign.ForeignPtr (withForeignPtr, plusForeignPtr)
import Control.Monad (when)
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)
import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (toCBOR, encodedSizeExpr))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.C.Types (CUChar)
import Foreign.Marshal.Alloc (allocaBytes)
import Cardano.Crypto.Schnorr (
  secpKeyPairCreate, 
  SECP256k1Context, 
  secpKeyPairXOnlyPub,
  secpSchnorrSigVerify, 
  secpContextSignVerify,
  secpSchnorrSigSignCustom, 
  secpContextCreate
  )
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
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes, 
  psbUseAsCPtr, 
  psbCreate,
  psbToByteString,
  psbFromByteStringCheck,
  )

data SchnorrSecp256k1DSIGN

instance DSIGNAlgorithm SchnorrSecp256k1DSIGN where
  type SeedSizeDSIGN SchnorrSecp256k1DSIGN = 32
  type SizeSigDSIGN SchnorrSecp256k1DSIGN = 64
  type SizeSignKeyDSIGN SchnorrSecp256k1DSIGN = 32
  type SizeVerKeyDSIGN SchnorrSecp256k1DSIGN = 64
  type Signable SchnorrSecp256k1DSIGN = SignableRepresentation
  newtype VerKeyDSIGN SchnorrSecp256k1DSIGN =
    VerKeySchnorr256k1 (PinnedSizedBytes (SizeVerKeyDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SignKeyDSIGN SchnorrSecp256k1DSIGN =
    SignKeySchnorr256k1 (PinnedSizedBytes (SizeSignKeyDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SigDSIGN SchnorrSecp256k1DSIGN =
    SigSchnorr256k1 (PinnedSizedBytes (SizeSigDSIGN SchnorrSecp256k1DSIGN))
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  algorithmNameDSIGN _ = "schnorr-secp256k1"
  {-# NOINLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeySchnorr256k1 psb) = 
    unsafeDupablePerformIO . psbUseAsCPtr psb $ \skp -> do
      let skp' :: Ptr CUChar = castPtr skp
      allocaBytes 96 $ \kpp -> do
        res <- secpKeyPairCreate ctxPtr kpp skp'
        when (res /= 1) (error "deriveVerKeyDSIGN: Failed to create keypair")
        xonlyPSB <- psbCreate $ \xonlyp -> do
                      res' <- secpKeyPairXOnlyPub ctxPtr (castPtr xonlyp) nullPtr kpp
                      when (res' /= 1) 
                           (error "deriveVerKeyDsIGN: could not extract xonly pubkey")
        pure . VerKeySchnorr256k1 $ xonlyPSB
  {-# NOINLINE signDSIGN #-}
  signDSIGN () msg (SignKeySchnorr256k1 skpsb) = 
    unsafeDupablePerformIO . psbUseAsCPtr skpsb $ \skp -> do
      let bs = getSignableRepresentation msg
      let skp' :: Ptr CUChar = castPtr skp
      allocaBytes 96 $ \kpp -> do
        res <- secpKeyPairCreate ctxPtr kpp skp'
        when (res /= 1) (error "signDSIGN: Failed to create keypair")
        let (msgFP, msgOff, msgLen) = toForeignPtr bs
        sigPSB <- psbCreate $ \sigp -> 
                    withForeignPtr (plusForeignPtr msgFP msgOff) $ \msgp -> do
                      res' <- secpSchnorrSigSignCustom ctxPtr
                                                       (castPtr sigp)
                                                       (castPtr msgp)
                                                       (fromIntegral msgLen)
                                                       kpp
                                                       nullPtr
                      when (res' /= 1)
                           (error "signDSIGN: Failed to sign message")
        pure . SigSchnorr256k1 $ sigPSB
  {-# NOINLINE verifyDSIGN #-}
  verifyDSIGN () (VerKeySchnorr256k1 pubkeyPSB) msg (SigSchnorr256k1 sigPSB) =
    unsafeDupablePerformIO . psbUseAsCPtr pubkeyPSB $ \pkp -> 
      psbUseAsCPtr sigPSB $ \sigp -> do
        let bs = getSignableRepresentation msg
        let (msgFP, msgOff, msgLen) = toForeignPtr bs
        let sigp' :: Ptr CUChar = castPtr sigp
        res <- withForeignPtr (plusForeignPtr msgFP msgOff) $ \msgp -> 
          pure $
          secpSchnorrSigVerify ctxPtr
                               sigp'
                               (castPtr msgp)
                               (fromIntegral msgLen) 
                               (castPtr pkp)
        pure $ if res == 0
          then Left "Schnorr signature failed to verify."
          else pure ()
  {-# NOINLINE genKeyDSIGN #-}
  genKeyDSIGN seed = runMonadRandomWithSeed seed $ do
    bs <- getRandomBytes 32
    unsafeDupablePerformIO $ do
      let (bsFP, bsOff, _) = toForeignPtr bs
      psb <- withForeignPtr (plusForeignPtr bsFP bsOff) $ \bsp -> do
        psbCreate $ \skp -> do
          copyPtr skp bsp 32 
      pure . pure . SignKeySchnorr256k1 $ psb
  rawSerialiseSigDSIGN (SigSchnorr256k1 sigPSB) = psbToByteString sigPSB
  rawSerialiseVerKeyDSIGN (VerKeySchnorr256k1 vkPSB) = psbToByteString vkPSB
  rawSerialiseSignKeyDSIGN (SignKeySchnorr256k1 skPSB) = psbToByteString skPSB
  rawDeserialiseVerKeyDSIGN bs = 
    VerKeySchnorr256k1 <$> psbFromByteStringCheck bs
  rawDeserialiseSignKeyDSIGN bs = 
    SignKeySchnorr256k1 <$> psbFromByteStringCheck bs
  rawDeserialiseSigDSIGN bs = 
    SigSchnorr256k1 <$> psbFromByteStringCheck bs

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

-- Helpers

-- We follow the lead of secp256k1-haskell by creating (once) a context for both
-- signing and verification which we use everywhere, but do not export. This
-- saves considerable time, and is safe, provided nobody else gets to touch it.
--
-- We do _not_ make this dupable, as the whole point is _not_ to compute it more
-- than once!
{-# NOINLINE ctxPtr #-}
ctxPtr :: Ptr SECP256k1Context
ctxPtr = unsafePerformIO . secpContextCreate $ secpContextSignVerify
