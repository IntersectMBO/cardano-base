{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
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

import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafePackCStringLen)
import Data.Primitive.Ptr (copyPtr)
import Crypto.Random (getRandomBytes)
import Cardano.Crypto.Seed (runMonadRandomWithSeed)
import Data.ByteString.Internal (toForeignPtr, memcmp)
import Foreign.ForeignPtr (
  ForeignPtr, 
  withForeignPtr, 
  mallocForeignPtrBytes,
  plusForeignPtr, 
  castForeignPtr
  )
import Control.Monad (when)
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)
import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (toCBOR, encodedSizeExpr))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.C.Types (CUChar)
import Foreign.Marshal.Alloc (allocaBytes)
import Cardano.Crypto.Schnorr (
  SECP256k1XOnlyPubKey, 
  secpKeyPairCreate, 
  SECP256k1Context, 
  secpKeyPairXOnlyPub,
  SECP256k1SecKey, 
  secpSchnorrSigVerify, 
  secpContextSignVerify,
  SECP256k1SchnorrSig, 
  secpSchnorrSigSignCustom, 
  secpContextCreate
  )
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (OnlyCheckWhnfNamed))
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

data SchnorrSecp256k1DSIGN

instance DSIGNAlgorithm SchnorrSecp256k1DSIGN where
  type SeedSizeDSIGN SchnorrSecp256k1DSIGN = 32
  type SizeSigDSIGN SchnorrSecp256k1DSIGN = 64
  type SizeSignKeyDSIGN SchnorrSecp256k1DSIGN = 32
  type SizeVerKeyDSIGN SchnorrSecp256k1DSIGN = 64
  type Signable SchnorrSecp256k1DSIGN = SignableRepresentation
  newtype VerKeyDSIGN SchnorrSecp256k1DSIGN = 
    VerKeySchnorr256k1 (ForeignPtr SECP256k1XOnlyPubKey)
      deriving NoThunks via (
        OnlyCheckWhnfNamed "VerKeySchnorr256k1" (ForeignPtr SECP256k1XOnlyPubKey)
        )
  newtype SignKeyDSIGN SchnorrSecp256k1DSIGN = 
    SignKeySchnorr256k1 (ForeignPtr SECP256k1SecKey)
      deriving NoThunks via (
        OnlyCheckWhnfNamed "SignKeySchnorr256k1" (ForeignPtr SECP256k1SecKey)
        )
  newtype SigDSIGN SchnorrSecp256k1DSIGN = 
    SigSchnorr256k1 (ForeignPtr SECP256k1SchnorrSig)
      deriving NoThunks via (
        OnlyCheckWhnfNamed "SigSchnorr256k1" (ForeignPtr SECP256k1SchnorrSig)
        )
  algorithmNameDSIGN _ = "schnorr-secp256k1"
  {-# NOINLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeySchnorr256k1 fp) = 
    unsafeDupablePerformIO . withForeignPtr fp $ \skp -> do
      let skp' :: Ptr CUChar = castPtr skp
      allocaBytes 96 $ \kpp -> do
        res <- secpKeyPairCreate ctxPtr kpp skp'
        when (res /= 1) (error "deriveVerKeyDSIGN: Failed to create keypair")
        xonlyFP <- mallocForeignPtrBytes 64
        res' <- withForeignPtr xonlyFP $ \xonlyp -> 
          secpKeyPairXOnlyPub ctxPtr xonlyp nullPtr kpp
        when (res' /= 1) (error "deriveVerKeyDSIGN: could not extract xonly pubkey")
        pure . VerKeySchnorr256k1 $ xonlyFP
  {-# NOINLINE signDSIGN #-}
  signDSIGN () msg (SignKeySchnorr256k1 skfp) = 
    unsafeDupablePerformIO . withForeignPtr skfp $ \skp -> do
      let bs = getSignableRepresentation msg
      let skp' :: Ptr CUChar = castPtr skp
      allocaBytes 96 $ \kpp -> do
        res <- secpKeyPairCreate ctxPtr kpp skp'
        when (res /= 1) (error "signDSIGN: Failed to create keypair")
        sigFP <- mallocForeignPtrBytes 64
        let (msgFP, msgOff, msgLen) = toForeignPtr bs
        res' <- withForeignPtr sigFP $ \sigp -> 
          withForeignPtr (plusForeignPtr msgFP msgOff) $ \msgp -> 
            secpSchnorrSigSignCustom ctxPtr 
                                     sigp 
                                     (castPtr msgp) 
                                     (fromIntegral msgLen) 
                                     kpp 
                                     nullPtr
        when (res' /= 1) (error "signDSIGN: Failed to sign message")
        pure . SigSchnorr256k1 $ sigFP
  {-# NOINLINE verifyDSIGN #-}
  verifyDSIGN () (VerKeySchnorr256k1 pubkeyFP) msg (SigSchnorr256k1 sigFP) =
    unsafeDupablePerformIO . withForeignPtr pubkeyFP $ \pkp -> 
      withForeignPtr sigFP $ \sigp -> do 
        let bs = getSignableRepresentation msg
        let (msgFP, msgOff, msgLen) = toForeignPtr bs
        let sigp' :: Ptr CUChar = castPtr sigp
        res <- withForeignPtr (plusForeignPtr msgFP msgOff) $ \msgp -> 
          pure . 
          secpSchnorrSigVerify ctxPtr sigp' (castPtr msgp) (fromIntegral msgLen) $ pkp
        pure $ if res == 0
          then Left "Schnorr signature failed to verify."
          else pure ()
  {-# NOINLINE genKeyDSIGN #-}
  genKeyDSIGN seed = runMonadRandomWithSeed seed $ do
    bs <- getRandomBytes 32
    unsafeDupablePerformIO $ do
      let (bsFP, bsOff, _) = toForeignPtr bs
      fp <- withForeignPtr (plusForeignPtr bsFP bsOff) $ \bsp -> do
        skFP <- mallocForeignPtrBytes 64
        withForeignPtr skFP $ \skp -> do
          let skp' :: Ptr CUChar = castPtr skp
          let bsp' :: Ptr CUChar = castPtr bsp
          copyPtr skp' bsp' 64
        pure skFP
      pure . pure . SignKeySchnorr256k1 $ fp
  {-# NOINLINE rawSerialiseSigDSIGN #-}
  rawSerialiseSigDSIGN (SigSchnorr256k1 sigFP) = 
    unsafeDupablePerformIO . withForeignPtr sigFP $ \sigp -> 
      unsafePackCStringLen (castPtr sigp, 64)
  {-# NOINLINE rawSerialiseVerKeyDSIGN #-}
  rawSerialiseVerKeyDSIGN (VerKeySchnorr256k1 vkFP) = 
    unsafeDupablePerformIO . withForeignPtr vkFP $ \vkp -> 
      unsafePackCStringLen (castPtr vkp, 64)
  {-# NOINLINE rawSerialiseSignKeyDSIGN #-}
  rawSerialiseSignKeyDSIGN (SignKeySchnorr256k1 skFP) = 
    unsafeDupablePerformIO . withForeignPtr skFP $ \skp -> 
      unsafePackCStringLen (castPtr skp, 32)
  rawDeserialiseVerKeyDSIGN bs
    | BS.length bs == 64 = 
        let (bsFP, bsOff, _) = toForeignPtr bs in
          pure . 
          VerKeySchnorr256k1 . 
          castForeignPtr . 
          plusForeignPtr bsFP $ bsOff
    | otherwise = Nothing
  rawDeserialiseSignKeyDSIGN bs
    | BS.length bs == 32 = 
        let (bsFP, bsOff, _) = toForeignPtr bs in
          pure . 
          SignKeySchnorr256k1 . 
          castForeignPtr . 
          plusForeignPtr bsFP $ bsOff
    | otherwise = Nothing
  rawDeserialiseSigDSIGN bs
    | BS.length bs == 64 = 
        let (bsFP, bsOff, _) = toForeignPtr bs in
          pure . 
          SigSchnorr256k1 . 
          castForeignPtr . 
          plusForeignPtr bsFP $ bsOff
    | otherwise = Nothing

instance Eq (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  {-# NOINLINE (==) #-}
  VerKeySchnorr256k1 fp == VerKeySchnorr256k1 fp' = 
    unsafeDupablePerformIO . withForeignPtr fp $ \p -> 
      withForeignPtr fp' $ \p' -> do
        res <- memcmp (castPtr p) (castPtr p') 64
        pure $ case res of 
          0 -> True
          _ -> False

instance Eq (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  {-# NOINLINE (==) #-}
  SignKeySchnorr256k1 fp == SignKeySchnorr256k1 fp' = 
    unsafeDupablePerformIO . withForeignPtr fp $ \p -> 
      withForeignPtr fp' $ \p' -> do
        res <- memcmp (castPtr p) (castPtr p') 32
        pure $ case res of 
          0 -> True
          _ -> False

instance Eq (SigDSIGN SchnorrSecp256k1DSIGN) where
  {-# NOINLINE (==) #-}
  SigSchnorr256k1 fp == SigSchnorr256k1 fp' = 
    unsafeDupablePerformIO . withForeignPtr fp $ \p -> 
      withForeignPtr fp' $ \p' -> do
        res <- memcmp (castPtr p) (castPtr p') 64
        pure $ case res of 
          0 -> True
          _ -> False

instance Show (VerKeyDSIGN SchnorrSecp256k1DSIGN) where
  {-# NOINLINE show #-}
  show (VerKeySchnorr256k1 fp) = 
    ("VerKeySchnorr256k1 " <>) .
    show .
    unsafeDupablePerformIO . 
    withForeignPtr fp $ \p -> 
      unsafePackCStringLen (castPtr p, 64)

instance Show (SignKeyDSIGN SchnorrSecp256k1DSIGN) where
  {-# NOINLINE show #-}
  show (SignKeySchnorr256k1 fp) =
    ("SignKeySchnorr256k1 " <>) .
    show . 
    unsafeDupablePerformIO . 
    withForeignPtr fp $ \p -> 
      unsafePackCStringLen (castPtr p, 32)

instance Show (SigDSIGN SchnorrSecp256k1DSIGN) where
  {-# NOINLINE show #-}
  show (SigSchnorr256k1 fp) = 
    ("SigSchnorr256k1 " <>) . 
    show . 
    unsafeDupablePerformIO . 
    withForeignPtr fp $ \p -> 
      unsafePackCStringLen (castPtr p, 64)

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
