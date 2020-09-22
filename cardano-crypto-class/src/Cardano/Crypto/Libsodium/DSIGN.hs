{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
module Cardano.Crypto.Libsodium.DSIGN (
    SodiumDSIGNAlgorithm (..),
    naclSignDSIGN,
    naclVerifyDSIGN,
    naclForgetSignKeyDSIGN,
    SodiumSignKeyDSIGN,
    SodiumVerKeyDSIGN,
    SodiumSigDSIGN,
) where

import Control.Monad (unless)
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Data.Type.Equality ((:~:)(..))
import GHC.IO.Exception (ioException)
import GHC.TypeLits
import System.IO.Unsafe (unsafeDupablePerformIO)

import qualified Data.ByteString as BS

import Cardano.Foreign
import Cardano.Crypto.DSIGN
import Cardano.Crypto.PinnedSizedBytes
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.Libsodium.Memory.Internal
import Cardano.Crypto.Libsodium.MLockedBytes.Internal
import Cardano.Crypto.Util (SignableRepresentation (..))

-- TODO: these could be newtypes, then we wouldn't need proxy args
type SodiumSignKeyDSIGN v = MLockedSizedBytes (SizeSignKeyDSIGN v)
type SodiumVerKeyDSIGN v = PinnedSizedBytes (SizeVerKeyDSIGN v)
type SodiumSigDSIGN v = PinnedSizedBytes (SizeSigDSIGN v)

class (DSIGNAlgorithm v, ContextDSIGN v ~ (), Signable v ~ SignableRepresentation) => SodiumDSIGNAlgorithm v where
    naclSignDSIGNPtr
        :: Proxy v
        -> Ptr a -> Int
        -> SodiumSignKeyDSIGN v
        -> IO (SodiumSigDSIGN v)

    naclVerifyDSIGNPtr
        :: Proxy v
        -> SodiumVerKeyDSIGN v
        -> Ptr a -> Int
        -> SodiumSigDSIGN v
        -> IO (Either String ())

    naclGenKeyDSIGN
        :: Proxy v
        -> MLockedSizedBytes (SeedSizeDSIGN v)
        -> IO (SodiumSignKeyDSIGN v)

    naclDeriveVerKeyDSIGN
        :: Proxy v
        -> SodiumSignKeyDSIGN v
        -> IO (SodiumVerKeyDSIGN v)

naclForgetSignKeyDSIGN
    :: Proxy v
    -> SodiumSignKeyDSIGN v
    -> IO ()
naclForgetSignKeyDSIGN _ (MLSB mfp) =
  finalizeMLockedForeignPtr mfp

naclSignDSIGN
    :: (SodiumDSIGNAlgorithm v, SignableRepresentation a)
    => Proxy v
    -> a
    -> SodiumSignKeyDSIGN v
    -> SodiumSigDSIGN v
naclSignDSIGN pv a sk = unsafeDupablePerformIO $ do
    let bs = getSignableRepresentation a
    BS.useAsCStringLen bs $ \(ptr,len) ->
        naclSignDSIGNPtr pv ptr len sk

naclVerifyDSIGN
    :: (SodiumDSIGNAlgorithm v, SignableRepresentation a)
    => Proxy v
    -> SodiumVerKeyDSIGN v
    -> a
    -> SodiumSigDSIGN v
    -> Either String ()
naclVerifyDSIGN pv vk a sig = unsafeDupablePerformIO $ do
    let bs = getSignableRepresentation a
    BS.useAsCStringLen bs $ \(ptr,len) ->
        naclVerifyDSIGNPtr pv vk ptr len sig

-------------------------------------------------------------------------------
-- Ed25519 instance
-------------------------------------------------------------------------------

instance SodiumDSIGNAlgorithm Ed25519DSIGN where
    naclGenKeyDSIGN _ = mlsbCopy

    naclDeriveVerKeyDSIGN _ seed =
        mlsbUseAsSizedPtr seed $ \seedPtr ->
        mlockedAllocaSized $ \skPtr ->
        psbCreateSized $ \pkPtr -> do
            res <- c_crypto_sign_ed25519_seed_keypair pkPtr skPtr seedPtr
            unless (res == 0) $ do
                errno <- getErrno
                ioException $ errnoToIOError "naclDeriveVerKeyDSIGN @Ed25519DSIGN: c_crypto_sign_ed25519_seed_keypair" errno Nothing Nothing

    naclSignDSIGNPtr _ ptr len seed =
        mlsbUseAsSizedPtr seed $ \seedPtr ->
        mlockedAllocaSized $ \skPtr ->
        allocaSized $ \pkPtr -> do
            -- copy paste
            res <- c_crypto_sign_ed25519_seed_keypair pkPtr skPtr seedPtr
            unless (res == 0) $ do
                errno <- getErrno
                ioException $ errnoToIOError "naclDeriveVerKeyDSIGN @Ed25519DSIGN: c_crypto_sign_ed25519_seed_keypair" errno Nothing Nothing

            psbCreateSized $ \sigPtr -> do
                res2 <- c_crypto_sign_ed25519_detached sigPtr nullPtr (castPtr ptr) (fromIntegral len) skPtr
                unless (res2 == 0) $ do
                    errno <- getErrno
                    ioException $ errnoToIOError "naclDeriveVerKeyDSIGN @Ed25519DSIGN: c_crypto_sign_ed25519_seed_keypair" errno Nothing Nothing

    naclVerifyDSIGNPtr _ vk ptr len sig =
        psbUseAsSizedPtr vk $ \vkPtr ->
        psbUseAsSizedPtr sig $ \sigPtr -> do
            res <- c_crypto_sign_ed25519_verify_detached sigPtr (castPtr ptr) (fromIntegral len) vkPtr
            if res == 0
            then return (Right ())
            else do
                -- errno <- getErrno
                return (Left  "Verification failed")

_testEd25519a :: SeedSizeDSIGN Ed25519DSIGN :~: CRYPTO_SIGN_ED25519_SEEDBYTES
_testEd25519a = Refl

_testEd25519b :: SizeSignKeyDSIGN Ed25519DSIGN + SizeVerKeyDSIGN Ed25519DSIGN :~: CRYPTO_SIGN_ED25519_SECRETKEYBYTES
_testEd25519b = Refl

_testEd25519c :: SizeVerKeyDSIGN Ed25519DSIGN :~: CRYPTO_SIGN_ED25519_PUBLICKEYBYTES
_testEd25519c = Refl

_testEd25519d :: SizeSigDSIGN Ed25519DSIGN :~: CRYPTO_SIGN_ED25519_BYTES
_testEd25519d = Refl
