{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Ed25519 digital signatures. This flavor of Ed25519 stores secrets in
-- mlocked memory to make sure they cannot leak to disk via swapping.
module Cardano.Crypto.DSIGN.Ed25519ML (
  Ed25519DSIGNM,
  SigDSIGNM (..),
  SignKeyDSIGNM (..),
  VerKeyDSIGNM (..),
)
where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Monad ((<$!>))
import Control.Monad.Class.MonadST (MonadST (..))
import Control.Monad.Class.MonadThrow (MonadThrow (..), throwIO)
import Control.Monad.ST (ST, stToIO)
import Control.Monad.ST.Unsafe (unsafeIOToST)
import qualified Data.ByteString as BS
import Data.Proxy
import Foreign.C.Error (Errno, errnoToIOError, getErrno)
import Foreign.Ptr (castPtr, nullPtr)
import GHC.Generics (Generic)
import GHC.TypeLits (ErrorMessage (..), TypeError)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Libsodium (
  MLockedSizedBytes,
  mlsbCopyWith,
  mlsbFinalize,
  mlsbFromByteStringCheckWith,
  mlsbNewWith,
  mlsbToByteString,
  mlsbUseAsSizedPtr,
 )
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreateSizedResult,
  psbFromByteStringCheck,
  psbToByteString,
  psbUseAsSizedPtr,
 )
import Cardano.Foreign

import Cardano.Crypto.DSIGNM.Class
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Util (SignableRepresentation (..))

data Ed25519DSIGNM

instance NoThunks (VerKeyDSIGNM Ed25519DSIGNM)
instance NoThunks (SigDSIGNM Ed25519DSIGNM)

deriving via
  (MLockedSizedBytes (SizeSignKeyDSIGNM Ed25519DSIGNM))
  instance
    NoThunks (SignKeyDSIGNM Ed25519DSIGNM)

instance NFData (SignKeyDSIGNM Ed25519DSIGNM) where
  rnf = rwhnf

-- | Convert C-style return code / errno error reporting into Haskell
-- exceptions.
--
-- Runs an IO action (which should be some FFI call into C) that returns a
-- result code; if the result code returned is nonzero, fetch the errno, and
-- return it.
cOrError :: MonadST m => (forall s. ST s Int) -> m (Maybe Errno)
cOrError action = do
  withLiftST $ \fromST -> fromST $ do
    res <- action
    if res == 0
      then
        return Nothing
      else
        Just <$> unsafeIOToST getErrno

-- | Throws an error when 'Just' an 'Errno' is given.
throwOnErrno :: MonadThrow m => String -> String -> Maybe Errno -> m ()
throwOnErrno contextDesc cFunName maybeErrno = do
  case maybeErrno of
    Just errno -> throwIO $ errnoToIOError (contextDesc ++ ": " ++ cFunName) errno Nothing Nothing
    Nothing -> return ()

instance DSIGNMAlgorithmBase Ed25519DSIGNM where
  type SeedSizeDSIGNM Ed25519DSIGNM = CRYPTO_SIGN_ED25519_SEEDBYTES

  -- \| Ed25519 key size is 32 octets
  -- (per <https://tools.ietf.org/html/rfc8032#section-5.1.6>)
  type SizeVerKeyDSIGNM Ed25519DSIGNM = CRYPTO_SIGN_ED25519_PUBLICKEYBYTES

  -- \| Ed25519 secret key size is 32 octets; however, libsodium packs both
  -- the secret key and the public key into a 64-octet compound and exposes
  -- that as the secret key; the actual 32-octet secret key is called
  -- \"seed\" in libsodium. For backwards compatibility reasons and
  -- efficiency, we use the 64-octet compounds internally (this is what
  -- libsodium expects), but we only serialize the 32-octet secret key part
  -- (the libsodium \"seed\").
  type SizeSignKeyDSIGNM Ed25519DSIGNM = CRYPTO_SIGN_ED25519_SEEDBYTES

  -- \| Ed25519 signature size is 64 octets
  type SizeSigDSIGNM Ed25519DSIGNM = CRYPTO_SIGN_ED25519_BYTES

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGNM Ed25519DSIGNM = VerKeyEd25519DSIGNM (PinnedSizedBytes (SizeVerKeyDSIGNM Ed25519DSIGNM))
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  -- Note that the size of the internal key data structure is the SECRET KEY
  -- bytes as per libsodium, while the declared key size (for serialization)
  -- is libsodium's SEED bytes. We expand 32-octet keys to 64-octet ones
  -- during deserialization, and we delete the 32 octets that contain the
  -- public key from the secret key before serializing.
  newtype SignKeyDSIGNM Ed25519DSIGNM
    = SignKeyEd25519DSIGNM (MLockedSizedBytes CRYPTO_SIGN_ED25519_SECRETKEYBYTES)
    deriving (Show)

  newtype SigDSIGNM Ed25519DSIGNM = SigEd25519DSIGNM (PinnedSizedBytes (SizeSigDSIGNM Ed25519DSIGNM))
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGNM _ = "ed25519-ml"

  --
  -- Core algorithm operations
  --

  type SignableM Ed25519DSIGNM = SignableRepresentation

  verifyDSIGNM () (VerKeyEd25519DSIGNM vk) a (SigEd25519DSIGNM sig) =
    let bs = getSignableRepresentation a
     in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
            psbUseAsSizedPtr vk $ \vkPtr ->
              psbUseAsSizedPtr sig $ \sigPtr -> do
                res <- c_crypto_sign_ed25519_verify_detached sigPtr (castPtr ptr) (fromIntegral len) vkPtr
                if res == 0
                  then
                    return (Right ())
                  else
                    return (Left "Verification failed")

  --
  -- raw serialise/deserialise
  --

  rawSerialiseVerKeyDSIGNM (VerKeyEd25519DSIGNM vk) = psbToByteString vk
  rawSerialiseSigDSIGNM (SigEd25519DSIGNM sig) = psbToByteString sig

  rawDeserialiseVerKeyDSIGNM = fmap VerKeyEd25519DSIGNM . psbFromByteStringCheck
  rawDeserialiseSigDSIGNM = fmap SigEd25519DSIGNM . psbFromByteStringCheck

-- Note on the use of 'MonadST' and 'unsafeIOToST' here.
--
-- This instance is intended to be used in two types of contexts:
-- - 'IO', or a monad stack built on top of it.
-- - 'IOSim', or a monad stack built on top of it.
--
-- Both of these implement morally correct 'ST', and the 'MonadST' constraint
-- reflects this.
--
-- Various libsodium primitives, particularly 'MLockedSizedBytes' primitives,
-- are used via the 'MonadST' typeclass, which is responsible for
-- guaranteeing orderly execution of these actions. We avoid using these
-- primitives inside 'unsafeIOToST', as well as any 'IO' actions that would be
-- unsafe to use inside 'unsafePerformIO'.
--
-- Specifically, we only use the following potentially dangerous operations
-- inside 'unsafeIOToST':
--
-- - Libsodium functions (via C FFI) that are morally referentially
--   transparent: that is, while they do perform destructive updates, the
--   update is idempotent in the imperative sense, and the functions themselves
--   never allocate / deallocate, they only operate on previously allocated
--   memory passed to them via C pointers.
-- - 'getErrno'; however, 'ST' guarantees sequentiality in the context where
--   we use 'getErrno', so this is fine.
instance DSIGNMAlgorithm Ed25519DSIGNM where
  deriveVerKeyDSIGNM (SignKeyEd25519DSIGNM sk) =
    VerKeyEd25519DSIGNM <$!> do
      mlsbUseAsSizedPtr sk $ \skPtr -> do
        (psb, maybeErrno) <-
          psbCreateSizedResult $ \pkPtr ->
            withLiftST $ \fromST -> fromST $ do
              cOrError $
                unsafeIOToST $
                  c_crypto_sign_ed25519_sk_to_pk pkPtr skPtr
        throwOnErrno "deriveVerKeyDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_sk_to_pk" maybeErrno
        return psb

  signDSIGNM () a (SignKeyEd25519DSIGNM sk) =
    let bs = getSignableRepresentation a
     in SigEd25519DSIGNM <$!> do
          mlsbUseAsSizedPtr sk $ \skPtr -> do
            (psb, maybeErrno) <-
              psbCreateSizedResult $ \sigPtr -> do
                withLiftST $ \fromST -> fromST $ do
                  cOrError $ unsafeIOToST $ do
                    BS.useAsCStringLen bs $ \(ptr, len) ->
                      c_crypto_sign_ed25519_detached sigPtr nullPtr (castPtr ptr) (fromIntegral len) skPtr
            throwOnErrno "signDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_detached" maybeErrno
            return psb

  --
  -- Key generation
  --
  {-# NOINLINE genKeyDSIGNMWith #-}
  genKeyDSIGNMWith allocator seed =
    SignKeyEd25519DSIGNM <$!> do
      sk <- mlsbNewWith allocator
      mlsbUseAsSizedPtr sk $ \skPtr ->
        mlockedSeedUseAsCPtr seed $ \seedPtr -> do
          maybeErrno <- withLiftST $ \fromST ->
            fromST $ allocaSizedST $ \pkPtr -> do
              cOrError $
                unsafeIOToST $
                  c_crypto_sign_ed25519_seed_keypair pkPtr skPtr (SizedPtr . castPtr $ seedPtr)
          throwOnErrno "genKeyDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_seed_keypair" maybeErrno
      return sk
    where
      allocaSizedST k =
        unsafeIOToST $ allocaSized $ \ptr -> stToIO $ k ptr

  cloneKeyDSIGNMWith allocator (SignKeyEd25519DSIGNM sk) =
    SignKeyEd25519DSIGNM <$!> mlsbCopyWith allocator sk

  getSeedDSIGNMWith allocator _ (SignKeyEd25519DSIGNM sk) = do
    seed <- mlockedSeedNewWith allocator
    mlsbUseAsSizedPtr sk $ \skPtr ->
      mlockedSeedUseAsSizedPtr seed $ \seedPtr -> do
        maybeErrno <- withLiftST $ \fromST ->
          fromST $
            cOrError $
              unsafeIOToST $
                c_crypto_sign_ed25519_sk_to_seed seedPtr skPtr
        throwOnErrno "genKeyDSIGNM @Ed25519DSIGNM" "c_crypto_sign_ed25519_seed_keypair" maybeErrno
    return seed

  --
  -- Secure forgetting
  --
  forgetSignKeyDSIGNMWith _ (SignKeyEd25519DSIGNM sk) = mlsbFinalize sk

instance UnsoundDSIGNMAlgorithm Ed25519DSIGNM where
  --
  -- Ser/deser (dangerous - do not use in production code)
  --
  rawSerialiseSignKeyDSIGNM sk = do
    seed <- getSeedDSIGNM (Proxy @Ed25519DSIGNM) sk
    -- We need to copy the seed into unsafe memory and finalize the MLSB, in
    -- order to avoid leaking mlocked memory. This will, however, expose the
    -- secret seed to the unprotected Haskell heap (see 'mlsbToByteString').
    raw <- mlsbToByteString . mlockedSeedMLSB $ seed
    mlockedSeedFinalize seed
    return raw

  rawDeserialiseSignKeyDSIGNMWith allocator raw = do
    mseed <- fmap MLockedSeed <$> mlsbFromByteStringCheckWith allocator raw
    case mseed of
      Nothing -> return Nothing
      Just seed -> do
        sk <- Just <$> genKeyDSIGNMWith allocator seed
        mlockedSeedFinalize seed
        return sk

instance ToCBOR (VerKeyDSIGNM Ed25519DSIGNM) where
  toCBOR = encodeVerKeyDSIGNM
  encodedSizeExpr _ = encodedVerKeyDSIGNMSizeExpr

instance FromCBOR (VerKeyDSIGNM Ed25519DSIGNM) where
  fromCBOR = decodeVerKeyDSIGNM

instance
  TypeError ('Text "CBOR encoding would violate mlocking guarantees") =>
  ToCBOR (SignKeyDSIGNM Ed25519DSIGNM)
  where
  toCBOR = error "unsupported"
  encodedSizeExpr _ = error "unsupported"

instance
  TypeError ('Text "CBOR decoding would violate mlocking guarantees") =>
  FromCBOR (SignKeyDSIGNM Ed25519DSIGNM)
  where
  fromCBOR = error "unsupported"

instance ToCBOR (SigDSIGNM Ed25519DSIGNM) where
  toCBOR = encodeSigDSIGNM
  encodedSizeExpr _ = encodedSigDSIGNMSizeExpr

instance FromCBOR (SigDSIGNM Ed25519DSIGNM) where
  fromCBOR = decodeSigDSIGNM
