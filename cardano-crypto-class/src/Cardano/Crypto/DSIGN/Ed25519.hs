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

-- | Ed25519 digital signatures.
module Cardano.Crypto.DSIGN.Ed25519
  ( Ed25519DSIGN
  , SigDSIGN (..)
  , SignKeyDSIGN (..)
  , SignKeyDSIGNM (..)
  , VerKeyDSIGN (..)
  )
where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Monad ((<$!>), unless, guard)
import Control.Monad.Class.MonadST (MonadST (..))
import Control.Monad.Class.MonadThrow (MonadThrow (..), throwIO)
import Control.Monad.ST (ST)
import Control.Monad.ST.Unsafe (unsafeIOToST)
import qualified Data.ByteString as BS
import Data.Proxy
import Foreign.C.Error (errnoToIOError, getErrno, Errno)
import Foreign.Ptr (castPtr, nullPtr)
import GHC.Generics (Generic)
import GHC.IO.Exception (ioException)
import GHC.TypeLits (TypeError, ErrorMessage (..))
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)


import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Libsodium
  ( MLockedSizedBytes
  , mlsbToByteString
  , mlsbFromByteStringCheckWith
  , mlsbUseAsSizedPtr
  , mlsbNewWith
  , mlsbFinalize
  , mlsbCopyWith
  )
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.PinnedSizedBytes
  ( PinnedSizedBytes
  , psbUseAsSizedPtr
  , psbUseAsCPtrLen
  , psbToByteString
  , psbFromByteStringCheck
  , psbCreate
  , psbCreateSized
  , psbCreateSizedResult
  )
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation(..))
import Cardano.Foreign
import Cardano.Crypto.DirectSerialise



data Ed25519DSIGN

instance NoThunks (VerKeyDSIGN Ed25519DSIGN)
instance NoThunks (SignKeyDSIGN Ed25519DSIGN)
instance NoThunks (SigDSIGN Ed25519DSIGN)

deriving via (MLockedSizedBytes (SizeSignKeyDSIGN Ed25519DSIGN))
  instance NoThunks (SignKeyDSIGNM Ed25519DSIGN)

instance NFData (SignKeyDSIGNM Ed25519DSIGN) where
  rnf = rwhnf

-- | Convert C-style return code / errno error reporting into Haskell
-- exceptions.
--
-- Runs an IO action (which should be some FFI call into C) that returns a
-- result code; if the result code returned is nonzero, fetch the errno, and
-- throw a suitable IO exception.
cOrThrowError :: String -> String -> IO Int -> IO ()
cOrThrowError contextDesc cFunName action = do
  res <- action
  unless (res == 0) $ do
      errno <- getErrno
      ioException $ errnoToIOError (contextDesc ++ ": " ++ cFunName) errno Nothing Nothing
--
-- | Convert C-style return code / errno error reporting into Haskell
-- exceptions.
--
-- Runs an IO action (which should be some FFI call into C) that returns a
-- result code; if the result code returned is nonzero, fetch the errno, and
-- return it.
cOrError :: MonadST m => (forall s. ST s Int) -> m (Maybe Errno)
cOrError action = stToIO $ do
  res <- action
  if res == 0 then
    return Nothing
  else
    Just <$> unsafeIOToST getErrno

-- | Throws an error when 'Just' an 'Errno' is given.
throwOnErrno :: MonadThrow m => String -> String -> Maybe Errno -> m ()
throwOnErrno contextDesc cFunName maybeErrno = do
  case maybeErrno of
    Just errno -> throwIO $ errnoToIOError (contextDesc ++ ": " ++ cFunName) errno Nothing Nothing
    Nothing -> return ()


instance DSIGNAlgorithm Ed25519DSIGN where
    -- | Seed size is 32 octets, the same as sign key size, because generating
    -- a sign key is literally just taking a chunk from the seed. We use
    -- SEEDBYTES to define both the seed size and the sign key size.
    type SeedSizeDSIGN Ed25519DSIGN = CRYPTO_SIGN_ED25519_SEEDBYTES
    -- | Ed25519 key size is 32 octets
    -- (per <https://tools.ietf.org/html/rfc8032#section-5.1.6>)
    type SizeVerKeyDSIGN  Ed25519DSIGN = CRYPTO_SIGN_ED25519_PUBLICKEYBYTES
    -- | Ed25519 secret key size is 32 octets; however, libsodium packs both
    -- the secret key and the public key into a 64-octet compound and exposes
    -- that as the secret key; the actual 32-octet secret key is called
    -- \"seed\" in libsodium. For backwards compatibility reasons and
    -- efficiency, we use the 64-octet compounds internally (this is what
    -- libsodium expects), but we only serialize the 32-octet secret key part
    -- (the libsodium \"seed\"). And because of this, we need to define the
    -- sign key size to be SEEDBYTES (which is 32), not PRIVATEKEYBYTES (which
    -- would be 64).
    type SizeSignKeyDSIGN Ed25519DSIGN = CRYPTO_SIGN_ED25519_SEEDBYTES
    -- | Ed25519 signature size is 64 octets
    type SizeSigDSIGN     Ed25519DSIGN = CRYPTO_SIGN_ED25519_BYTES

    --
    -- Key and signature types
    --

    newtype VerKeyDSIGN Ed25519DSIGN = VerKeyEd25519DSIGN (PinnedSizedBytes (SizeVerKeyDSIGN Ed25519DSIGN))
        deriving (Show, Eq, Generic)
        deriving newtype NFData

    -- Note that the size of the internal key data structure is the SECRET KEY
    -- bytes as per libsodium, while the declared key size (for serialization)
    -- is libsodium's SEED bytes. We expand 32-octet keys to 64-octet ones
    -- during deserialization, and we delete the 32 octets that contain the
    -- public key from the secret key before serializing.
    newtype SignKeyDSIGN Ed25519DSIGN = SignKeyEd25519DSIGN (PinnedSizedBytes CRYPTO_SIGN_ED25519_SECRETKEYBYTES)
        deriving (Show, Eq, Generic)
        deriving newtype NFData

    newtype SigDSIGN Ed25519DSIGN = SigEd25519DSIGN (PinnedSizedBytes (SizeSigDSIGN Ed25519DSIGN))
        deriving (Show, Eq, Generic)
        deriving newtype NFData

    --
    -- Metadata and basic key operations
    --

    algorithmNameDSIGN _ = "ed25519"

    deriveVerKeyDSIGN (SignKeyEd25519DSIGN sk) =
      VerKeyEd25519DSIGN $
        unsafeDupablePerformIO $
        psbUseAsSizedPtr sk $ \skPtr ->
        psbCreateSized $ \pkPtr ->
          cOrThrowError "deriveVerKeyDSIGN @Ed25519DSIGN" "c_crypto_sign_ed25519_sk_to_pk"
            $ c_crypto_sign_ed25519_sk_to_pk pkPtr skPtr

    --
    -- Core algorithm operations
    --

    type Signable Ed25519DSIGN = SignableRepresentation

    signDSIGN () a (SignKeyEd25519DSIGN sk) =
      let bs = getSignableRepresentation a
      in SigEd25519DSIGN $ unsafeDupablePerformIO $
            BS.useAsCStringLen bs $ \(ptr, len) ->
            psbUseAsSizedPtr sk $ \skPtr ->
            allocaSized $ \pkPtr -> do
                cOrThrowError "signDSIGN @Ed25519DSIGN" "c_crypto_sign_ed25519_sk_to_pk"
                  $ c_crypto_sign_ed25519_sk_to_pk pkPtr skPtr
                psbCreateSized $ \sigPtr -> do
                  cOrThrowError "signDSIGN @Ed25519DSIGN" "c_crypto_sign_ed25519_detached"
                    $ c_crypto_sign_ed25519_detached sigPtr nullPtr (castPtr ptr) (fromIntegral len) skPtr

    verifyDSIGN () (VerKeyEd25519DSIGN vk) a (SigEd25519DSIGN sig) =
        let bs = getSignableRepresentation a
        in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(ptr, len) ->
          psbUseAsSizedPtr vk $ \vkPtr ->
          psbUseAsSizedPtr sig $ \sigPtr -> do
              res <- c_crypto_sign_ed25519_verify_detached sigPtr (castPtr ptr) (fromIntegral len) vkPtr
              if res == 0
              then return (Right ())
              else do
                  -- errno <- getErrno
                  return (Left  "Verification failed")

    --
    -- Key generation
    --
    genKeyDSIGN seed = SignKeyEd25519DSIGN $
      let (sb, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @Ed25519DSIGN)) seed
      in unsafeDupablePerformIO $ do
          psbCreateSized $ \skPtr ->
            BS.useAsCStringLen sb $ \(seedPtr, _) ->
            allocaSized $ \pkPtr -> do
                cOrThrowError "genKeyDSIGN @Ed25519DSIGN" "c_crypto_sign_ed25519_seed_keypair"
                  $ c_crypto_sign_ed25519_seed_keypair pkPtr skPtr (SizedPtr . castPtr $ seedPtr)
    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyDSIGN   (VerKeyEd25519DSIGN vk) = psbToByteString vk
    rawSerialiseSignKeyDSIGN  (SignKeyEd25519DSIGN sk) =
        psbToByteString @(SeedSizeDSIGN Ed25519DSIGN) $ unsafeDupablePerformIO $ do
          psbCreateSized $ \seedPtr ->
            psbUseAsSizedPtr sk $ \skPtr ->
              cOrThrowError "deriveVerKeyDSIGN @Ed25519DSIGN" "c_crypto_sign_ed25519_sk_to_seed"
                $ c_crypto_sign_ed25519_sk_to_seed seedPtr skPtr

    rawSerialiseSigDSIGN      (SigEd25519DSIGN sig) = psbToByteString sig

    rawDeserialiseVerKeyDSIGN  = fmap VerKeyEd25519DSIGN . psbFromByteStringCheck
    {-# INLINE rawDeserialiseVerKeyDSIGN #-}
    rawDeserialiseSignKeyDSIGN bs = do
      guard (fromIntegral (BS.length bs) == seedSizeDSIGN (Proxy @Ed25519DSIGN))
      pure . genKeyDSIGN . mkSeedFromBytes $ bs
    rawDeserialiseSigDSIGN     = fmap SigEd25519DSIGN . psbFromByteStringCheck
    {-# INLINE rawDeserialiseSigDSIGN #-}

instance DSIGNMAlgorithm Ed25519DSIGN where
    -- Note that the size of the internal key data structure is the SECRET KEY
    -- bytes as per libsodium, while the declared key size (for serialization)
    -- is libsodium's SEED bytes. We expand 32-octet keys to 64-octet ones
    -- during deserialization, and we delete the 32 octets that contain the
    -- public key from the secret key before serializing.
    newtype SignKeyDSIGNM Ed25519DSIGN = SignKeyEd25519DSIGNM (MLockedSizedBytes CRYPTO_SIGN_ED25519_SECRETKEYBYTES)
        deriving (Show)

    deriveVerKeyDSIGNM (SignKeyEd25519DSIGNM sk) =
      VerKeyEd25519DSIGN <$!> do
        mlsbUseAsSizedPtr sk $ \skPtr -> do
          (psb, maybeErrno) <-
            psbCreateSizedResult $ \pkPtr ->
              stToIO $ do
                cOrError $ unsafeIOToST $
                  c_crypto_sign_ed25519_sk_to_pk pkPtr skPtr
          throwOnErrno "deriveVerKeyDSIGN @Ed25519DSIGN" "c_crypto_sign_ed25519_sk_to_pk" maybeErrno
          return psb


    signDSIGNM () a (SignKeyEd25519DSIGNM sk) =
      let bs = getSignableRepresentation a
      in SigEd25519DSIGN <$!> do
          mlsbUseAsSizedPtr sk $ \skPtr -> do
            (psb, maybeErrno) <-
              psbCreateSizedResult $ \sigPtr ->
                stToIO $ do
                  cOrError $ unsafeIOToST $ do
                    BS.useAsCStringLen bs $ \(ptr, len) ->
                      c_crypto_sign_ed25519_detached sigPtr nullPtr (castPtr ptr) (fromIntegral len) skPtr
            throwOnErrno "signDSIGNM @Ed25519DSIGN" "c_crypto_sign_ed25519_detached" maybeErrno
            return psb

    --
    -- Key generation
    --
    {-# NOINLINE genKeyDSIGNMWith #-}
    genKeyDSIGNMWith allocator seed = SignKeyEd25519DSIGNM <$!> do
      sk <- mlsbNewWith allocator
      mlsbUseAsSizedPtr sk $ \skPtr ->
        mlockedSeedUseAsCPtr seed $ \seedPtr -> do
          maybeErrno <- stToIO $ allocaSizedST $ \pkPtr -> do
              cOrError $ unsafeIOToST $
                c_crypto_sign_ed25519_seed_keypair pkPtr skPtr (SizedPtr . castPtr $ seedPtr)
          throwOnErrno "genKeyDSIGNM @Ed25519DSIGN" "c_crypto_sign_ed25519_seed_keypair" maybeErrno
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
          maybeErrno <-
            stToIO $ cOrError $ unsafeIOToST $
              c_crypto_sign_ed25519_sk_to_seed seedPtr skPtr
          throwOnErrno "genKeyDSIGNM @Ed25519DSIGN" "c_crypto_sign_ed25519_seed_keypair" maybeErrno
      return seed

    --
    -- Secure forgetting
    --
    forgetSignKeyDSIGNMWith _ (SignKeyEd25519DSIGNM sk) = mlsbFinalize sk

instance UnsoundDSIGNMAlgorithm Ed25519DSIGN where
    --
    -- Ser/deser (dangerous - do not use in production code)
    --
    rawSerialiseSignKeyDSIGNM sk = do
      seed <- getSeedDSIGNM (Proxy @Ed25519DSIGN) sk
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

instance ToCBOR (VerKeyDSIGN Ed25519DSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN Ed25519DSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN Ed25519DSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN Ed25519DSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN Ed25519DSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN Ed25519DSIGN) where
  fromCBOR = decodeSigDSIGN


instance TypeError ('Text "CBOR encoding would violate mlocking guarantees")
  => ToCBOR (SignKeyDSIGNM Ed25519DSIGN) where
  toCBOR = error "unsupported"
  encodedSizeExpr _ = error "unsupported"

instance TypeError ('Text "CBOR decoding would violate mlocking guarantees")
  => FromCBOR (SignKeyDSIGNM Ed25519DSIGN) where
  fromCBOR = error "unsupported"

instance DirectSerialise (SignKeyDSIGNM Ed25519DSIGN) where
  -- /Note:/ We only serialize the 32-byte seed, not the full 64-byte key. The
  -- latter contains both the seed and the 32-byte verification key, which is
  -- convenient, but redundant, since we can always reconstruct it from the
  -- seed. This is also reflected in the 'SizeSignKeyDSIGNM', which equals
  -- 'SeedSizeDSIGNM' == 32, rather than reporting the in-memory size of 64.
  directSerialise push sk = do
    bracket
      (getSeedDSIGNM (Proxy @Ed25519DSIGN) sk)
      mlockedSeedFinalize
      (\seed -> mlockedSeedUseAsCPtr seed $ \ptr ->
          push
            (castPtr ptr)
            (fromIntegral $ seedSizeDSIGN (Proxy @Ed25519DSIGN)))

instance DirectDeserialise (SignKeyDSIGNM Ed25519DSIGN) where
  -- /Note:/ We only serialize the 32-byte seed, not the full 64-byte key. See
  -- the DirectSerialise instance above.
  directDeserialise pull = do
    bracket
      mlockedSeedNew
      mlockedSeedFinalize
      (\seed -> do
          mlockedSeedUseAsCPtr seed $ \ptr -> do
            pull
              (castPtr ptr)
              (fromIntegral $ seedSizeDSIGN (Proxy @Ed25519DSIGN))
          genKeyDSIGNM seed
      )

instance DirectSerialise (VerKeyDSIGN Ed25519DSIGN) where
  directSerialise push (VerKeyEd25519DSIGN psb) = do
    psbUseAsCPtrLen psb $ \ptr _ ->
      push
        (castPtr ptr)
        (fromIntegral $ sizeVerKeyDSIGN (Proxy @Ed25519DSIGN))

instance DirectDeserialise (VerKeyDSIGN Ed25519DSIGN) where
  directDeserialise pull = do
    psb <- psbCreate $ \ptr ->
      pull
        (castPtr ptr)
        (fromIntegral $ sizeVerKeyDSIGN (Proxy @Ed25519DSIGN))
    return $! VerKeyEd25519DSIGN psb
