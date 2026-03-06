{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the Blake2b hashing algorithm, with various sizes.
module Cardano.Crypto.Hash.Blake2b (
  Blake2b_224,
  Blake2b_256,
  blake2b_libsodium, -- Used for Hash.Short
)
where

import Control.Monad (unless)
import Control.Monad.Class.MonadST (MonadST)
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize, CULLong)
import Foreign.Ptr (castPtr, nullPtr)
import GHC.IO.Exception (ioException)

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as B

import Cardano.Crypto.Hash.Class (
  Hash,
  HashAlgorithm (..),
  HashSize,
  IncrementalHashAlgorithm (..),
  digest,
  hashAlgorithmName,
  hashFromPackedBytes,
  hashSize,
 )
import Cardano.Crypto.Libsodium.C (
  CRYPTO_BLAKE2B_STATE_SIZE,
  c_crypto_generichash_blake2b,
  c_crypto_generichash_blake2b_final,
  c_crypto_generichash_blake2b_init,
  c_crypto_generichash_blake2b_update,
 )
import Cardano.Crypto.Libsodium.Memory.Internal (unsafeIOToMonadST)
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreateLen,
  psbCreateSizedAligned,
  psbToPackedBytes,
  psbUseAsSizedPtr,
 )

data Blake2b_224
data Blake2b_256

instance HashAlgorithm Blake2b_224 where
  type HashSize Blake2b_224 = 28
  hashAlgorithmName _ = "blake2b_224"
  digest _ = blake2b_libsodium 28

instance HashAlgorithm Blake2b_256 where
  type HashSize Blake2b_256 = 32
  hashAlgorithmName _ = "blake2b_256"
  digest _ = blake2b_libsodium 32

instance IncrementalHashAlgorithm Blake2b_224 where
  data HashContext Blake2b_224 s
    = Blake2b224Context (PinnedSizedBytes CRYPTO_BLAKE2B_STATE_SIZE)
  hashInit = Blake2b224Context <$> blake2bInitContext @Blake2b_224
  hashUpdate (Blake2b224Context psb) = blake2bUpdateContext psb
  hashFinalize (Blake2b224Context psb) = blake2bFinalizeHash @Blake2b_224 psb

instance IncrementalHashAlgorithm Blake2b_256 where
  data HashContext Blake2b_256 s
    = Blake2b256Context (PinnedSizedBytes CRYPTO_BLAKE2B_STATE_SIZE)
  hashInit = Blake2b256Context <$> blake2bInitContext @Blake2b_256
  hashUpdate (Blake2b256Context psb) = blake2bUpdateContext psb
  hashFinalize (Blake2b256Context psb) = blake2bFinalizeHash @Blake2b_256 psb

-------------------------------------------------------------------------------
-- Shared helpers for incremental Blake2b hashing
-------------------------------------------------------------------------------

{-# INLINE blake2bInitContext #-}
blake2bInitContext ::
  forall h m.
  (HashAlgorithm h, MonadST m) =>
  m (PinnedSizedBytes CRYPTO_BLAKE2B_STATE_SIZE)
blake2bInitContext = do
  let outLen = fromIntegral @Word @CSize (hashSize (Proxy @h))
  -- libsodium source notes (in crypto_generichash.h) that "the state address should be 64-bytes aligned"
  unsafeIOToMonadST $
    psbCreateSizedAligned 64 $ \sizedPtr -> do
      res <-
        c_crypto_generichash_blake2b_init
          sizedPtr
          nullPtr -- no key
          0 -- key length
          outLen
      unless (res == 0) $ do
        errno <- getErrno
        ioException $
          errnoToIOError "blake2bInitContext: c_crypto_generichash_blake2b_init" errno Nothing Nothing

{-# INLINE blake2bUpdateContext #-}
blake2bUpdateContext ::
  MonadST m => PinnedSizedBytes CRYPTO_BLAKE2B_STATE_SIZE -> B.ByteString -> m ()
blake2bUpdateContext psb chunk =
  unsafeIOToMonadST $
    psbUseAsSizedPtr psb $ \sizedPtr ->
      B.unsafeUseAsCStringLen chunk $ \(inPtr, inLen) -> do
        res <-
          c_crypto_generichash_blake2b_update
            sizedPtr
            (castPtr inPtr)
            (fromIntegral @Int @CULLong inLen)
        unless (res == 0) $ do
          errno <- getErrno
          ioException $
            errnoToIOError "blake2bUpdateContext: c_crypto_generichash_blake2b_update" errno Nothing Nothing

{-# INLINE blake2bFinalizeHash #-}
blake2bFinalizeHash ::
  forall h a m.
  (HashAlgorithm h, MonadST m) =>
  PinnedSizedBytes CRYPTO_BLAKE2B_STATE_SIZE ->
  m (Hash h a)
blake2bFinalizeHash psb = do
  psbHash :: PinnedSizedBytes (HashSize h) <-
    unsafeIOToMonadST $
      psbUseAsSizedPtr psb $ \sizedPtr ->
        psbCreateLen $ \outPtr outLen -> do
          res <-
            c_crypto_generichash_blake2b_final
              sizedPtr
              outPtr
              outLen
          unless (res == 0) $ do
            errno <- getErrno
            ioException $
              errnoToIOError "blake2bFinalizeHash: c_crypto_generichash_blake2b_final" errno Nothing Nothing
  pure $ hashFromPackedBytes $ psbToPackedBytes psbHash

-------------------------------------------------------------------------------
-- Single-shot Blake2b
-------------------------------------------------------------------------------

blake2b_libsodium :: Int -> B.ByteString -> B.ByteString
blake2b_libsodium size input =
  BI.unsafeCreate size $ \outptr ->
    B.useAsCStringLen input $ \(inptr, inputlen) -> do
      res <-
        c_crypto_generichash_blake2b
          (castPtr outptr)
          (fromIntegral @Int @CSize size)
          (castPtr inptr)
          (fromIntegral @Int @CULLong inputlen)
          nullPtr
          0 -- we used unkeyed hash
      unless (res == 0) $ do
        errno <- getErrno
        ioException $ errnoToIOError "digest @Blake2b: crypto_generichash_blake2b" errno Nothing Nothing
