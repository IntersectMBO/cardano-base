{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

-- We need this so that we can forward the deprecated traceMLockedForeignPtr
{-# OPTIONS_GHC -Wno-deprecations #-}

-- | The Libsodium API generalized to fit arbitrary-ish Monads.
--
-- The purpose of this module is to provide a drop-in replacement for the plain
-- 'Cardano.Crypto.Libsodium' module, but such that the Monad in which some
-- essential actions run can be mocked, rather than forcing it to be 'IO'.
--
-- It may also be used to provide Libsodium functionality in monad stacks that
-- have IO at the bottom, but decorate certain Libsodium operations with
-- additional effects, e.g. logging mlocked memory access.
module Cardano.Crypto.MonadMLock.Class
(
  MonadMLock (..),
  MonadUnmanagedMemory (..),
  MonadByteStringMemory (..),
  MonadPSB (..),

  module PSB_Export,

  psbUseAsCPtr,
  psbUseAsSizedPtr,

  psbCreate,
  psbCreateLen,
  psbCreateSized,
  psbCreateSizedResult,

  packByteStringCStringLen,
)
where

import qualified Cardano.Crypto.Libsodium.Memory as NaCl
import Control.Monad (void)
import Control.Monad.Class.MonadST (MonadST (..))
import Control.Monad.ST.Unsafe

import Cardano.Foreign (c_memset, c_memcpy, SizedPtr (..))

import Data.Kind (type Type)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (Storable)
import Foreign.C.Types (CSize)
import Foreign.C.String (CStringLen)
import qualified Foreign.Marshal.Alloc as Foreign
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Cardano.Crypto.PinnedSizedBytes as PSB
import Cardano.Crypto.PinnedSizedBytes as PSB_Export
          ( PinnedSizedBytes
          , psbToByteString
          , psbFromByteStringCheck
          )
import Data.Word (Word8)
import GHC.TypeLits (KnownNat)

{-# DEPRECATED traceMLockedForeignPtr "Do not use traceMLockedForeignPtr in production" #-}

-- | Primitive operations on unmanaged mlocked memory.
-- These are all implemented in 'IO' underneath, but should morally be in 'ST'.
-- There are two use cases for this:
-- - Running mlocked-memory operations in a mocking context (e.g. 'IOSim') for
--   testing purposes.
-- - Running mlocked-memory operations directly on some monad stack with 'IO'
--   at the bottom.
class MonadUnmanagedMemory m => MonadMLock m where
  type MLockedForeignPtr m :: Type -> Type
  withMLockedForeignPtr :: forall a b. MLockedForeignPtr m a -> (Ptr a -> m b) -> m b
  finalizeMLockedForeignPtr :: forall a. MLockedForeignPtr m a -> m ()
  traceMLockedForeignPtr :: (Storable a, Show a) => MLockedForeignPtr m a -> m ()
  mlockedMalloc :: CSize -> m (MLockedForeignPtr m a)

class Monad m => MonadUnmanagedMemory m where
  zeroMem :: Ptr a -> CSize -> m ()
  copyMem :: Ptr a -> Ptr a -> CSize -> m ()
  allocaBytes :: Int -> (Ptr a -> m b) -> m b

class Monad m => MonadByteStringMemory m where
  useByteStringAsCStringLen :: ByteString -> (CStringLen -> m a) -> m a

class Monad m => MonadPSB m where
  psbUseAsCPtrLen :: forall n r.
                     KnownNat n
                  => PSB.PinnedSizedBytes n
                  -> (Ptr Word8 -> CSize -> m r)
                  -> m r
  psbCreateResultLen :: forall n r.
                        KnownNat n
                     => (Ptr Word8 -> CSize -> m r)
                     -> m (PSB.PinnedSizedBytes n, r)

instance MonadMLock IO where
  type MLockedForeignPtr IO = NaCl.MLockedForeignPtr
  withMLockedForeignPtr = NaCl.withMLockedForeignPtr
  finalizeMLockedForeignPtr = NaCl.finalizeMLockedForeignPtr
  traceMLockedForeignPtr = NaCl.traceMLockedForeignPtr
  mlockedMalloc = NaCl.mlockedMalloc

instance MonadUnmanagedMemory IO where
  zeroMem ptr size = void $ c_memset (castPtr ptr) 0 size
  copyMem dst src size = void $ c_memcpy (castPtr dst) (castPtr src) size
  allocaBytes = Foreign.allocaBytes

instance MonadByteStringMemory IO where
  useByteStringAsCStringLen = BS.useAsCStringLen

instance MonadPSB IO where
  psbUseAsCPtrLen = PSB.psbUseAsCPtrLen
  psbCreateResultLen = PSB.psbCreateResultLen

psbUseAsCPtr :: forall n r m.
                MonadPSB m
             => KnownNat n
             => PinnedSizedBytes n
             -> (Ptr Word8 -> m r)
             -> m r
psbUseAsCPtr psb action =
  psbUseAsCPtrLen psb $ \ptr _ -> action ptr

psbUseAsSizedPtr :: forall n r m.
                    MonadPSB m
                 => KnownNat n
                 => PinnedSizedBytes n
                 -> (SizedPtr n -> m r)
                 -> m r
psbUseAsSizedPtr psb action =
  psbUseAsCPtrLen psb $ \ptr _len ->
    action (SizedPtr $ castPtr ptr)

psbCreateSized ::
  forall n m.
  (KnownNat n, MonadPSB m) =>
  (SizedPtr n -> m ()) ->
  m (PinnedSizedBytes n)
psbCreateSized k = psbCreate (k . SizedPtr . castPtr)

-- | As 'psbCreateResult', but presumes that no useful value is produced: that
-- is, the function argument is run only for its side effects.
psbCreate ::
  forall n m.
  (KnownNat n, MonadPSB m) =>
  (Ptr Word8 -> m ()) ->
  m (PinnedSizedBytes n)
psbCreate f = fst <$> psbCreateResult f

-- | As 'psbCreateResultLen', but presumes that no useful value is produced:
-- that is, the function argument is run only for its side effects.
psbCreateLen ::
  forall n m.
  (KnownNat n, MonadPSB m) =>
  (Ptr Word8 -> CSize -> m ()) ->
  m (PinnedSizedBytes n)
psbCreateLen f = fst <$> psbCreateResultLen f

-- | Given an \'initialization action\', which also produces some result, allocate
-- new pinned memory of the specified size, perform the action, then return the
-- result together with the initialized pinned memory (as a 'PinnedSizedBytes').
--
-- = Note
--
-- It is essential that @r@ is not the 'Ptr' given to the function argument.
-- Returning this 'Ptr' is /extremely/ unsafe:
--
-- * It breaks referential transparency guarantees by aliasing supposedly
-- immutable memory; and
-- * This 'Ptr' could refer to memory which has already been garbage collected,
-- which can lead to segfaults or out-of-bounds reads.
--
-- This poses both correctness /and/ security risks, so please don't do it.
psbCreateResult ::
  forall n r m.
  (KnownNat n, MonadPSB m) =>
  (Ptr Word8 -> m r) ->
  m (PinnedSizedBytes n, r)
psbCreateResult f = psbCreateResultLen (\p _ -> f p)

-- | As 'psbCreateResult', but gives a 'SizedPtr' to the function argument. The
-- same caveats apply to this function as to 'psbCreateResult': the 'SizedPtr'
-- given to the function argument /must not/ be resulted as @r@.
psbCreateSizedResult ::
  forall n r m.
  (KnownNat n, MonadPSB m) =>
  (SizedPtr n -> m r) ->
  m (PinnedSizedBytes n, r)
psbCreateSizedResult f = psbCreateResult (f . SizedPtr . castPtr)


packByteStringCStringLen :: MonadST m => CStringLen -> m ByteString
packByteStringCStringLen (ptr, len) =
  withLiftST $ \lift -> lift . unsafeIOToST $ BS.packCStringLen (ptr, len)
