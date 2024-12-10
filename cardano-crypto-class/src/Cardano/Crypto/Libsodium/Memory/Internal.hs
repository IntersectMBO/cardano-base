{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Crypto.Libsodium.Memory.Internal (
  -- * High-level memory management
  MLockedForeignPtr (..),
  withMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,

  -- * MLocked allocations
  mlockedMalloc,
  MLockedAllocator (..),
  mlockedAlloca,
  mlockedAllocaSized,
  mlockedAllocForeignPtr,
  mlockedAllocForeignPtrBytes,

  -- * Allocations using an explicit allocator
  mlockedAllocaWith,
  mlockedAllocaSizedWith,
  mlockedAllocForeignPtrWith,
  mlockedAllocForeignPtrBytesWith,

  -- * 'ForeignPtr' operations, generalized to 'MonadST'
  ForeignPtr (..),
  mallocForeignPtrBytes,
  withForeignPtr,

  -- * Unmanaged memory, generalized to 'MonadST'
  zeroMem,
  copyMem,
  allocaBytes,

  -- * ByteString memory access, generalized to 'MonadST'
  unpackByteStringCStringLen,
  packByteStringCStringLen,

  -- * Helper
  unsafeIOToMonadST,
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (Exception, mask_)
import Control.Monad (void, when)
import Control.Monad.Class.MonadST (MonadST, stToIO)
import Control.Monad.Class.MonadThrow (MonadThrow (bracket))
import Control.Monad.Primitive (touch)
import Control.Monad.ST (RealWorld, ST)
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Coerce (coerce)
import Data.Kind
import Data.Typeable
import Debug.Trace (traceShowM)
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.String (CStringLen)
import Foreign.C.Types (CSize (..))
import qualified Foreign.Concurrent as Foreign
import qualified Foreign.ForeignPtr as Foreign hiding (newForeignPtr)
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
import qualified Foreign.ForeignPtr.Unsafe as Foreign
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable (peek), alignment, sizeOf)
import GHC.IO.Exception (ioException)
import GHC.TypeLits (KnownNat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafePerformIO)
import System.Memory.Pool (Pool, grabNextBlock, initPool)

import Cardano.Crypto.Libsodium.C
import Cardano.Foreign (SizedPtr (..), c_memcpy, c_memset)

-- | Foreign pointer to securely allocated memory.
newtype MLockedForeignPtr a = SFP {_unwrapMLockedForeignPtr :: Foreign.ForeignPtr a}
  deriving (NoThunks) via OnlyCheckWhnfNamed "MLockedForeignPtr" (MLockedForeignPtr a)

instance NFData (MLockedForeignPtr a) where
  rnf = rwhnf . _unwrapMLockedForeignPtr

withMLockedForeignPtr :: MonadST m => MLockedForeignPtr a -> (Ptr a -> m b) -> m b
withMLockedForeignPtr (SFP fptr) f = do
  r <- f (unsafeForeignPtrToPtr fptr)
  r <$ unsafeIOToMonadST (Foreign.touchForeignPtr fptr)

finalizeMLockedForeignPtr :: MonadST m => MLockedForeignPtr a -> m ()
finalizeMLockedForeignPtr (SFP fptr) =
  unsafeIOToMonadST $ Foreign.finalizeForeignPtr fptr

{-# WARNING traceMLockedForeignPtr "Do not use traceMLockedForeignPtr in production" #-}
traceMLockedForeignPtr :: (Storable a, Show a, MonadST m) => MLockedForeignPtr a -> m ()
traceMLockedForeignPtr fptr = withMLockedForeignPtr fptr $ \ptr -> do
  a <- unsafeIOToMonadST (peek ptr)
  traceShowM a

unsafeIOToMonadST :: MonadST m => IO a -> m a
unsafeIOToMonadST = stToIO . unsafeIOToST

makeMLockedPool :: forall n s. KnownNat n => ST s (Pool n s)
makeMLockedPool = do
  initPool
    (max 1 . fromIntegral $ 4096 `div` natVal (Proxy @n) `div` 64)
    ( \size -> unsafeIOToST $ mask_ $ do
        ptr <- sodiumMalloc (fromIntegral size)
        Foreign.newForeignPtr ptr (sodiumFree ptr (fromIntegral size))
    )
    ( \ptr -> do
        eraseMem (Proxy @n) ptr
    )

eraseMem :: forall n a. KnownNat n => Proxy n -> Ptr a -> IO ()
eraseMem proxy ptr = fillBytes ptr 0xff (fromIntegral $ natVal proxy)

mlockedPool32 :: Pool 32 RealWorld
mlockedPool32 = unsafePerformIO $ stToIO makeMLockedPool
{-# NOINLINE mlockedPool32 #-}

mlockedPool64 :: Pool 64 RealWorld
mlockedPool64 = unsafePerformIO $ stToIO makeMLockedPool
{-# NOINLINE mlockedPool64 #-}

mlockedPool128 :: Pool 128 RealWorld
mlockedPool128 = unsafePerformIO $ stToIO makeMLockedPool
{-# NOINLINE mlockedPool128 #-}

mlockedPool256 :: Pool 256 RealWorld
mlockedPool256 = unsafePerformIO $ stToIO makeMLockedPool
{-# NOINLINE mlockedPool256 #-}

mlockedPool512 :: Pool 512 RealWorld
mlockedPool512 = unsafePerformIO $ stToIO makeMLockedPool
{-# NOINLINE mlockedPool512 #-}

data AllocatorException
  = AllocatorNoTracer
  | AllocatorNoGenerator
  deriving (Show)

instance Exception AllocatorException

mlockedMalloc :: MonadST m => MLockedAllocator m
mlockedMalloc =
  MLockedAllocator {mlAllocate = unsafeIOToMonadST . mlockedMallocIO}

mlockedMallocIO :: CSize -> IO (MLockedForeignPtr a)
mlockedMallocIO size =
  SFP <$> do
    if
      | size <= 32 -> do
          fmap coerce $ stToIO $ grabNextBlock mlockedPool32
      | size <= 64 -> do
          fmap coerce $ stToIO $ grabNextBlock mlockedPool64
      | size <= 128 -> do
          fmap coerce $ stToIO $ grabNextBlock mlockedPool128
      | size <= 256 -> do
          fmap coerce $ stToIO $ grabNextBlock mlockedPool256
      | size <= 512 -> do
          fmap coerce $ stToIO $ grabNextBlock mlockedPool512
      | otherwise -> do
          mask_ $ do
            ptr <- sodiumMalloc size
            Foreign.newForeignPtr ptr $ do
              sodiumFree ptr size

sodiumMalloc :: CSize -> IO (Ptr a)
sodiumMalloc size = do
  ptr <- c_sodium_malloc size
  when (ptr == nullPtr) $ do
    errno <- getErrno
    ioException $ errnoToIOError "c_sodium_malloc" errno Nothing Nothing
  res <- c_sodium_mlock ptr size
  when (res /= 0) $ do
    errno <- getErrno
    ioException $ errnoToIOError "c_sodium_mlock" errno Nothing Nothing
  return ptr

sodiumFree :: Ptr a -> CSize -> IO ()
sodiumFree ptr size = do
  res <- c_sodium_munlock ptr size
  when (res /= 0) $ do
    errno <- getErrno
    ioException $ errnoToIOError "c_sodium_munlock" errno Nothing Nothing
  c_sodium_free ptr

zeroMem :: MonadST m => Ptr a -> CSize -> m ()
zeroMem ptr size = unsafeIOToMonadST . void $ c_memset (castPtr ptr) 0 size

copyMem :: MonadST m => Ptr a -> Ptr a -> CSize -> m ()
copyMem dst src size = unsafeIOToMonadST . void $ c_memcpy (castPtr dst) (castPtr src) size

-- | A 'ForeignPtr' type, generalized to 'MonadST'. The type is tagged with
-- the correct Monad @m@ in order to ensure that foreign pointers created in
-- one ST context can only be used within the same ST context.
newtype ForeignPtr (m :: Type -> Type) a = ForeignPtr {unsafeRawForeignPtr :: Foreign.ForeignPtr a}

mallocForeignPtrBytes :: MonadST m => Int -> m (ForeignPtr m a)
mallocForeignPtrBytes size =
  ForeignPtr <$> unsafeIOToMonadST (Foreign.mallocForeignPtrBytes size)

-- | 'Foreign.withForeignPtr', generalized to 'MonadST'.
-- Caveat: if the monadic action passed to 'withForeignPtr' does not terminate
-- (e.g., 'forever'), the 'ForeignPtr' finalizer may run prematurely.
withForeignPtr :: MonadST m => ForeignPtr m a -> (Ptr a -> m b) -> m b
withForeignPtr (ForeignPtr fptr) f = do
  result <- f $ Foreign.unsafeForeignPtrToPtr fptr
  stToIO $ touch fptr
  return result

allocaBytes :: (MonadThrow m, MonadST m) => Int -> (Ptr a -> m b) -> m b
allocaBytes size action = do
  fptr <- mallocForeignPtrBytes size
  withForeignPtr fptr action

-- | Unpacks a ByteString into a temporary buffer and runs the provided 'ST'
-- function on it.
unpackByteStringCStringLen :: (MonadThrow m, MonadST m) => ByteString -> (CStringLen -> m a) -> m a
unpackByteStringCStringLen bs f = do
  let len = BS.length bs
  allocaBytes len $ \buf -> do
    unsafeIOToMonadST $ BS.unsafeUseAsCString bs $ \ptr -> do
      copyMem buf ptr (fromIntegral len)
    f (buf, len)

packByteStringCStringLen :: MonadST m => CStringLen -> m ByteString
packByteStringCStringLen =
  unsafeIOToMonadST . BS.packCStringLen

newtype MLockedAllocator m
  = MLockedAllocator
  { mlAllocate :: forall a. CSize -> m (MLockedForeignPtr a)
  }

mlockedAllocaSized ::
  forall m n b. (MonadST m, MonadThrow m, KnownNat n) => (SizedPtr n -> m b) -> m b
mlockedAllocaSized = mlockedAllocaSizedWith mlockedMalloc

mlockedAllocaSizedWith ::
  forall m n b.
  (MonadST m, MonadThrow m, KnownNat n) =>
  MLockedAllocator m ->
  (SizedPtr n -> m b) ->
  m b
mlockedAllocaSizedWith allocator k = mlockedAllocaWith allocator size (k . SizedPtr)
  where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))

mlockedAllocForeignPtrBytes :: MonadST m => CSize -> CSize -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrBytes = mlockedAllocForeignPtrBytesWith mlockedMalloc

mlockedAllocForeignPtrBytesWith :: MLockedAllocator m -> CSize -> CSize -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrBytesWith _ _ 0 =
  error "Zero alignment"
mlockedAllocForeignPtrBytesWith allocator size align = do
  mlAllocate allocator size'
  where
    size' :: CSize
    size'
      | m == 0 = size
      | otherwise = (q + 1) * align
      where
        (q, m) = size `quotRem` align

mlockedAllocForeignPtr :: forall a m. (MonadST m, Storable a) => m (MLockedForeignPtr a)
mlockedAllocForeignPtr = mlockedAllocForeignPtrWith mlockedMalloc

mlockedAllocForeignPtrWith ::
  forall a m.
  Storable a =>
  MLockedAllocator m ->
  m (MLockedForeignPtr a)
mlockedAllocForeignPtrWith allocator =
  mlockedAllocForeignPtrBytesWith allocator size align
  where
    dummy :: a
    dummy = undefined

    size :: CSize
    size = fromIntegral $ sizeOf dummy

    align :: CSize
    align = fromIntegral $ alignment dummy

mlockedAlloca :: forall a b m. (MonadST m, MonadThrow m) => CSize -> (Ptr a -> m b) -> m b
mlockedAlloca = mlockedAllocaWith mlockedMalloc

mlockedAllocaWith ::
  forall a b m.
  (MonadThrow m, MonadST m) =>
  MLockedAllocator m ->
  CSize ->
  (Ptr a -> m b) ->
  m b
mlockedAllocaWith allocator size =
  bracket alloc finalizeMLockedForeignPtr . flip withMLockedForeignPtr
  where
    alloc = mlAllocate allocator size
