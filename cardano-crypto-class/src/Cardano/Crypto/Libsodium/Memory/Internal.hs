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
  AllocatorEvent(..),
  getAllocatorEvent,

  mlockedAlloca,
  mlockedAllocaSized,
  mlockedAllocForeignPtr,
  mlockedAllocForeignPtrBytes,

  -- * Allocations using an explicit allocator
  mlockedAllocaWith,
  mlockedAllocaSizedWith,
  mlockedAllocForeignPtrWith,
  mlockedAllocForeignPtrBytesWith,

  -- * Unmanaged memory, generalized to 'MonadST'
  zeroMem,
  copyMem,
  allocaBytes,

  -- * ByteString memory access, generalized to 'MonadST'
  useByteStringAsCStringLen,
  packByteStringCStringLen,

  -- * Helper
  unsafeIOToMonadST
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (Exception, mask_)
import Control.Monad (when, void)
import Control.Monad.Class.MonadST
import Control.Monad.Class.MonadThrow (MonadThrow (bracket))
import Control.Monad.ST
import Control.Monad.ST.Unsafe (unsafeIOToST, unsafeSTToIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Coerce (coerce)
import Data.Typeable
import Debug.Trace (traceShowM)
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.String (CStringLen)
import Foreign.C.Types (CSize (..))
import Foreign.Concurrent (newForeignPtr)
import Foreign.ForeignPtr (ForeignPtr, finalizeForeignPtr, touchForeignPtr)
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
import qualified Foreign.Marshal.Alloc as Foreign
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, nullPtr, castPtr)
import Foreign.Storable (Storable (peek), sizeOf, alignment)
import GHC.IO.Exception (ioException)
import GHC.TypeLits (KnownNat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafePerformIO)

import Cardano.Crypto.Libsodium.C
import Cardano.Foreign (c_memset, c_memcpy, SizedPtr (..))
import Cardano.Memory.Pool (initPool, grabNextBlock, Pool)

-- | Foreign pointer to securely allocated memory.
newtype MLockedForeignPtr a = SFP { _unwrapMLockedForeignPtr :: ForeignPtr a }
  deriving NoThunks via OnlyCheckWhnfNamed "MLockedForeignPtr" (MLockedForeignPtr a)

instance NFData (MLockedForeignPtr a) where
  rnf = rwhnf . _unwrapMLockedForeignPtr

withMLockedForeignPtr :: MonadST m => MLockedForeignPtr a -> (Ptr a -> m b) -> m b
withMLockedForeignPtr (SFP fptr) f = do
  r <- f (unsafeForeignPtrToPtr fptr)
  r <$ unsafeIOToMonadST (touchForeignPtr fptr)

finalizeMLockedForeignPtr :: MonadST m => MLockedForeignPtr a -> m ()
finalizeMLockedForeignPtr (SFP fptr) = withLiftST $ \lift ->
  (lift . unsafeIOToST) (finalizeForeignPtr fptr)

{-# WARNING traceMLockedForeignPtr "Do not use traceMLockedForeignPtr in production" #-}

traceMLockedForeignPtr :: (Storable a, Show a, MonadST m) => MLockedForeignPtr a -> m ()
traceMLockedForeignPtr fptr = withMLockedForeignPtr fptr $ \ptr -> do
    a <- unsafeIOToMonadST (peek ptr)
    traceShowM a

unsafeIOToMonadST :: MonadST m => IO a -> m a
unsafeIOToMonadST action = withLiftST ($ unsafeIOToST action)

makeMLockedPool :: forall n s. KnownNat n => ST s (Pool n s)
makeMLockedPool = do
  initPool
    (max 1 . fromIntegral $ 4096 `div` natVal (Proxy @n) `div` 64)
    (\size -> unsafeIOToST $ mask_ $ do
      ptr <- sodiumMalloc (fromIntegral size)
      newForeignPtr ptr (sodiumFree ptr (fromIntegral size))
    )
    (\ptr -> do
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

data AllocatorException =
  AllocatorNoTracer
  | AllocatorNoGenerator
  deriving Show

instance Exception AllocatorException

mlockedMalloc :: MonadST m => MLockedAllocator m
mlockedMalloc =
  MLockedAllocator { mlAllocate = \ size -> withLiftST ($ unsafeIOToST (mlockedMallocIO size)) }

mlockedMallocIO :: CSize -> IO (MLockedForeignPtr a)
mlockedMallocIO size = SFP <$> do
  if
    | size <= 32 -> do
        coerce $ stToIO $ grabNextBlock mlockedPool32
    | size <= 64 -> do
        coerce $ stToIO $ grabNextBlock mlockedPool64
    | size <= 128 -> do
        coerce $ stToIO $ grabNextBlock mlockedPool128
    | size <= 256 -> do
        coerce $ stToIO $ grabNextBlock mlockedPool256
    | size <= 512 -> do
        coerce $ stToIO $ grabNextBlock mlockedPool512
    | otherwise -> do
        mask_ $ do
          ptr <- sodiumMalloc size
          newForeignPtr ptr $ do
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

allocaBytes :: Int -> (Ptr a -> ST s b) -> ST s b
allocaBytes size f =
  unsafeIOToST $ Foreign.allocaBytes size (unsafeSTToIO . f)

useByteStringAsCStringLen :: ByteString -> (CStringLen -> ST s a) -> ST s a
useByteStringAsCStringLen bs f =
  allocaBytes (BS.length bs + 1) $ \buf -> do
    len <- unsafeIOToST $ BS.unsafeUseAsCStringLen bs $ \(ptr, len) ->
      len <$ copyMem buf ptr (fromIntegral len)
    f (buf, len)

packByteStringCStringLen :: MonadST m => CStringLen -> m ByteString
packByteStringCStringLen (ptr, len) =
  withLiftST $ \lift -> lift . unsafeIOToST $ BS.packCStringLen (ptr, len)

data AllocatorEvent where
  AllocatorEvent :: (Show e, Typeable e) => e -> AllocatorEvent

instance Show AllocatorEvent where
  show (AllocatorEvent e) = "(AllocatorEvent " ++ show e ++ ")"

getAllocatorEvent :: forall e. Typeable e => AllocatorEvent -> Maybe e
getAllocatorEvent (AllocatorEvent e) = cast e

newtype MLockedAllocator m =
  MLockedAllocator
    { mlAllocate :: forall a. CSize -> m (MLockedForeignPtr a)
    }

mlockedAllocaSized :: forall m n b. (MonadST m, MonadThrow m, KnownNat n) => (SizedPtr n -> m b) -> m b
mlockedAllocaSized = mlockedAllocaSizedWith mlockedMalloc

mlockedAllocaSizedWith ::
     forall m n b. (MonadST m, MonadThrow m, KnownNat n)
  => MLockedAllocator m
  -> (SizedPtr n -> m b)
  -> m b
mlockedAllocaSizedWith allocator k = mlockedAllocaWith allocator size (k . SizedPtr) where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))

mlockedAllocForeignPtrBytes :: MonadST m => CSize -> CSize -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrBytes = mlockedAllocForeignPtrBytesWith mlockedMalloc

mlockedAllocForeignPtrBytesWith :: MLockedAllocator m -> CSize -> CSize -> m (MLockedForeignPtr a)
mlockedAllocForeignPtrBytesWith allocator size align = do
  mlAllocate allocator size'
  where
    size' :: CSize
    size'
        | m == 0    = size
        | otherwise = (q + 1) * align
      where
        (q,m) = size `quotRem` align

mlockedAllocForeignPtr :: forall a m . (MonadST m, Storable a) => m (MLockedForeignPtr a)
mlockedAllocForeignPtr = mlockedAllocForeignPtrWith mlockedMalloc

mlockedAllocForeignPtrWith ::
     forall a m. Storable a
  => MLockedAllocator m
  -> m (MLockedForeignPtr a)
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
     forall a b m. (MonadThrow m, MonadST m)
  => MLockedAllocator m
  -> CSize
  -> (Ptr a -> m b)
  -> m b
mlockedAllocaWith allocator size =
  bracket alloc free . flip withMLockedForeignPtr
  where
    alloc = mlAllocate allocator size
    free = finalizeMLockedForeignPtr
