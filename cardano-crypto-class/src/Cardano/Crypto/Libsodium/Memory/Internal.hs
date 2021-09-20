{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE CPP #-}
module Cardano.Crypto.Libsodium.Memory.Internal (
  -- * High-level memory management
  MLockedForeignPtr (..),
  withMLockedForeignPtr,
  allocMLockedForeignPtr,
  finalizeMLockedForeignPtr,
  traceMLockedForeignPtr,
  -- * Low-level memory function
  mlockedAlloca,
  mlockedAllocaSized,
  sodiumMalloc,
  sodiumFree,
  -- * Debugging / testing instrumentation
  AllocEvent (..),
  popAllocLogEvent,
) where

import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TChan (newTChanIO, TChan, tryReadTChan, writeTChan)
import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (bracket)
import Control.Monad (when)
import Data.Coerce (coerce)
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize (..))
import Foreign.Ptr (Ptr, nullPtr, WordPtr, ptrToWordPtr)
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr, finalizeForeignPtr)
import Foreign.Concurrent (newForeignPtr)
import Foreign.Storable (Storable (alignment, sizeOf, peek))
import GHC.TypeLits (KnownNat, natVal)
import GHC.IO.Exception (ioException)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafePerformIO)

import Cardano.Foreign
import Cardano.Crypto.Libsodium.C

data AllocEvent
  = AllocEv !WordPtr
  | FreeEv !WordPtr
  deriving (Eq, Show)

{-#NOINLINE allocLog #-}
allocLog :: TChan AllocEvent
allocLog = unsafePerformIO newTChanIO

popAllocLogEvent :: IO (Maybe AllocEvent)
popAllocLogEvent = atomically $ tryReadTChan allocLog

pushAllocLogEvent :: AllocEvent -> IO ()
pushAllocLogEvent = atomically . writeTChan allocLog

-- | Foreign pointer to securely allocated memory.
newtype MLockedForeignPtr a = SFP { _unwrapMLockedForeignPtr :: ForeignPtr a }
  deriving NoThunks via OnlyCheckWhnfNamed "MLockedForeignPtr" (MLockedForeignPtr a)

instance NFData (MLockedForeignPtr a) where
  rnf = rwhnf . _unwrapMLockedForeignPtr

withMLockedForeignPtr :: forall a b. MLockedForeignPtr a -> (Ptr a -> IO b) -> IO b
withMLockedForeignPtr = coerce (withForeignPtr @a @b)

finalizeMLockedForeignPtr :: forall a. MLockedForeignPtr a -> IO ()
finalizeMLockedForeignPtr = coerce (finalizeForeignPtr @a)

traceMLockedForeignPtr :: (Storable a, Show a) => MLockedForeignPtr a -> IO ()
traceMLockedForeignPtr fptr = withMLockedForeignPtr fptr $ \ptr -> do
    a <- peek ptr
    print a

{-# DEPRECATED traceMLockedForeignPtr "Don't leave traceMLockedForeignPtr in production" #-}

-- | Allocate secure memory using 'c_sodium_malloc'.
--
-- <https://libsodium.gitbook.io/doc/memory_management>
--
allocMLockedForeignPtr :: Storable a => IO (MLockedForeignPtr a)
allocMLockedForeignPtr = impl undefined where
    impl :: forall b. Storable b => b -> IO (MLockedForeignPtr b)
    impl b = do
        ptr <- sodiumMalloc size
        let finalizer = sodiumFree ptr
        fmap SFP (newForeignPtr ptr finalizer)

      where
        size :: CSize
        size = fromIntegral size''

        size' :: Int
        size' = sizeOf b

        align :: Int
        align = alignment b

        size'' :: Int
        size''
            | m == 0    = size'
            | otherwise = (q + 1) * align
          where
            (q,m) = size' `divMod` align

sodiumMalloc :: CSize -> IO (Ptr a)
sodiumMalloc size = do
    ptr <- c_sodium_malloc size
    when (ptr == nullPtr) $ do
        errno <- getErrno
        ioException $ errnoToIOError "c_sodium_malloc" errno Nothing Nothing
    -- putStrLn $ "sodiumMalloc " <> show ptr
    pushAllocLogEvent $ AllocEv (ptrToWordPtr ptr)
    return ptr

sodiumFree :: Ptr a -> IO ()
sodiumFree ptr = do
  -- putStrLn $ "sodiumFree " <> show ptr
  pushAllocLogEvent $ FreeEv (ptrToWordPtr ptr)
  c_sodium_free ptr

mlockedAlloca :: forall a b. CSize -> (Ptr a -> IO b) -> IO b
mlockedAlloca size = bracket (sodiumMalloc size) sodiumFree

mlockedAllocaSized :: forall n b. KnownNat n => (SizedPtr n -> IO b) -> IO b
mlockedAllocaSized k = mlockedAlloca size (k . SizedPtr) where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))
