{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -fprof-auto #-}
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
  pushAllocLogEvent,
  withAllocLog,
) where

import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TChan (newTChanIO, TChan, tryReadTChan, writeTChan)
import Control.Concurrent.STM.TVar (newTVarIO, TVar, readTVar, modifyTVar)
import Control.DeepSeq (NFData (..), rwhnf)
import Control.Exception (bracket, bracket_)
import Control.Monad (when)
import Data.Coerce (coerce)
import Data.Proxy (Proxy (..))
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize (..))
import Foreign.Ptr (Ptr, nullPtr, WordPtr, ptrToWordPtr)
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr, finalizeForeignPtr, castForeignPtr)
import Foreign.Concurrent (newForeignPtr)
import Foreign.Storable (Storable (alignment, sizeOf, peek))
import Foreign.Marshal.Utils (fillBytes)
import GHC.TypeLits (KnownNat, natVal)
import GHC.IO.Exception (ioException)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafePerformIO)
import System.IO (hPutStrLn, stderr)

import Cardano.Foreign
import Cardano.Crypto.Libsodium.C
import Cardano.Memory.Pool (initPool, grabNextBlock, Pool)

-- | Allocation log event. These are emitted automatically whenever mlocked
-- memory is allocated through the 'allocMLockedForeignPtr' primitive, or
-- released through an associated finalizer (either explicitly or due to GC).
-- Additional events that are not actual allocations/deallocations, but may
-- provide useful debugging context, can be inserted as 'MarkerEv'.
data AllocEvent
  = AllocEv !WordPtr
  | FreeEv !WordPtr
  | MarkerEv !String
  deriving (Eq, Show)

{-#NOINLINE allocLog #-}
allocLog :: TChan AllocEvent
allocLog = unsafePerformIO newTChanIO

{-#NOINLINE allocLogEnableCounter #-}
allocLogEnableCounter :: TVar Int
allocLogEnableCounter = unsafePerformIO $ newTVarIO 0

enableAllocLog :: IO ()
enableAllocLog = atomically $ modifyTVar allocLogEnableCounter succ

disableAllocLog :: IO ()
disableAllocLog = atomically $ modifyTVar allocLogEnableCounter pred

drainAllocLog :: IO [AllocEvent]
drainAllocLog =
  reverse <$> go []
  where
    go xs = do
      popAllocLogEvent >>= \case
        Nothing ->
          return xs
        Just x ->
          go (x:xs)

-- | Run an IO action with allocation logging. The allocation log for the
-- action will be returned as a list of events, in ascending chronological
-- order.
withAllocLog :: IO () -> IO [AllocEvent]
withAllocLog a =
  bracket_
    enableAllocLog
    disableAllocLog
    (a >> drainAllocLog)

popAllocLogEvent :: IO (Maybe AllocEvent)
popAllocLogEvent = atomically $ tryReadTChan allocLog

pushAllocLogEvent :: AllocEvent -> IO ()
pushAllocLogEvent ev = atomically $ do
  count <- readTVar allocLogEnableCounter
  when (count > 0) $
    writeTChan allocLog ev

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

makeMLockedPool :: forall n. KnownNat n => IO (Pool n)
makeMLockedPool = do
  hPutStrLn stderr "makeMLockedPool"
  initPool
    (fromIntegral $ 4096 `div` (natVal (Proxy @n)) `div` 64)
    (\size -> do
      ptr <- sodiumMalloc (fromIntegral size)
      newForeignPtr ptr (sodiumFree ptr)
    )
    (\ptr -> do
      eraseMem (Proxy @n) ptr
      pushAllocLogEvent $ FreeEv (ptrToWordPtr ptr)
    )

eraseMem :: forall n a. KnownNat n => Proxy n -> Ptr a -> IO ()
eraseMem proxy ptr = fillBytes ptr 0xff (fromIntegral $ natVal proxy)

mlpool32 :: Pool 32
mlpool32 = unsafePerformIO makeMLockedPool
{-#NOINLINE mlpool32 #-}

mlpool64 :: Pool 64
mlpool64 = unsafePerformIO makeMLockedPool
{-#NOINLINE mlpool64 #-}


-- | Allocate secure memory using 'c_sodium_malloc'.
--
-- <https://libsodium.gitbook.io/doc/memory_management>
--
-- allocMLockedForeignPtr :: Storable a => IO (MLockedForeignPtr a)
-- allocMLockedForeignPtr = impl undefined where
--     impl :: forall b. Storable b => b -> IO (MLockedForeignPtr b)
--     impl b = do
--         ptr <- sodiumMalloc size
--         let finalizer = sodiumFree ptr
--         fmap SFP (newForeignPtr ptr finalizer)
--
--       where
--         size :: CSize
--         size = fromIntegral size''
--
--         size' :: Int
--         size' = sizeOf b
--
--         align :: Int
--         align = alignment b
--
--         size'' :: Int
--         size''
--             | m == 0    = size'
--             | otherwise = (q + 1) * align
--           where
--             (q,m) = size' `divMod` align

allocMLockedForeignPtr :: forall a. Storable a => IO (MLockedForeignPtr a)
allocMLockedForeignPtr = do
  fptr <- mlockedMalloc size
  withForeignPtr fptr $ \ptr -> pushAllocLogEvent $ AllocEv (ptrToWordPtr ptr)

  return $ SFP . castForeignPtr $ fptr
  where
    b :: a
    b = undefined

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

mlockedMalloc :: CSize -> IO (ForeignPtr a)
mlockedMalloc size = do
  pushAllocLogEvent $ MarkerEv $ "Allocating " ++ show size ++ " bytes"
  if
    | size <= 32 -> do
        pushAllocLogEvent $ MarkerEv $ "Using 32-bit pool"
        coerce $ grabNextBlock mlpool32
    | size <= 64 -> do
        pushAllocLogEvent $ MarkerEv $ "Using 64-bit pool"
        coerce $ grabNextBlock mlpool64
    | otherwise -> do
        pushAllocLogEvent $ MarkerEv $ "Using direct allocation"
        ptr <- sodiumMalloc (fromIntegral size)
        newForeignPtr ptr $ do
          pushAllocLogEvent $ FreeEv (ptrToWordPtr ptr)
          sodiumFree ptr

mlockedAlloca :: forall a b. CSize -> (Ptr a -> IO b) -> IO b
mlockedAlloca size =
  bracket alloc free . flip withForeignPtr
  where
    alloc = mlockedMalloc size
    free = finalizeForeignPtr


mlockedAllocaSized :: forall n b. KnownNat n => (SizedPtr n -> IO b) -> IO b
mlockedAllocaSized k = mlockedAlloca size (k . SizedPtr) where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))

sodiumMalloc :: CSize -> IO (Ptr a)
sodiumMalloc size = do
    ptr <- c_sodium_malloc size
    when (ptr == nullPtr) $ do
        errno <- getErrno
        ioException $ errnoToIOError "c_sodium_malloc" errno Nothing Nothing
    return ptr

sodiumFree :: Ptr a -> IO ()
sodiumFree ptr = do
  c_sodium_free ptr
