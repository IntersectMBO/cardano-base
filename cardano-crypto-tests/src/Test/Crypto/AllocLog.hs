{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
module Test.Crypto.AllocLog where

import Cardano.Crypto.MonadSodium
import Cardano.Crypto.Libsodium.Memory.Internal (MLockedForeignPtr (..))
import Control.Tracer
import Control.Monad.Reader
import Foreign.Ptr
import Control.Monad.Class.MonadThrow
import Control.Monad.Class.MonadST
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Data.Typeable
import Data.Coerce (coerce)
import Foreign.Concurrent (addForeignPtrFinalizer)
import Test.Crypto.RunIO

-- | Allocation log event. These are emitted automatically whenever mlocked
-- memory is allocated through the 'mlockedAllocForeignPtr' primitive, or
-- released through an associated finalizer (either explicitly or due to GC).
-- Additional events that are not actual allocations/deallocations, but may
-- provide useful debugging context, can be inserted as 'MarkerEv'.
data AllocEvent
  = AllocEv !WordPtr
  | FreeEv !WordPtr
  | MarkerEv !String
  deriving (Eq, Show)

newtype LogT event m a = LogT { unLogT :: ReaderT (Tracer (LogT event m) event) m a }
  deriving (Functor, Applicative, Monad, MonadThrow, MonadST, Typeable, MonadIO)

type AllocLogT = LogT AllocEvent

instance Monad m => MonadReader (Tracer (LogT event m) event) (LogT event m) where
  ask = LogT ask
  local f (LogT action) = LogT (local f action)

instance MonadTrans (LogT event) where
  lift action = LogT (lift action)

runLogT :: Tracer (LogT event m) event -> LogT event m a -> m a
runLogT tracer action = runReaderT (unLogT action) tracer

runAllocLogT :: Tracer (LogT AllocEvent m) AllocEvent -> LogT AllocEvent m a -> m a
runAllocLogT = runLogT

pushLogEvent :: Monad m => event -> LogT event m ()
pushLogEvent event = do
  tracer <- ask
  traceWith tracer event

pushAllocLogEvent :: Monad m => AllocEvent -> LogT AllocEvent m ()
pushAllocLogEvent = pushLogEvent

-- | Automatically log all mlocked allocation events (allocate and free) via
-- 'mlockedAlloca', 'mlockedMalloc', and associated finalizers.
instance (MonadIO m, MonadThrow m, MonadSodium m, MonadST m, RunIO m)
         => MonadSodium (LogT AllocEvent m) where
  withMLockedForeignPtr fptr action = LogT $ do
    tracer <- ask
    lift $ withMLockedForeignPtr fptr (\ptr -> (runReaderT . unLogT) (action ptr) tracer)

  finalizeMLockedForeignPtr = lift . finalizeMLockedForeignPtr

  traceMLockedForeignPtr = lift . traceMLockedForeignPtr

  mlockedMalloc size = do
    fptr <- lift (mlockedMalloc size)
    addr <- withMLockedForeignPtr fptr (return . ptrToWordPtr)
    pushAllocLogEvent (AllocEv addr)
    tracer :: Tracer (LogT event m) event <- ask
    withLiftST $ \liftST -> liftST . unsafeIOToST $
      addForeignPtrFinalizer
        (coerce fptr)
        (io . runLogT tracer . pushAllocLogEvent $ FreeEv addr)
    return fptr

  zeroMem addr size = lift $ zeroMem addr size
  copyMem dst src size = lift $ copyMem dst src size

-- | Newtype wrapper over an arbitrary event; we use this to write the generic
-- 'MonadSodium' instance below while avoiding overlapping instances.
newtype GenericEvent e = GenericEvent { concreteEvent :: e }

-- | Generic instance, log nothing automatically. Log entries can be triggered
-- manually using 'pushLogEvent'.
instance MonadSodium m => MonadSodium (LogT (GenericEvent e) m) where
  withMLockedForeignPtr fptr (action) = LogT $ do
    tracer <- ask
    lift $ withMLockedForeignPtr fptr (\ptr -> (runReaderT . unLogT) (action ptr) tracer)

  finalizeMLockedForeignPtr = lift . finalizeMLockedForeignPtr
  traceMLockedForeignPtr = lift . traceMLockedForeignPtr
  mlockedMalloc size = lift (mlockedMalloc size)

  zeroMem addr size = lift $ zeroMem addr size
  copyMem dst src size = lift $ copyMem dst src size
