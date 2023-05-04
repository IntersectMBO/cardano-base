{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Test.Crypto.AllocLog where

import Control.Tracer
import Control.Monad.Reader
import Data.Typeable
import Foreign.Ptr
import Foreign.Concurrent
import Control.Monad.Class.MonadThrow
import Control.Monad.Class.MonadST
import System.Random

import Cardano.Crypto.Libsodium (withMLockedForeignPtr)
import Cardano.Crypto.Libsodium.Memory (getAllocatorEvent, MLockedAllocator(..))
import Cardano.Crypto.Libsodium.Memory.Internal (MLockedForeignPtr (..))

-- | Allocation log event. These are emitted automatically whenever mlocked
-- memory is allocated through the 'mlockedAllocForeignPtr' primitive, or
-- released through an associated finalizer (either explicitly or due to GC).
-- Additional events that are not actual allocations/deallocations, but may
-- provide useful debugging context, can be inserted as 'MarkerEv'.
data AllocEvent
  = AllocEv !WordPtr
  | FreeEv !WordPtr
  | MarkerEv !String
  deriving (Eq, Show, Typeable)

newtype LogT event m a = LogT { unLogT :: ReaderT (Tracer m event) m a }
  deriving (Functor, Applicative, Monad, MonadThrow, MonadST, Typeable, MonadIO)

type AllocLogT = LogT AllocEvent

instance Monad m => MonadReader (Tracer m event) (LogT event m) where
  ask = LogT ask
  local f (LogT action) = LogT (local f action)

instance MonadTrans (LogT event) where
  lift action = LogT (lift action)

runLogT :: Tracer m event -> LogT event m a -> m a
runLogT tracer action = runReaderT (unLogT action) tracer

pushLogEvent :: Monad m => event -> LogT event m ()
pushLogEvent event = do
  tracer <- ask
  lift $ traceWith tracer event

-- The below no longer works without MonadMLock.

-- instance (MonadIO m, MonadThrow m, MonadMLock m, MonadST m, RunIO m)
--          => MonadMLock (LogT AllocEvent m) where
--   withMLockedForeignPtr fptr action = LogT $ do
--     tracer <- ask
--     lift $ withMLockedForeignPtr fptr (\ptr -> (runReaderT . unLogT) (action ptr) tracer)
--
--   finalizeMLockedForeignPtr = lift . finalizeMLockedForeignPtr
--
--   traceMLockedForeignPtr = lift . traceMLockedForeignPtr
--
--   mlockedMalloc size = do
--     fptr <- lift (mlockedMalloc size)
--     addr <- withMLockedForeignPtr fptr (return . ptrToWordPtr)
--     pushAllocLogEvent (AllocEv addr)
--     tracer :: Tracer (LogT event m) event <- ask
--     withLiftST $ \liftST -> liftST . unsafeIOToST $
--       addForeignPtrFinalizer
--         (coerce fptr)
--         (io . runLogT tracer . pushAllocLogEvent $ FreeEv addr)
--     return fptr

mkLoggingAllocator ::
  MLockedAllocator IO -> LogT AllocEvent IO (MLockedAllocator (LogT AllocEvent IO))
mkLoggingAllocator ioAllocator = do
  tracer <- ask
  pure $ MLockedAllocator
    { mlAllocate =
        \size ->
          liftIO $ do
            sfptr@(SFP fptr) <- mlAllocate ioAllocator size
            addr <- withMLockedForeignPtr sfptr (return . ptrToWordPtr)
            traceWith tracer (AllocEv addr)
            addForeignPtrFinalizer fptr (traceWith tracer (FreeEv addr))
            return sfptr
    , mlTrace = liftIO . mapM_ (traceWith tracer) . getAllocatorEvent
    , mlUniformWord = randomRIO
    }
