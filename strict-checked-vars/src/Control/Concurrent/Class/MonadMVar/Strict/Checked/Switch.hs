{-# LANGUAGE CPP #-}

module Control.Concurrent.Class.MonadMVar.Strict.Checked.Switch (
    -- * StrictMVar
    LazyMVar
  , StrictMVar
  , castStrictMVar
  , fromLazyMVar
  , isEmptyMVar
  , modifyMVar
  , modifyMVarMasked
  , modifyMVarMasked_
  , modifyMVar_
  , newEmptyMVar
  , newEmptyMVarWithInvariant
  , newMVar
  , newMVarWithInvariant
  , putMVar
  , readMVar
  , swapMVar
  , takeMVar
  , toLazyMVar
  , tryPutMVar
  , tryReadMVar
  , tryTakeMVar
  , withMVar
  , withMVarMasked
    -- * Invariant
  , checkInvariant
    -- * Re-exports
  , MonadMVar
  ) where

#if CHECK_MVAR_INVARIANTS
import qualified Control.Concurrent.Class.MonadMVar.Strict.Checked as StrictMVar.Checked
import           Control.Concurrent.Class.MonadMVar.Strict.Checked hiding (checkInvariant, newMVarWithInvariant, newEmptyMVarWithInvariant)
#else
import qualified Control.Concurrent.Class.MonadMVar.Strict as StrictMVar
import           Control.Concurrent.Class.MonadMVar.Strict
#endif
import           GHC.Stack (HasCallStack)

newEmptyMVarWithInvariant :: MonadMVar m
                          => (a -> Maybe String)
                          -> m (StrictMVar m a)
#if CHECK_MVAR_INVARIANTS
newEmptyMVarWithInvariant   = StrictMVar.Checked.newEmptyMVarWithInvariant
#else
newEmptyMVarWithInvariant _ = StrictMVar.newEmptyMVar
#endif

newMVarWithInvariant :: (HasCallStack, MonadMVar m)
                     => (a -> Maybe String)
                     -> a
                     -> m (StrictMVar m a)
#if CHECK_MVAR_INVARIANTS
newMVarWithInvariant   = StrictMVar.Checked.newMVarWithInvariant
#else
newMVarWithInvariant _ = StrictMVar.newMVar
#endif

checkInvariant :: HasCallStack => Maybe String -> a -> a
#if CHECK_MVAR_INVARIANTS
checkInvariant = StrictMVar.Checked.checkInvariant
#else
checkInvariant = \_ a -> a
#endif