{-# LANGUAGE CPP #-}

module Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.Switch (
    -- * StrictTVar
    LazyTVar
  , StrictTVar
  , castStrictTVar
  , fromLazyTVar
  , modifyTVar
  , newTVar
  , newTVarIO
  , newTVarWithInvariant
  , newTVarWithInvariantIO
  , readTVar
  , readTVarIO
  , stateTVar
  , swapTVar
  , toLazyTVar
  , writeTVar
    -- * MonadLabelSTM
  , labelTVar
  , labelTVarIO
    -- * MonadTraceSTM
  , traceTVar
  , traceTVarIO
    -- * invariant
  , checkInvariant
  ) where

import           Control.Concurrent.Class.MonadSTM (MonadSTM, STM)
#if CHECK_TVAR_INVARIANTS
import qualified Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked as StrictTVar.Checked
import           Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked hiding (checkInvariant, newTVarWithInvariant, newTVarWithInvariantIO)
#else
import qualified Control.Concurrent.Class.MonadSTM.Strict.TVar as StrictTVar
import           Control.Concurrent.Class.MonadSTM.Strict.TVar
#endif
import           GHC.Stack (HasCallStack)

newTVarWithInvariant :: (MonadSTM m, HasCallStack)
                     => (a -> Maybe String)
                     -> a
                     -> STM m (StrictTVar m a)
#if CHECK_TVAR_INVARIANTS
newTVarWithInvariant   = StrictTVar.Checked.newTVarWithInvariant
#else
newTVarWithInvariant _ = StrictTVar.newTVar
#endif

newTVarWithInvariantIO :: (MonadSTM m, HasCallStack)
                       => (a -> Maybe String)
                       -> a
                       -> m (StrictTVar m a)
#if CHECK_TVAR_INVARIANTS
newTVarWithInvariantIO   = StrictTVar.Checked.newTVarWithInvariantIO
#else
newTVarWithInvariantIO _ = StrictTVar.newTVarIO
#endif

checkInvariant :: HasCallStack => Maybe String -> a -> a
#if CHECK_TVAR_INVARIANTS
checkInvariant = StrictTVar.Checked.checkInvariant
#else
checkInvariant = \_ a -> a
#endif