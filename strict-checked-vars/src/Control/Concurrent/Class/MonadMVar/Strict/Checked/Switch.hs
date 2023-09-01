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
import           Control.Concurrent.Class.MonadMVar.Strict.Checked hiding
                                                                   (checkInvariant,
                                                                    modifyMVar,
                                                                    modifyMVarMasked,
                                                                    modifyMVarMasked_,
                                                                    modifyMVar_,
                                                                    newEmptyMVarWithInvariant,
                                                                    newMVarWithInvariant,
                                                                    putMVar,
                                                                    swapMVar,
                                                                    tryPutMVar)
import qualified Control.Concurrent.Class.MonadMVar.Strict.Checked as StrictMVar.Checked
#else
import           Control.Concurrent.Class.MonadMVar.Strict         hiding
                                                                   (modifyMVar,
                                                                    modifyMVarMasked,
                                                                    modifyMVarMasked_,
                                                                    modifyMVar_,
                                                                    putMVar,
                                                                    swapMVar,
                                                                    tryPutMVar)
import qualified Control.Concurrent.Class.MonadMVar.Strict         as StrictMVar
#endif
import           GHC.Stack                                         (HasCallStack)

newEmptyMVarWithInvariant :: MonadMVar m
                          => (a -> Maybe String)
                          -> m (StrictMVar m a)

newMVarWithInvariant :: (HasCallStack, MonadMVar m)
                     => (a -> Maybe String)
                     -> a
                     -> m (StrictMVar m a)

putMVar :: (HasCallStack, MonadMVar m) => StrictMVar m a -> a -> m ()

swapMVar :: (HasCallStack, MonadMVar m) => StrictMVar m a -> a -> m a

tryPutMVar :: (HasCallStack, MonadMVar m) => StrictMVar m a -> a -> m Bool

modifyMVar_ :: (HasCallStack, MonadMVar m)
            => StrictMVar m a
            -> (a -> m a)
            -> m ()

modifyMVar :: (HasCallStack, MonadMVar m)
           => StrictMVar m a
           -> (a -> m (a,b))
           -> m b

modifyMVarMasked_ :: (HasCallStack, MonadMVar m)
                  => StrictMVar m a
                  -> (a -> m a)
                  -> m ()

modifyMVarMasked :: (HasCallStack, MonadMVar m)
                 => StrictMVar m a
                 -> (a -> m (a,b))
                 -> m b

checkInvariant :: HasCallStack => Maybe String -> a -> a

#if CHECK_MVAR_INVARIANTS
newEmptyMVarWithInvariant   = StrictMVar.Checked.newEmptyMVarWithInvariant
newMVarWithInvariant        = StrictMVar.Checked.newMVarWithInvariant
putMVar                     = StrictMVar.Checked.putMVar
swapMVar                    = StrictMVar.Checked.swapMVar
tryPutMVar                  = StrictMVar.Checked.tryPutMVar
modifyMVar_                 = StrictMVar.Checked.modifyMVar_
modifyMVar                  = StrictMVar.Checked.modifyMVar
modifyMVarMasked_           = StrictMVar.Checked.modifyMVarMasked_
modifyMVarMasked            = StrictMVar.Checked.modifyMVarMasked
checkInvariant              = StrictMVar.Checked.checkInvariant
#else
newEmptyMVarWithInvariant _ = StrictMVar.newEmptyMVar
newMVarWithInvariant _      = StrictMVar.newMVar
putMVar                     = StrictMVar.putMVar
swapMVar                    = StrictMVar.swapMVar
tryPutMVar                  = StrictMVar.tryPutMVar
modifyMVar_                 = StrictMVar.modifyMVar_
modifyMVar                  = StrictMVar.modifyMVar
modifyMVarMasked_           = StrictMVar.modifyMVarMasked_
modifyMVarMasked            = StrictMVar.modifyMVarMasked
checkInvariant              = \_ a -> a
#endif
