{-# LANGUAGE LambdaCase    #-}
{-# LANGUAGE TupleSections #-}

module Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF where

import           Control.Concurrent.Class.MonadSTM (MonadSTM, STM, atomically)
import           Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked hiding
                     (newTVar, newTVarIO, newTVarWithInvariant,
                     newTVarWithInvariantIO)
import qualified Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked as Checked
import           Control.Monad (void)
import           Control.Monad.IOSim (runSimOrThrow)
import           Data.Typeable (Typeable)
import           NoThunks.Class (OnlyCheckWhnf (..), unsafeNoThunks)
import           Test.Tasty (TestTree, testGroup)
import           Test.Tasty.QuickCheck (Fun, Property, applyFun, counterexample,
                     ioProperty, property, testProperty)
import           Test.Utils (Invariant (..), (..:))

{-------------------------------------------------------------------------------
  Main test tree
-------------------------------------------------------------------------------}

tests :: TestTree
tests = testGroup "Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF" [
      testGroup "IO"    testIO
    , testGroup "IOSim" testIOSim
    ]
  where
    testIO = [
          testProperty "prop_newTVarWithInvariant_IO"
            prop_newTVarWithInvariant_IO
        , testProperty "prop_newTVarWithInvariantIO_IO"
            prop_newTVarWithInvariantIO_IO
        , testProperty "prop_writeTVar_IO"
            prop_writeTVar_IO
        , testProperty "prop_modifyTVar_IO"
            prop_modifyTVar_IO
        , testProperty "prop_stateTVar_IO"
            prop_stateTVar_IO
        , testProperty "prop_swapTVar_IO"
            prop_swapTVar_IO
        ]

    testIOSim = [
          testProperty "prop_newTVarWithInvariant_IOSim"
            prop_newTVarWithInvariant_IOSim
        , testProperty "prop_newTVarWithInvariantIO_IOSim"
            prop_newTVarWithInvariantIO_IOSim
        , testProperty "prop_writeTVar_IOSim"
            prop_writeTVar_IOSim
        , testProperty "prop_modifyTVar_IOSim"
            prop_modifyTVar_IOSim
        , testProperty "prop_stateTVar"
            prop_stateTVar_IOSim
        , testProperty "prop_swapTVar"
            prop_swapTVar_IOSim
        ]

{-------------------------------------------------------------------------------
  Utilities
-------------------------------------------------------------------------------}

isInWHNF :: (MonadSTM m, Typeable a) => StrictTVar m a -> m Property
isInWHNF v = do
    x <- readTVarIO v
    pure $ case unsafeNoThunks (OnlyCheckWhnf x) of
      Nothing    -> property True
      Just tinfo -> counterexample ("Not in WHNF: " ++ show tinfo)
                  $ property False

-- | Wrapper around 'Checked.newTVar' and 'Checked.newTVarWithInvariant'.
newTVarWithInvariant :: MonadSTM m => Invariant a -> a -> STM m (StrictTVar m a)
newTVarWithInvariant = \case
    NoInvariant     -> Checked.newTVar
    Invariant _ inv -> Checked.newTVarWithInvariant inv

-- | Wrapper around 'Checked.newTVarIO' and 'Checked.newTVarWithInvariantIO'.
newTVarWithInvariantIO :: MonadSTM m => Invariant a -> a -> m (StrictTVar m a)
newTVarWithInvariantIO = \case
    NoInvariant     -> Checked.newTVarIO
    Invariant _ inv -> Checked.newTVarWithInvariantIO inv

-- | The 'isInWHNF' check fails when running tests in 'IOSim', since 'IOSim'
-- runs in the lazy 'ST' monad. 'withSanityCheckWhnf' can be used to perform the
-- test conditionally.
withSanityCheckWhnf ::
     (MonadSTM m, Typeable a)
  => Bool
  -> StrictTVar m a
  -> m Property
withSanityCheckWhnf check v =
    if check then
      isInWHNF v
    else
      pure $ property True

{-------------------------------------------------------------------------------
  Properties
-------------------------------------------------------------------------------}

--
-- newTVarWithInvariant
--

-- | Test 'newTVarWithInvariant', not to be confused with
-- 'Checked.newTVarWithInvariant'.
prop_newTVarWithInvariant_M ::
     MonadSTM m
  => Bool
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_newTVarWithInvariant_M check inv x f = do
    v <- atomically $ newTVarWithInvariant inv (applyFun f x)
    withSanityCheckWhnf check v

prop_newTVarWithInvariant_IO ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_newTVarWithInvariant_IO = ioProperty ..:
    prop_newTVarWithInvariant_M True

prop_newTVarWithInvariant_IOSim ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_newTVarWithInvariant_IOSim inv x f = runSimOrThrow $
    prop_newTVarWithInvariant_M False inv x f

--
-- newTVarWithInvariantIO
--

-- | Test 'newTVarWithInvariantIO', not to be confused with
-- 'Checked.newTVarWithInvariantIO'.
prop_newTVarWithInvariantIO_M ::
     MonadSTM m
  => Bool
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_newTVarWithInvariantIO_M check inv x f = do
    v <- newTVarWithInvariantIO inv (applyFun f x)
    withSanityCheckWhnf check v

prop_newTVarWithInvariantIO_IO ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_newTVarWithInvariantIO_IO = ioProperty ..:
    prop_newTVarWithInvariantIO_M True

prop_newTVarWithInvariantIO_IOSim ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_newTVarWithInvariantIO_IOSim inv x f = runSimOrThrow $
    prop_newTVarWithInvariantIO_M False inv x f

--
-- writeTVar
--

prop_writeTVar_M ::
     MonadSTM m
  => Bool
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_writeTVar_M check inv x f = do
    v <- newTVarWithInvariantIO inv x
    atomically $ writeTVar v (applyFun f x)
    withSanityCheckWhnf check v

prop_writeTVar_IO ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_writeTVar_IO = ioProperty ..:
    prop_writeTVar_M True

prop_writeTVar_IOSim ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_writeTVar_IOSim inv x f = runSimOrThrow $
    prop_writeTVar_M False inv x f

--
-- modifyTVar
--

prop_modifyTVar_M ::
     MonadSTM m
  => Bool
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_modifyTVar_M check inv x f = do
    v <- newTVarWithInvariantIO inv x
    atomically $ modifyTVar v (applyFun f)
    withSanityCheckWhnf check v

prop_modifyTVar_IO ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_modifyTVar_IO = ioProperty ..:
    prop_modifyTVar_M True

prop_modifyTVar_IOSim ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_modifyTVar_IOSim inv x f = runSimOrThrow $
    prop_modifyTVar_M False inv x f

--
-- stateTVar
--

prop_stateTVar_M ::
     MonadSTM m
  => Bool
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_stateTVar_M check inv x f = do
    v <- newTVarWithInvariantIO inv x
    atomically $ stateTVar v (((),) . applyFun f)
    withSanityCheckWhnf check v

prop_stateTVar_IO ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_stateTVar_IO = ioProperty ..:
    prop_stateTVar_M True

prop_stateTVar_IOSim ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_stateTVar_IOSim inv x f = runSimOrThrow $
    prop_stateTVar_M False inv x f

--
-- swapTVar
--

prop_swapTVar_M ::
     MonadSTM m
  => Bool
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_swapTVar_M check inv x f = do
    v <- newTVarWithInvariantIO inv x
    void $ atomically $ swapTVar v (applyFun f x)
    withSanityCheckWhnf check v

prop_swapTVar_IO ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_swapTVar_IO = ioProperty ..:
    prop_swapTVar_M True

prop_swapTVar_IOSim ::
     Invariant Int
  -> Int
  -> Fun Int Int
  -> Property
prop_swapTVar_IOSim inv x f = runSimOrThrow $
    prop_swapTVar_M False inv x f
