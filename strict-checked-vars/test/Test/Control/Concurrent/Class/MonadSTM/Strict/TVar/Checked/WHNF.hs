{-# LANGUAGE LambdaCase    #-}
{-# LANGUAGE TupleSections #-}

module Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF where

import           Control.Concurrent.Class.MonadSTM (MonadSTM, STM, atomically)
import           Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked hiding
                     (newTVar, newTVarIO, newTVarWithInvariant,
                     newTVarWithInvariantIO)
import qualified Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked as Checked
import           Control.Monad (void)
import           Data.Typeable (Typeable)
import           NoThunks.Class (OnlyCheckWhnf (OnlyCheckWhnf), unsafeNoThunks)
import           Test.QuickCheck.Monadic (PropertyM, monadicIO, monitor, run)
import           Test.Tasty (TestTree, testGroup)
import           Test.Tasty.QuickCheck (Fun, applyFun, counterexample,
                     testProperty)
import           Test.Utils (Invariant (..), monadicSim, noInvariant,
                     trivialInvariant, whnfInvariant, (.:))

{-------------------------------------------------------------------------------
  Main test tree
-------------------------------------------------------------------------------}

tests :: TestTree
tests = testGroup "Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF" [
      testGroup "IO" [
          testIO    "No invariant"      sanityCheckWhnf   noInvariant
        , testIO    "Trivial invariant" sanityCheckWhnf   trivialInvariant
        , testIO    "WHNF invariant"    sanityCheckWhnf   whnfInvariant
        ]
      -- Sanity checks for WHNF fail in IOSim because IOSim runs in the lazy ST
      -- monad, so we turn off sanity checks here.
    , testGroup "IOSim" [
          testIOSim "No invariant"      noSanityCheckWhnf noInvariant
        , testIOSim "Trivial invariant" noSanityCheckWhnf trivialInvariant
        , testIOSim "WHNF invariant"    noSanityCheckWhnf whnfInvariant
        ]
    ]
  where
    testIO name check inv = testGroup name [
          testProperty "prop_newTVarWithInvariant" $
            monadicIO .: prop_newTVarWithInvariant check inv
        , testProperty "prop_newTVarWithInvariantIO" $
            monadicIO .: prop_newTVarWithInvariantIO check inv
        , testProperty "prop_writeTVar" $
            monadicIO .: prop_writeTVar check inv
        , testProperty "prop_modifyTVar" $
            monadicIO .: prop_modifyTVar check inv
        , testProperty "prop_stateTVar" $
            monadicIO .: prop_stateTVar check inv
        , testProperty "prop_swapTVar" $
            monadicIO .: prop_swapTVar check inv
        ]

    testIOSim name check inv = testGroup name [
          testProperty "prop_newTVarWithInvariant" $ \x f ->
            monadicSim $ prop_newTVarWithInvariant check inv x f
        , testProperty "prop_newTVarWithInvariantIO" $ \x f ->
            monadicSim $ prop_newTVarWithInvariantIO check inv x f
        , testProperty "prop_writeTVar" $ \x f ->
            monadicSim $ prop_writeTVar check inv x f
        , testProperty "prop_modifyTVar" $ \x f ->
            monadicSim $ prop_modifyTVar check inv x f
        , testProperty "prop_stateTVar" $ \x f ->
            monadicSim $ prop_stateTVar check inv x f
        , testProperty "prop_swapTVar" $ \x f ->
            monadicSim $ prop_swapTVar check inv x f
        ]

{-------------------------------------------------------------------------------
  Utilities
-------------------------------------------------------------------------------}


isInWHNF :: (MonadSTM m, Typeable a) => StrictTVar m a -> PropertyM m Bool
isInWHNF v = do
    x <- run $ readTVarIO v
    case unsafeNoThunks (OnlyCheckWhnf x) of
      Nothing    -> pure True
      Just tinfo -> monitor (counterexample $ "Not in WHNF: " ++ show tinfo)
                 >> pure False

-- | Wrapper around 'Checked.newTVar' and 'Checked.newTVarWithInvariant'.
newTVarWithInvariant :: MonadSTM m => Invariant a -> a -> STM m (StrictTVar m a)
newTVarWithInvariant = \case
    NoInvariant   -> Checked.newTVar
    Invariant inv -> Checked.newTVarWithInvariant inv

-- | Wrapper around 'Checked.newTVarIO' and 'Checked.newTVarWithInvariantIO'.
newTVarWithInvariantIO :: MonadSTM m => Invariant a -> a -> m (StrictTVar m a)
newTVarWithInvariantIO = \case
    NoInvariant   -> Checked.newTVarIO
    Invariant inv -> Checked.newTVarWithInvariantIO inv

newtype SanityCheckWhnf = SanityCheckWhnf { getSanityCheckWhnf :: Bool }
  deriving (Show, Eq)

noSanityCheckWhnf :: SanityCheckWhnf
noSanityCheckWhnf = SanityCheckWhnf False

sanityCheckWhnf :: SanityCheckWhnf
sanityCheckWhnf = SanityCheckWhnf True

withSanityCheckWhnf ::
     (MonadSTM m, Typeable a)
  => SanityCheckWhnf
  -> StrictTVar m a
  -> PropertyM m Bool
withSanityCheckWhnf check v =
    if getSanityCheckWhnf check then
      isInWHNF v
    else
      pure True

{-------------------------------------------------------------------------------
  Properties
-------------------------------------------------------------------------------}

-- | Test 'newTVarWithInvariant', not to be confused with
-- 'Checked.newTVarWithInvariant'.
prop_newTVarWithInvariant ::
     MonadSTM m
  => SanityCheckWhnf
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_newTVarWithInvariant check inv x f = do
    v <- run $ atomically $ newTVarWithInvariant inv (applyFun f x)
    withSanityCheckWhnf check v

-- | Test 'newTVarWithInvariantIO', not to be confused with
-- 'Checked.newTVarWithInvariantIO'.
prop_newTVarWithInvariantIO ::
     MonadSTM m
  => SanityCheckWhnf
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_newTVarWithInvariantIO check inv x f = do
    v <- run $ newTVarWithInvariantIO inv (applyFun f x)
    withSanityCheckWhnf check v

prop_writeTVar ::
     MonadSTM m
  => SanityCheckWhnf
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_writeTVar check inv x f = do
    v <- run $ newTVarWithInvariantIO inv x
    run $ atomically $ writeTVar v (applyFun f x)
    withSanityCheckWhnf check v

prop_modifyTVar ::
     MonadSTM m
  => SanityCheckWhnf
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_modifyTVar check inv x f = do
    v <- run $ newTVarWithInvariantIO inv x
    run $ atomically $ modifyTVar v (applyFun f)
    withSanityCheckWhnf check v

prop_stateTVar ::
     MonadSTM m
  => SanityCheckWhnf
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_stateTVar check inv x f = do
    v <- run $ newTVarWithInvariantIO inv x
    run $ atomically $ stateTVar v (((),) . applyFun f)
    withSanityCheckWhnf check v

prop_swapTVar ::
     MonadSTM m
  => SanityCheckWhnf
  -> Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_swapTVar check inv x f = do
    v <- run $ newTVarWithInvariantIO inv x
    void $ run $ atomically $ swapTVar v (applyFun f x)
    withSanityCheckWhnf check v
