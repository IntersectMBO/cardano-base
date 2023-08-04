{-# LANGUAGE LambdaCase #-}

module Test.Control.Concurrent.Class.MonadMVar.Strict.Checked.WHNF where

import           Control.Concurrent.Class.MonadMVar.Strict.Checked hiding
                     (newEmptyMVar, newEmptyMVarWithInvariant, newMVar,
                     newMVarWithInvariant)
import qualified Control.Concurrent.Class.MonadMVar.Strict.Checked as Checked
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
tests = testGroup "WHNF" [
      testGroup "IO" [
          testIO    "No invariant"      noInvariant
        , testIO    "Trivial invariant" trivialInvariant
        , testIO    "WHNF invariant"    whnfInvariant
        ]
    , testGroup "IOSim" [
          testIOSim "No invariant"      noInvariant
        , testIOSim "Trivial invariant" trivialInvariant
        , testIOSim "WHNF invariant"    whnfInvariant
        ]
    ]
  where
    testIO name inv = testGroup name [
          testProperty "prop_newMVarWithInvariant" $
            monadicIO .: prop_newMVarWithInvariant inv
        , testProperty "prop_putMVar" $
            monadicIO .: prop_putMVar inv
        , testProperty "prop_swapMVar" $
            monadicIO .: prop_swapMVar inv
        , testProperty "prop_tryPutMVarJust" $
            monadicIO .: prop_tryPutMVarNothing inv
        , testProperty "prop_tryPutMVarNothing" $
            monadicIO .: prop_tryPutMVarNothing inv
        , testProperty "prop_modifyMVar_" $
            monadicIO .: prop_modifyMVar_ inv
        , testProperty "prop_modifyMVar" $
            monadicIO .: prop_modifyMVar inv
        , testProperty "prop_modifyMVarMasked_" $
            monadicIO .: prop_modifyMVarMasked_ inv
        , testProperty "prop_modifyMVarMasked" $
            monadicIO .: prop_modifyMVarMasked inv
        ]

    testIOSim name inv = testGroup name [
          testProperty "prop_newMVarWithInvariant" $ \x f ->
            monadicSim $ prop_newMVarWithInvariant inv x f
        , testProperty "prop_putMVar" $ \x f ->
            monadicSim $ prop_putMVar inv x f
        , testProperty "prop_swapMVar" $ \x f ->
            monadicSim $ prop_swapMVar inv x f
        , testProperty "prop_tryPutMVarJust" $ \x f ->
            monadicSim $ prop_tryPutMVarJust inv x f
        , testProperty "prop_tryPutMVarNothing" $ \x f ->
            monadicSim $ prop_tryPutMVarNothing inv x f
        , testProperty "prop_modifyMVar_" $ \x f ->
            monadicSim $ prop_modifyMVar_ inv x f
        , testProperty "prop_modifyMVar" $ \x f ->
            monadicSim $ prop_modifyMVar inv x f
        , testProperty "prop_modifyMVarMasked_" $ \x f ->
            monadicSim $ prop_modifyMVarMasked_ inv x f
        , testProperty "prop_modifyMVarMasked" $ \x f ->
            monadicSim $ prop_modifyMVarMasked inv x f
        ]

{-------------------------------------------------------------------------------
  Utilities
-------------------------------------------------------------------------------}

isInWHNF :: (MonadMVar m, Typeable a) => StrictMVar m a -> PropertyM m Bool
isInWHNF v = do
    x <- run $ readMVar v
    case unsafeNoThunks (OnlyCheckWhnf x) of
      Nothing    -> pure True
      Just tinfo -> monitor (counterexample $ "Not in WHNF: " ++ show tinfo)
                 >> pure False

-- | Wrapper around 'Checked.newMVar' and 'Checked.newMVarWithInvariant'.
newMVarWithInvariant :: MonadMVar m => Invariant a -> a -> m (StrictMVar m a)
newMVarWithInvariant = \case
    NoInvariant   -> Checked.newMVar
    Invariant inv -> Checked.newMVarWithInvariant inv

-- | Wrapper around 'Checked.newEmptyMVar' and
-- 'Checked.newEmptyMVarWithInvariant'.
newEmptyMVarWithInvariant :: MonadMVar m => Invariant a -> m (StrictMVar m a)
newEmptyMVarWithInvariant = \case
    NoInvariant   -> Checked.newEmptyMVar
    Invariant inv -> Checked.newEmptyMVarWithInvariant inv

{-------------------------------------------------------------------------------
  Properties
-------------------------------------------------------------------------------}

-- | Test 'newMVarWithInvariant', not to be confused with
-- 'Checked.newMVarWithInvariant'.
prop_newMVarWithInvariant ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_newMVarWithInvariant inv x f = do
    v <- run $ newMVarWithInvariant inv (applyFun f x)
    isInWHNF v

prop_putMVar ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_putMVar inv x f = do
    v <- run $ newEmptyMVarWithInvariant inv
    run $ putMVar v (applyFun f x)
    isInWHNF v

prop_swapMVar ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_swapMVar inv x f = do
    v <- run $ newMVarWithInvariant inv x
    void $ run $ swapMVar v (applyFun f x)
    isInWHNF v

prop_tryPutMVarJust ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_tryPutMVarJust inv x f = do
    v <- run $ newEmptyMVarWithInvariant inv
    b <- run $ tryPutMVar v (applyFun f x)
    b' <- isInWHNF v
    pure (b && b')

prop_tryPutMVarNothing ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_tryPutMVarNothing inv x f = do
    v <- run $ newMVarWithInvariant inv x
    b <- run $ tryPutMVar v (applyFun f x)
    b' <- isInWHNF v
    pure (not b && b')

prop_modifyMVar_ ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_modifyMVar_ inv x f = do
    v <-  run $ newMVarWithInvariant inv x
    run $ modifyMVar_ v (pure . applyFun f)
    isInWHNF v

prop_modifyMVar ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int (Int, Char)
  -> PropertyM m Bool
prop_modifyMVar inv x f =do
    v <-  run $ newMVarWithInvariant inv x
    void $ run $ modifyMVar v (pure . applyFun f)
    isInWHNF v

prop_modifyMVarMasked_ ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> PropertyM m Bool
prop_modifyMVarMasked_ inv x f =do
    v <-  run $ newMVarWithInvariant inv x
    void $ run $ modifyMVarMasked_ v (pure . applyFun f)
    isInWHNF v

prop_modifyMVarMasked ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int (Int, Char)
  -> PropertyM m Bool
prop_modifyMVarMasked inv x f =do
    v <-  run $ newMVarWithInvariant inv x
    void $ run $ modifyMVarMasked v (pure . applyFun f)
    isInWHNF v
