{-# LANGUAGE LambdaCase #-}

module Test.Control.Concurrent.Class.MonadMVar.Strict.Checked.WHNF where

import           Control.Concurrent.Class.MonadMVar.Strict.Checked hiding
                     (newEmptyMVar, newEmptyMVarWithInvariant, newMVar,
                     newMVarWithInvariant)
import qualified Control.Concurrent.Class.MonadMVar.Strict.Checked as Checked
import           Control.Monad (void)
import           Control.Monad.IOSim (runSimOrThrow)
import           Data.Typeable (Typeable)
import           NoThunks.Class (OnlyCheckWhnf (..), unsafeNoThunks)
import           Test.Tasty (TestTree, testGroup)
import           Test.Tasty.QuickCheck (Fun, Property, applyFun, counterexample,
                     ioProperty, property, testProperty, (.&&.))
import           Test.Utils (Invariant (..), noInvariant, trivialInvariant,
                     whnfInvariant, (..:))

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
          testProperty "prop_IO_newMVarWithInvariant" $
            prop_IO_newMVarWithInvariant inv
        , testProperty "prop_IO_putMVar" $
            prop_IO_putMVar inv
        , testProperty "prop_IO_swapMVar" $
            prop_IO_swapMVar inv
        , testProperty "prop_IO_tryPutMVarJust" $
            prop_IO_tryPutMVarJust inv
        , testProperty "prop_IO_tryPutMVarNothing" $
            prop_IO_tryPutMVarNothing inv
        , testProperty "prop_IO_modifyMVar_" $
            prop_IO_modifyMVar_ inv
        , testProperty "prop_IO_modifyMVar" $
            prop_IO_modifyMVar inv
        , testProperty "prop_IO_modifyMVarMasked_" $
            prop_IO_modifyMVarMasked_ inv
        , testProperty "prop_IO_modifyMVarMasked" $
            prop_IO_modifyMVarMasked inv
        ]

    testIOSim name inv = testGroup name [
          testProperty "prop_IOSim_newMVarWithInvariant" $
            prop_IOSim_newMVarWithInvariant inv
        , testProperty "prop_IOSim_putMVar" $
            prop_IOSim_putMVar inv
        , testProperty "prop_IOSim_swapMVar" $
            prop_IOSim_swapMVar inv
        , testProperty "prop_IOSim_tryPutMVarJust" $
            prop_IOSim_tryPutMVarJust inv
        , testProperty "prop_IOSim_tryPutMVarNothing" $
            prop_IOSim_tryPutMVarNothing inv
        , testProperty "prop_IOSim_modifyMVar_" $
            prop_IOSim_modifyMVar_ inv
        , testProperty "prop_IOSim_modifyMVar" $
            prop_IOSim_modifyMVar inv
        , testProperty "prop_IOSim_modifyMVarMasked_" $
            prop_IOSim_modifyMVarMasked_ inv
        , testProperty "prop_IOSim_modifyMVarMasked" $
            prop_IOSim_modifyMVarMasked inv
        ]

{-------------------------------------------------------------------------------
  Utilities
-------------------------------------------------------------------------------}

isInWHNF :: (MonadMVar m, Typeable a) => StrictMVar m a -> m Property
isInWHNF v = do
    x <- readMVar v
    pure $ case unsafeNoThunks (OnlyCheckWhnf x) of
      Nothing    -> property True
      Just tinfo -> counterexample ("Not in WHNF: " ++ show tinfo)
                  $ property False

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

--
-- newMVarWithInvariant
--

-- | Test 'newMVarWithInvariant', not to be confused with
-- 'Checked.newMVarWithInvariant'.
prop_M_newMVarWithInvariant ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_newMVarWithInvariant inv x f = do
    v <- newMVarWithInvariant inv (applyFun f x)
    isInWHNF v

prop_IO_newMVarWithInvariant :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_newMVarWithInvariant = ioProperty ..:
    prop_M_newMVarWithInvariant

prop_IOSim_newMVarWithInvariant :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IOSim_newMVarWithInvariant inv x f = runSimOrThrow $
    prop_M_newMVarWithInvariant inv x f

--
-- putMVar
--

prop_M_putMVar ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_putMVar inv x f = do
    v <- newEmptyMVarWithInvariant inv
    putMVar v (applyFun f x)
    isInWHNF v

prop_IO_putMVar :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_putMVar = ioProperty ..:
    prop_M_putMVar

prop_IOSim_putMVar :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IOSim_putMVar inv x f = runSimOrThrow $
    prop_M_putMVar inv x f


--
-- swapMVar
--

prop_M_swapMVar ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_swapMVar inv x f = do
    v <- newMVarWithInvariant inv x
    void $ swapMVar v (applyFun f x)
    isInWHNF v

prop_IO_swapMVar :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_swapMVar = ioProperty ..:
    prop_M_swapMVar

prop_IOSim_swapMVar :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IOSim_swapMVar inv x f = runSimOrThrow $
    prop_M_swapMVar inv x f
--
-- tryPutMVar
--

prop_M_tryPutMVarJust ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_tryPutMVarJust inv x f = do
    v <- newEmptyMVarWithInvariant inv
    b <- tryPutMVar v (applyFun f x)
    b' <- isInWHNF v
    pure (property b .&&. b')

prop_IO_tryPutMVarJust :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_tryPutMVarJust = ioProperty ..:
    prop_M_tryPutMVarJust

prop_IOSim_tryPutMVarJust :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IOSim_tryPutMVarJust inv x f = runSimOrThrow $
    prop_M_tryPutMVarJust inv x f

prop_M_tryPutMVarNothing ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_tryPutMVarNothing inv x f = do
    v <- newMVarWithInvariant inv x
    b <- tryPutMVar v (applyFun f x)
    b' <- isInWHNF v
    pure (property (not b) .&&. b')

prop_IO_tryPutMVarNothing :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_tryPutMVarNothing = ioProperty ..:
    prop_M_tryPutMVarNothing
prop_IOSim_tryPutMVarNothing :: Invariant Int -> Int -> Fun Int Int -> Property

prop_IOSim_tryPutMVarNothing inv x f = runSimOrThrow $
    prop_M_tryPutMVarNothing inv x f

--
-- modifyMVar_
--

prop_M_modifyMVar_ ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_modifyMVar_ inv x f = do
    v <-  newMVarWithInvariant inv x
    modifyMVar_ v (pure . applyFun f)
    isInWHNF v

prop_IO_modifyMVar_ :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_modifyMVar_ = ioProperty ..:
    prop_M_modifyMVar_

prop_IOSim_modifyMVar_ :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IOSim_modifyMVar_ inv x f = runSimOrThrow $
    prop_M_modifyMVar_ inv x f

--
-- modifyMVar_
--

prop_M_modifyMVar ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int (Int, Char)
  -> m Property
prop_M_modifyMVar inv x f =do
    v <-  newMVarWithInvariant inv x
    void $ modifyMVar v (pure . applyFun f)
    isInWHNF v

prop_IO_modifyMVar :: Invariant Int -> Int -> Fun Int (Int, Char) -> Property
prop_IO_modifyMVar = ioProperty ..:
    prop_M_modifyMVar

prop_IOSim_modifyMVar :: Invariant Int -> Int -> Fun Int (Int, Char) -> Property
prop_IOSim_modifyMVar inv x f = runSimOrThrow $
    prop_M_modifyMVar inv x f

--
-- modifyMVarMasked_
--

prop_M_modifyMVarMasked_ ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int Int
  -> m Property
prop_M_modifyMVarMasked_ inv x f =do
    v <- newMVarWithInvariant inv x
    void $  modifyMVarMasked_ v (pure . applyFun f)
    isInWHNF v

prop_IO_modifyMVarMasked_ :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IO_modifyMVarMasked_ = ioProperty ..:
    prop_M_modifyMVarMasked_

prop_IOSim_modifyMVarMasked_ :: Invariant Int -> Int -> Fun Int Int -> Property
prop_IOSim_modifyMVarMasked_ inv x f = runSimOrThrow $
    prop_M_modifyMVarMasked_ inv x f

--
-- modifyMVarMasked
--

prop_M_modifyMVarMasked ::
     MonadMVar m
  => Invariant Int
  -> Int
  -> Fun Int (Int, Char)
  -> m Property
prop_M_modifyMVarMasked inv x f = do
    v <-newMVarWithInvariant inv x
    void $ modifyMVarMasked v (pure . applyFun f)
    isInWHNF v

prop_IO_modifyMVarMasked :: Invariant Int -> Int -> Fun Int (Int, Char) -> Property
prop_IO_modifyMVarMasked = ioProperty ..:
    prop_M_modifyMVarMasked

prop_IOSim_modifyMVarMasked :: Invariant Int -> Int -> Fun Int (Int, Char) -> Property
prop_IOSim_modifyMVarMasked inv x f = runSimOrThrow $
    prop_M_modifyMVarMasked inv x f
