{-# LANGUAGE CPP        #-}
{-# LANGUAGE RankNTypes #-}

module Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked where

import           Control.Concurrent.Class.MonadSTM (MonadSTM, atomically)
import           Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Utils

tests :: TestTree
tests = testGroup "Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked" [
      testGroup "Checked" [
          testGroup "IO" [
              testProperty "prop_invariantShouldFail" $
                once $ cppToggle $ monadicIO prop_invariantShouldFail
            , testProperty "prop_invariantShouldNotFail" $
                once             $ monadicIO prop_invariantShouldNotFail
            ]
        , testGroup "IOSim" [
              testProperty "prop_invariantShouldFail" $
                once $ cppToggle $ monadicSim prop_invariantShouldFail
            , testProperty "prop_invariantShouldNotFail" $
                once             $ monadicSim prop_invariantShouldNotFail
            ]
        ]
    ]

-- | Invariant that checks whether an @Int@ is positive.
invPositiveInt :: Int -> Maybe String
invPositiveInt x
  | x >= 0    = Nothing
  | otherwise = Just $ "x<0 for x=" <> show x

prop_invariantShouldNotFail :: MonadSTM m => PropertyM m ()
prop_invariantShouldNotFail = run $ atomically $ do
    v <- newTVarWithInvariant invPositiveInt 0
    modifyTVar v (+ 1)

prop_invariantShouldFail :: MonadSTM m => PropertyM m ()
prop_invariantShouldFail = run $ atomically $ do
    v <- newTVarWithInvariant invPositiveInt 0
    modifyTVar v (subtract 1)

cppToggle :: Property -> Property
#if CHECK_TVAR_INVARIANTS
cppToggle = expectFailure
#else
cppToggle = id
#endif
