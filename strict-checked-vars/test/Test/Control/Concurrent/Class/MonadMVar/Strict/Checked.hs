{-# LANGUAGE RankNTypes #-}

module Test.Control.Concurrent.Class.MonadMVar.Strict.Checked where

import           Control.Concurrent.Class.MonadMVar.Strict.Checked
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Utils

tests :: TestTree
tests = testGroup "Test.Control.Concurrent.Class.MonadMVar.Strict" [
      testGroup "Checked" [
          testGroup "IO" [
              testProperty "prop_invariantShouldFail" $
                once $ expectFailure $ monadicIO prop_invariantShouldFail
            , testProperty "prop_invariantShouldNotFail" $
                once                 $ monadicIO prop_invariantShouldNotFail
            ]
        , testGroup "IOSim" [
              testProperty "prop_invariantShouldFail" $
                once $ expectFailure $ monadicSim prop_invariantShouldFail
            , testProperty "prop_invariantShouldNotFail" $
                once                 $ monadicSim prop_invariantShouldNotFail
            ]
        ]
    ]

-- | Invariant that checks whether an @Int@ is positive.
invPositiveInt :: Int -> Maybe String
invPositiveInt x
  | x >= 0    = Nothing
  | otherwise = Just $ "x<0 for x=" <> show x

prop_invariantShouldNotFail :: MonadMVar m => PropertyM m ()
prop_invariantShouldNotFail = run $ do
    v <- newMVarWithInvariant invPositiveInt 0
    modifyMVar_ v (\x -> pure $ x + 1)

prop_invariantShouldFail :: MonadMVar m => PropertyM m ()
prop_invariantShouldFail = run $ do
    v <- newMVarWithInvariant invPositiveInt 0
    modifyMVar_ v (\x -> pure $ x - 1)
