module Main where

import qualified Test.Control.Concurrent.Class.MonadMVar.Strict.Checked as Test.StrictMVar.Checked
import qualified Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF as Test.StrictTVar.Checked
import           Test.Tasty (defaultMain, testGroup)

main :: IO ()
main = defaultMain $ testGroup "strict-checked-vars" [
      Test.StrictMVar.Checked.tests
    , Test.StrictTVar.Checked.tests
    ]
