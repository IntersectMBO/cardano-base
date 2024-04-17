module Main where

import qualified Test.Control.Concurrent.Class.MonadMVar.Strict.Checked
import qualified Test.Control.Concurrent.Class.MonadMVar.Strict.Checked.WHNF
import qualified Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked
import qualified Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF
import           Test.Tasty (defaultMain, testGroup)

main :: IO ()
main = defaultMain $ testGroup "strict-checked-vars" [
      Test.Control.Concurrent.Class.MonadMVar.Strict.Checked.tests
    , Test.Control.Concurrent.Class.MonadMVar.Strict.Checked.WHNF.tests
    , Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.tests
    , Test.Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked.WHNF.tests
    ]
