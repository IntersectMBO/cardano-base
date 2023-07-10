module Main where

import qualified Test.Control.Concurrent.Class.MonadMVar.Strict.Checked as Checked
import           Test.Tasty

main :: IO ()
main = defaultMain $ testGroup "strict-checked-vars" [
      Checked.tests
    ]
