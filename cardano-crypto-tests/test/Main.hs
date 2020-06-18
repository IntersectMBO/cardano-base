module Main (main) where

import qualified Test.Crypto.DSIGN (tests)
import qualified Test.Crypto.Hash (tests)
import qualified Test.Crypto.KES (tests)
import qualified Test.Crypto.VRF (tests)
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup "ouroboros-consensus"
    [ Test.Crypto.DSIGN.tests
    , Test.Crypto.Hash.tests
    , Test.Crypto.KES.tests
    , Test.Crypto.VRF.tests
    ]
