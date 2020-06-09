module Main (main) where

import qualified Test.Crypto.DSIGN (tests)
import qualified Test.Crypto.Hash (tests)
import qualified Test.Crypto.KES (tests)
import qualified Test.Crypto.VRF (tests)
import Test.Tasty
import Cardano.Crypto.Libsodium (sodiumInit)

main :: IO ()
main = do
    sodiumInit
    defaultMain tests

tests :: TestTree
tests =
  testGroup "ouroboros-consensus"
    [ Test.Crypto.DSIGN.tests
    , Test.Crypto.Hash.tests
    , Test.Crypto.KES.tests
    , Test.Crypto.VRF.tests
    ]
