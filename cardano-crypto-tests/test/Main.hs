module Main (main) where

import qualified Test.Crypto.DSIGN (tests)
import qualified Test.Crypto.Hash (tests)
import qualified Test.Crypto.KES (tests)
import qualified Test.Crypto.VRF (tests)
import Test.Tasty (TestTree, adjustOption, testGroup, defaultMain)
import Test.Tasty.QuickCheck (QuickCheckTests (QuickCheckTests))
import Cardano.Crypto.Libsodium (sodiumInit)

main :: IO ()
main = do
    sodiumInit
    defaultMain tests

tests :: TestTree
tests =
  adjustOption (\(QuickCheckTests i) -> QuickCheckTests $ max i 1000) . 
    testGroup "ouroboros-consensus" $
      [ Test.Crypto.DSIGN.tests
      , Test.Crypto.Hash.tests
      , Test.Crypto.KES.tests
      , Test.Crypto.VRF.tests
      ]
