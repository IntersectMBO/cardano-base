module Main (main) where

import Cardano.Crypto.Libsodium (sodiumInit)
import qualified Test.Crypto.DSIGN (tests)
import qualified Test.Crypto.Hash (tests)
import qualified Test.Crypto.KES (tests)
import qualified Test.Crypto.VRF (tests)
import Test.Tasty (TestTree, adjustOption, defaultMain, testGroup)
import Test.Tasty.QuickCheck (QuickCheckTests (QuickCheckTests))

main :: IO ()
main = do
  sodiumInit
  defaultMain tests

tests :: TestTree
tests =
  -- The default QuickCheck test count is 100. This is too few to catch
  -- anything, so we set a minimum of 1000.
  adjustOption (\(QuickCheckTests i) -> QuickCheckTests $ max i 1000)
    . testGroup "cardano-crypto-class"
    $ [ Test.Crypto.DSIGN.tests,
        Test.Crypto.Hash.tests,
        Test.Crypto.KES.tests,
        Test.Crypto.VRF.tests
      ]
