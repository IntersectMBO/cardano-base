module Main (main) where

import qualified Test.Crypto.DSIGN (tests)
import qualified Test.Crypto.Hash (tests)
import qualified Test.Crypto.KES (tests)
import qualified Test.Crypto.VRF (tests)
import Test.Tasty (TestTree, adjustOption, testGroup, defaultMain)
import Test.Tasty.QuickCheck (QuickCheckTests (QuickCheckTests))
import Cardano.Crypto.Libsodium (sodiumInit)
import Test.Crypto.Util (Lock, newLock)

main :: IO ()
main = do
    sodiumInit
    lock <- newLock
    defaultMain (tests lock)

tests :: Lock -> TestTree
tests lock =
  -- The default QuickCheck test count is 100. This is too few to catch
  -- anything, so we set a minimum of 1000.
  adjustOption (\(QuickCheckTests i) -> QuickCheckTests $ max i 1000) . 
    testGroup "cardano-crypto-class" $
      [ Test.Crypto.DSIGN.tests lock
      , Test.Crypto.Hash.tests
      , Test.Crypto.KES.tests lock
      , Test.Crypto.VRF.tests
      ]
