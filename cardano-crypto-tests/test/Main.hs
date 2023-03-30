module Main (main) where

import qualified Test.Crypto.DSIGN
import qualified Test.Crypto.Hash
import qualified Test.Crypto.KES
import qualified Test.Crypto.VRF
import qualified Test.Crypto.Regressions
import qualified Test.Crypto.Vector.Secp256k1DSIGN
import qualified Test.Crypto.EllipticCurve
import Test.Tasty (TestTree, adjustOption, testGroup, defaultMain)
import Test.Tasty.QuickCheck (QuickCheckTests (QuickCheckTests))
import Cardano.Crypto.Libsodium (sodiumInit)

main :: IO ()
main = do
    sodiumInit
    defaultMain tests

tests :: TestTree
tests =
  -- The default QuickCheck test count is 100. This is too few to catch
  -- anything, so we set a minimum of 1000.
  adjustOption (\(QuickCheckTests i) -> QuickCheckTests $ max i 1000) .
    testGroup "cardano-crypto-class" $
      [ Test.Crypto.DSIGN.tests
      , Test.Crypto.Hash.tests
      , Test.Crypto.KES.tests
      , Test.Crypto.VRF.tests
      , Test.Crypto.Regressions.tests
      , Test.Crypto.Vector.Secp256k1DSIGN.tests
      , Test.Crypto.EllipticCurve.tests
      ]
