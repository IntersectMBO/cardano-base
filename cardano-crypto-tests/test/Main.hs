{-# LANGUAGE CPP #-}

module Main (main) where

import qualified Test.Crypto.DSIGN
import qualified Test.Crypto.Hash
import qualified Test.Crypto.KES
import qualified Test.Crypto.VRF
import qualified Test.Crypto.Regressions
#ifdef SECP256K1_ENABLED
import qualified Test.Crypto.Vector.Secp256k1DSIGN
#endif
import Test.Tasty (TestTree, adjustOption, testGroup, defaultMain)
import Test.Tasty.QuickCheck (QuickCheckTests (QuickCheckTests))
import Cardano.Crypto.Libsodium (sodiumInit)
import Test.Crypto.Util (Lock, mkLock)

main :: IO ()
main = do
  sodiumInit

  -- This lock is used to prevent tests that use mlocking from running
  -- concurrently. Concurrent execution of these tests can cause the testsuite
  -- to exhaust mlock quota; but each individual test on its own should be
  -- fine.
  mlockLock <- mkLock

  defaultMain (tests mlockLock)

tests :: Lock -> TestTree
tests mlockLock =
  -- The default QuickCheck test count is 100. This is too few to catch
  -- anything, so we set a minimum of 1000.
  adjustOption (\(QuickCheckTests i) -> QuickCheckTests $ max i 1000) .
    testGroup "cardano-crypto-class" $
      [ Test.Crypto.DSIGN.tests mlockLock
      , Test.Crypto.Hash.tests mlockLock
      , Test.Crypto.KES.tests mlockLock
      , Test.Crypto.VRF.tests
      , Test.Crypto.Regressions.tests
#ifdef SECP256K1_ENABLED
      , Test.Crypto.Vector.Secp256k1DSIGN.tests
#endif
      ]
