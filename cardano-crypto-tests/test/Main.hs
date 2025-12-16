{-# LANGUAGE CPP #-}

{- FOURMOLU_DISABLE -}
module Main (main) where

import qualified Test.Crypto.DSIGN
import qualified Test.Crypto.Hash
import qualified Test.Crypto.KES
import qualified Test.Crypto.VRF
import qualified Test.Crypto.Regressions
#ifdef SECP256K1_ENABLED
import qualified Test.Crypto.Vector.Secp256k1DSIGN
#endif
import qualified Test.Crypto.EllipticCurve
import Test.Hspec (Spec, describe, hspec)
import Test.Hspec.QuickCheck (modifyMaxSuccess)
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

  hspec (tests mlockLock)

tests :: Lock -> Spec
tests mlockLock =
  -- The default QuickCheck test count is 100. This is too few to catch
  -- anything, so we set a minimum of 1000.
  modifyMaxSuccess (max 1000) .
    describe "cardano-crypto-class" $ do
      Test.Crypto.DSIGN.tests mlockLock
      Test.Crypto.Hash.tests mlockLock
      Test.Crypto.KES.tests mlockLock
      Test.Crypto.VRF.tests
      Test.Crypto.Regressions.tests
#ifdef SECP256K1_ENABLED
      Test.Crypto.Vector.Secp256k1DSIGN.tests
#endif
      Test.Crypto.EllipticCurve.tests
