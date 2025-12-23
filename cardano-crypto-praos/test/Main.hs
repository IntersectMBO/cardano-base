{-# LANGUAGE CPP #-}

{- FOURMOLU_DISABLE -}
module Main (main) where

import qualified Test.Crypto.VRF
import Test.Hspec (Spec, describe, hspec)
import Test.Hspec.QuickCheck (modifyMaxSuccess)
import Cardano.Crypto.Libsodium (sodiumInit)

main :: IO ()
main = do
  sodiumInit
  hspec tests

tests :: Spec
tests =
  -- The default QuickCheck test count is 100. This is too few to catch
  -- anything, so we set a minimum of 1000.
  modifyMaxSuccess (max 1000) .
    describe "cardano-crypto-praos" $ do
      Test.Crypto.VRF.tests
