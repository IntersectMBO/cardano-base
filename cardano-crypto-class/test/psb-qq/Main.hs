{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -ddump-splices #-}

module Main (main) where

import Cardano.Crypto.PinnedSizedBytes (psbHex, psbUseAsCPtr)
import Test.Tasty (defaultMain, testGroup)
import Test.Tasty.HUnit (testCase, assertEqual, assertBool)

main :: IO ()
main = defaultMain . testGroup "PinnedSizedBytes quasiquoter" $ [
  testCase "consistent with Show" $ do
    let stringRep = "abcd1234"
    let psb = [psbHex| 0xabcd1234 |]
    assertEqual "" (show stringRep) . show $ psb,
  testCase "different addresses for same literal" $ do
    let psb = [psbHex| 0xabcd1234 |]
    let psb' = [psbHex| 0xabcd1234 |]
    psbUseAsCPtr psb $ \psp -> 
      psbUseAsCPtr psb' $ \psp' -> 
        assertBool "Matching pointers" $ psp /= psp'
  ]
