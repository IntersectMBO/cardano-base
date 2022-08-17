{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}

module Main (main) where

import Cardano.Crypto.PinnedSizedBytes.TH (psbHex)
import Test.Tasty (defaultMain, testGroup)
import Test.Tasty.HUnit (testCase, assertEqual)

main :: IO ()
main = defaultMain . testGroup "PinnedSizedBytes quasiquoter" $ [
  testCase "consistent with Show" $ do
    let stringRep = "abcd1234"
    let psb = [psbHex| 0xabcd1234 |]
    assertEqual "" (show stringRep) . show $ psb,
  testCase "empty PSB parse" $ do
    let emptyPSB = [psbHex| 0x |]
    assertEqual "" "\"\"" . show $ emptyPSB,
  testCase "letter case does not matter" $ do
    let psb = [psbHex| 0xAbCd1234 |]
    let psb' = [psbHex| 0xabcd1234 |]
    assertEqual "" psb psb',
  testCase "0x is optional" $ do
    let psb = [psbHex| 0xabcd1234 |]
    let psb' = [psbHex| abcd1234 |]
    assertEqual "" psb psb',
  testCase "Leading whitespace does not matter" $ do
    let psb = [psbHex| 0xabcd1234 |]
    let psb' = [psbHex|           0xabcd1234 |]
    assertEqual "" psb psb',
  testCase "Trailing whitespace does not matter" $ do
    let psb = [psbHex| 0xabcd1234 |]
    let psb' = [psbHex| 0xabcd1234           |]
    assertEqual "" psb psb'
  ]
