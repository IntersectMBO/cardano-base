{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{- FOURMOLU_DISABLE -}
module Test.Crypto.Regressions (
  tests
  ) where

import Test.Tasty.HUnit (testCase, assertEqual)
import Test.Tasty (TestTree, testGroup)
import Cardano.Crypto.DSIGN (rawDeserialiseVerKeyDSIGN)
import Cardano.Crypto.DSIGN.Ed25519 (Ed25519DSIGN)
import qualified Data.ByteString as BS
#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN.SchnorrSecp256k1 (SchnorrSecp256k1DSIGN)
#endif

tests :: TestTree
tests = testGroup "Regressions" [
  testGroup "DSIGN" [
#ifdef SECP256K1_ENABLED
    testGroup "Schnorr serialization" [
        testCase "Schnorr verkey deserialization fails on \"m\" literal" $ do
          let actual = rawDeserialiseVerKeyDSIGN @SchnorrSecp256k1DSIGN "m"
          assertEqual "" Nothing actual
      ],
#endif
    testGroup "Ed25519 serialization" [
      testCase "Ed25519 sign key deserialization fails on 33 NUL bytes" $ do
        let actual = rawDeserialiseVerKeyDSIGN @Ed25519DSIGN . BS.replicate 33 $ 0
        assertEqual "" Nothing actual
      ]
    ]
  ]
