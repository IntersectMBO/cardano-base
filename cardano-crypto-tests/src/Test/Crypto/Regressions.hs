{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
#ifdef SECP256K1_ENABLED
{-# LANGUAGE TypeApplications #-}
#endif

module Test.Crypto.Regressions (
  tests
  ) where

import Test.Tasty.HUnit (testCase, assertEqual)
import Test.Tasty (TestTree, testGroup)
#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN (rawDeserialiseVerKeyDSIGN)
import Cardano.Crypto.DSIGN.SchnorrSecp256k1 (SchnorrSecp256k1DSIGN)
#endif

tests :: TestTree
tests = testGroup "Regressions" [
#ifdef SECP256K1_ENABLED
  testGroup "DSIGN" [
    testGroup "Schnorr serialization" [
        testCase "Schnorr verkey deserialization fails on \"m\" literal" $ do
          let actual = rawDeserialiseVerKeyDSIGN @SchnorrSecp256k1DSIGN "m"
          assertEqual "" Nothing actual
      ]
    ]
#endif
  ]
