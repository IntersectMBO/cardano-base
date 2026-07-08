{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{- FOURMOLU_DISABLE -}
module Test.Crypto.Regressions (
  tests
  ) where

import Test.Hspec (Spec, describe, it, shouldBe)
import Cardano.Crypto.DSIGN (DSIGNAlgorithm (..))
import Cardano.Crypto.DSIGN.Ed25519 (Ed25519DSIGN)
import qualified Data.ByteString as BS
#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN.SchnorrSecp256k1 (SchnorrSecp256k1DSIGN)
import Cardano.Binary.FixedSizeCodec (FixedSizeCodec(..))
#endif

tests :: Spec
tests = describe "Regressions" $ do
  describe "DSIGN" $ do
#ifdef SECP256K1_ENABLED
    describe "Schnorr serialization" $ do
        it "Schnorr verkey deserialization fails on \"m\" literal" $ do
          rawDecodeFixedSized @(VerKeyDSIGN SchnorrSecp256k1DSIGN) "m" `shouldBe` Nothing
#endif
    describe "Ed25519 serialization" $ do
      it "Ed25519 sign key deserialization fails on 33 NUL bytes" $ do
        rawDecodeFixedSized @(SignKeyDSIGN Ed25519DSIGN) (BS.replicate 33 0) `shouldBe` Nothing
