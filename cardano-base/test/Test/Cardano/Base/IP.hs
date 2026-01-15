{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Base.IP (tests) where

import Cardano.Base.IP
import Control.Exception (evaluate)
import Data.Aeson (Result (..), fromJSON, toJSON)
import Data.Aeson.QQ (aesonQQ)
import Test.Hspec

isError :: Result a -> Bool
isError (Error _) = True
isError _ = False

tests :: Spec
tests = describe "IP" $ do
  describe "IPv4" $ do
    it "Show instance" $ do
      show (toIPv4 [192, 168, 1, 1]) `shouldBe` "\"192.168.1.1\""
      show (toIPv4 [0, 0, 0, 0]) `shouldBe` "\"0.0.0.0\""

    it "Read instance" $ do
      (read "\"192.168.1.1\"" :: IPv4) `shouldBe` toIPv4 [192, 168, 1, 1]
      (read "\"0.0.0.0\"" :: IPv4) `shouldBe` toIPv4 [0, 0, 0, 0]

    it "Read fails on invalid input" $ do
      evaluate (read "\"invalid\"" :: IPv4) `shouldThrow` anyException
      evaluate (read "\"256.0.0.1\"" :: IPv4) `shouldThrow` anyException

    it "Show/Read roundtrip" $ do
      read (show (toIPv4 [192, 168, 1, 1])) `shouldBe` toIPv4 [192, 168, 1, 1]
      read (show (toIPv4 [0, 0, 0, 0])) `shouldBe` toIPv4 [0, 0, 0, 0]

    it "ToJSON instance" $ do
      toJSON (toIPv4 [192, 168, 1, 1]) `shouldBe` [aesonQQ| "192.168.1.1" |]
      toJSON (toIPv4 [0, 0, 0, 0]) `shouldBe` [aesonQQ| "0.0.0.0" |]

    it "FromJSON instance" $ do
      fromJSON [aesonQQ| "192.168.1.1" |] `shouldBe` pure (toIPv4 [192, 168, 1, 1])
      fromJSON [aesonQQ| "invalid" |] `shouldSatisfy` (isError @IPv4)
      fromJSON [aesonQQ| 123 |] `shouldSatisfy` (isError @IPv4)

  describe "IPv6" $ do
    it "Show instance" $ do
      show (toIPv6 [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]) `shouldBe` "\"2001:db8::1\""
      show (toIPv6 [0, 0, 0, 0, 0, 0, 0, 0]) `shouldBe` "\"::\""
      show (toIPv6 [0, 0, 0, 0, 0, 0, 0, 1]) `shouldBe` "\"::1\""

    it "Read instance" $ do
      (read "\"2001:db8::1\"" :: IPv6) `shouldBe` toIPv6 [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]
      (read "\"::\"" :: IPv6) `shouldBe` toIPv6 [0, 0, 0, 0, 0, 0, 0, 0]
      (read "\"::1\"" :: IPv6) `shouldBe` toIPv6 [0, 0, 0, 0, 0, 0, 0, 1]

    it "Read fails on invalid input" $ do
      evaluate (read "\"invalid\"" :: IPv6) `shouldThrow` anyException
      evaluate (read "\"gggg::1\"" :: IPv6) `shouldThrow` anyException

    it "Show/Read roundtrip" $ do
      read (show (toIPv6 [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]))
        `shouldBe` toIPv6 [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]
      read (show (toIPv6 [0, 0, 0, 0, 0, 0, 0, 0])) `shouldBe` toIPv6 [0, 0, 0, 0, 0, 0, 0, 0]
      read (show (toIPv6 [0, 0, 0, 0, 0, 0, 0, 1])) `shouldBe` toIPv6 [0, 0, 0, 0, 0, 0, 0, 1]

    it "ToJSON instance" $ do
      toJSON (toIPv6 [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]) `shouldBe` [aesonQQ| "2001:db8::1" |]
      toJSON (toIPv6 [0, 0, 0, 0, 0, 0, 0, 0]) `shouldBe` [aesonQQ| "::" |]

    it "FromJSON instance" $ do
      fromJSON [aesonQQ| "2001:db8::1" |] `shouldBe` pure (toIPv6 [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])
      fromJSON [aesonQQ| "invalid" |] `shouldSatisfy` (isError @IPv6)
      fromJSON [aesonQQ| 123 |] `shouldSatisfy` (isError @IPv6)
