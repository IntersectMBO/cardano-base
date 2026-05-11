{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Crypto.Wallet.RoundTripSpec (tests) where

import qualified Data.ByteString as BS
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Cardano.Crypto.WalletHD.Encrypted
import Test.Cardano.Crypto.WalletHD.Instances ()

-- | Empty passphrase — matches what 'Arbitrary EncryptedKey' uses.
emptyPass :: BS.ByteString
emptyPass = BS.empty

testPass :: BS.ByteString
testPass = BS.replicate 32 0x42

testSeed :: BS.ByteString
testSeed = BS.replicate 32 0x02

testCC :: BS.ByteString
testCC = BS.replicate 32 0xAB

tests :: Spec
tests = describe "RoundTrip" $ do
  it "encryptedCreate produces EnvelopeV2 format" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> encryptedKeyFormat key `shouldBe` EnvelopeV2

  it "validateXPrvPassphrase succeeds with correct passphrase" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> encryptedValidatePassphrase key testPass `shouldBe` Right ()

  it "validateXPrvPassphrase fails with wrong passphrase" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        encryptedValidatePassphrase key (BS.replicate 32 0x00)
          `shouldBe` Left XPrvAuthenticationFailed

  it "encryptedChangePass preserves public key" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        let newPass = BS.replicate 32 0xFF
         in case encryptedChangePass testPass newPass key of
              Left err -> expectationFailure $ "changePass failed: " ++ show err
              Right key' -> encryptedPublic key `shouldBe` encryptedPublic key'

  prop "encryptedChangePass roundtrip preserves public key" $
    \(key :: EncryptedKey) ->
      let newPass = BS.replicate 32 0xFF
       in case encryptedChangePass emptyPass newPass key of
            Left err -> counterexample ("changePass failed: " ++ show err) False
            Right key' ->
              case encryptedChangePass newPass emptyPass key' of
                Left err -> counterexample ("change back failed: " ++ show err) False
                Right key'' -> encryptedPublic key === encryptedPublic key''

  it "encryptedDerivePrivate and encryptedDerivePublic are consistent" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        let pub = encryptedPublic key
            cc = encryptedChainCode key
            idx = 0
         in case encryptedDerivePrivate DerivationScheme2 key testPass idx of
              Left err -> expectationFailure $ "derivePrivate failed: " ++ show err
              Right child ->
                let (derivedPub, _) = encryptedDerivePublic DerivationScheme2 (pub, cc) idx
                 in encryptedPublic child `shouldBe` derivedPub

  it "encryptedDerivePublic is consistent for both schemes" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        let pub = encryptedPublic key
            cc = encryptedChainCode key
            (pub1, _) = encryptedDerivePublic DerivationScheme1 (pub, cc) 0
            (pub2, _) = encryptedDerivePublic DerivationScheme2 (pub, cc) 0
         in -- v1 and v2 derivation produce different child keys
            pub1 `shouldNotBe` pub2

  prop "encryptedKey . unEncryptedKey is identity" $
    \(key :: EncryptedKey) ->
      case encryptedKey (unEncryptedKey key) of
        Left err -> counterexample ("re-parse failed: " ++ show err) False
        Right key' -> unEncryptedKey key === unEncryptedKey key'

  it "encryptedCreate with seed too short fails" $
    encryptedCreate (BS.replicate 16 0x01) testPass testCC
      `shouldBe` Left XPrvInvalidSecretKey

  it "encryptedCreate with chain code wrong size fails" $
    encryptedCreate testSeed testPass (BS.replicate 16 0xAB)
      `shouldBe` Left XPrvInvalidChainCode
