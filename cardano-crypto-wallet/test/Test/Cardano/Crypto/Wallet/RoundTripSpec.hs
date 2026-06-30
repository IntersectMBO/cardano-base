{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Crypto.Wallet.RoundTripSpec (tests) where

import qualified Data.ByteString as BS
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Test.QuickCheck.Monadic (monadicIO, run)

import Cardano.Crypto.WalletHD.Encrypted
import Test.Cardano.Crypto.WalletHD.Arbitrary ()

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
  it "encryptedCreate produces EnvelopeV2 format" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> encryptedKeyFormat key `shouldBe` EnvelopeV2

  it "validateXPrvPassphrase succeeds with correct passphrase" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        r <- encryptedValidatePassphrase key testPass
        r `shouldBe` Right ()

  it "validateXPrvPassphrase fails with wrong passphrase" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        r <- encryptedValidatePassphrase key (BS.replicate 32 0x00)
        r `shouldBe` Left XPrvAuthenticationFailed

  it "encryptedChangePassphrase preserves public key" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        let newPass = BS.replicate 32 0xFF
        res' <- encryptedChangePassphrase testPass newPass key
        case res' of
          Left err -> expectationFailure $ "changePass failed: " ++ show err
          Right key' -> encryptedPublic key `shouldBe` encryptedPublic key'

  prop "encryptedChangePassphrase roundtrip preserves public key" $
    \(key :: EncryptedKey) -> monadicIO $ do
      let newPass = BS.replicate 32 0xFF
      res1 <- run $ encryptedChangePassphrase emptyPass newPass key
      case res1 of
        Left err -> pure $ counterexample ("changePass failed: " ++ show err) False
        Right key' -> do
          res2 <- run $ encryptedChangePassphrase newPass emptyPass key'
          case res2 of
            Left err -> pure $ counterexample ("change back failed: " ++ show err) False
            Right key'' -> pure (encryptedPublic key === encryptedPublic key'')

  it "encryptedDerivePrivate and encryptedDerivePublic are consistent" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        let pub = encryptedPublic key
            cc = encryptedChainCode key
            idx = 0
        res' <- encryptedDerivePrivate DerivationScheme2 key testPass idx
        case res' of
          Left err -> expectationFailure $ "derivePrivate failed: " ++ show err
          Right child ->
            let (derivedPub, _) = encryptedDerivePublic DerivationScheme2 (pub, cc) idx
             in encryptedPublic child `shouldBe` derivedPub

  it "encryptedDerivePublic is consistent for both schemes" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        let pub = encryptedPublic key
            cc = encryptedChainCode key
            (pub1, _) = encryptedDerivePublic DerivationScheme1 (pub, cc) 0
            (pub2, _) = encryptedDerivePublic DerivationScheme2 (pub, cc) 0
        pub1 `shouldNotBe` pub2

  prop "mkEncryptedKey . unEncryptedKey is identity" $
    \(key :: EncryptedKey) ->
      case mkEncryptedKey (unEncryptedKey key) of
        Left err -> counterexample ("re-parse failed: " ++ show err) False
        Right key' -> unEncryptedKey key === unEncryptedKey key'

  it "encryptedCreate with seed too short fails" $ do
    res <- encryptedCreate (BS.replicate 16 0x01) testPass testCC
    res `shouldBe` Left XPrvInvalidSecretKey

  it "encryptedCreate with chain code wrong size fails" $ do
    res <- encryptedCreate testSeed testPass (BS.replicate 16 0xAB)
    res `shouldBe` Left XPrvInvalidChainCode
