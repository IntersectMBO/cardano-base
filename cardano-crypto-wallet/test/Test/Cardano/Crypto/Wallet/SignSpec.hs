{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Wallet.SignSpec (tests) where

import qualified Data.ByteString as BS
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafePerformIO)
import Test.Hspec

import Cardano.Crypto.WalletHD.Encrypted

foreign import ccall "cardano_crypto_wallet_ed25519_sign_open"
  wallet_ed25519_sign_open ::
    Ptr a ->
    CSize ->
    Ptr a ->
    Ptr a ->
    IO CInt

verifySignature :: PublicKey -> BS.ByteString -> Signature -> Bool
verifySignature publicKey msg (Signature sig) = unsafePerformIO $
  BS.useAsCStringLen msg $ \(mp, ml) ->
    BS.useAsCString (publicKeyByteString publicKey) $ \pkp ->
      BS.useAsCString sig $ \sigp ->
        (== 0)
          <$> wallet_ed25519_sign_open
            (castPtr mp)
            (fromIntegral @Int @CSize ml)
            (castPtr pkp)
            (castPtr sigp)

testSeed :: BS.ByteString
testSeed = BS.replicate 32 0x02

testCC :: BS.ByteString
testCC = BS.replicate 32 0xAB

testPass :: BS.ByteString
testPass = BS.replicate 32 0x42

testMsg :: BS.ByteString
testMsg = "cardano transaction body hash"

tests :: Spec
tests = describe "Sign" $ do
  it "encryptedSign produces a verifiable signature" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        res' <- encryptedSign key testPass testMsg
        case res' of
          Left err -> expectationFailure $ "encryptedSign failed: " ++ show err
          Right sig -> verifySignature (encryptedPublic key) testMsg sig `shouldBe` True

  it "encryptedSign fails with wrong passphrase" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        r <- encryptedSign key (BS.replicate 32 0x00) testMsg
        r `shouldBe` Left XPrvAuthenticationFailed

  it "encryptedSign produces a 64-byte signature" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        res' <- encryptedSign key testPass testMsg
        case res' of
          Left err -> expectationFailure $ "encryptedSign failed: " ++ show err
          Right (Signature s) -> BS.length s `shouldBe` 64

  it "encryptedSign after passphrase change produces a verifiable signature" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        let newPass = BS.replicate 32 0xFF
        res' <- encryptedChangePassphrase testPass newPass key
        case res' of
          Left err -> expectationFailure $ "encryptedChangePassphrase failed: " ++ show err
          Right key' -> do
            res'' <- encryptedSign key' newPass testMsg
            case res'' of
              Left err -> expectationFailure $ "encryptedSign after changePass failed: " ++ show err
              Right sig -> verifySignature (encryptedPublic key') testMsg sig `shouldBe` True

  it "signature from original key verifies against public key preserved by passphrase change" $ do
    res <- encryptedCreate testSeed testPass testCC
    case res of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key -> do
        res' <- encryptedSign key testPass testMsg
        case res' of
          Left err -> expectationFailure $ "encryptedSign failed: " ++ show err
          Right sig -> do
            let newPass = BS.replicate 32 0xFF
            res'' <- encryptedChangePassphrase testPass newPass key
            case res'' of
              Left err -> expectationFailure $ "encryptedChangePassphrase failed: " ++ show err
              Right key' ->
                verifySignature (encryptedPublic key') testMsg sig `shouldBe` True
