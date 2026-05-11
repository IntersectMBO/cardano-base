{-# LANGUAGE OverloadedStrings #-}

module Test.Cardano.Crypto.Wallet.SignSpec (tests) where

import qualified Data.ByteString as BS
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafePerformIO)
import Test.Hspec

import Cardano.Crypto.WalletHD.Encrypted

-- Verify a Cardano ed25519 signature (chain-code-salted nonce variant).
-- Uses the matching sign_open from the vendored ed25519 C code.
foreign import ccall "cardano_crypto_ed25519_sign_open"
  c_ed25519_sign_open ::
    Ptr a -> -- message
    CSize -> -- message length
    Ptr a -> -- public key (32 bytes)
    Ptr a -> -- signature (64 bytes)
    IO CInt

verifySignature :: BS.ByteString -> BS.ByteString -> Signature -> Bool
verifySignature pub msg (Signature sig) = unsafePerformIO $
  BS.useAsCStringLen msg $ \(mp, ml) ->
    BS.useAsCString pub $ \pkp ->
      BS.useAsCString sig $ \sigp ->
        (== 0)
          <$> c_ed25519_sign_open
            (castPtr mp)
            (fromIntegral ml)
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
  it "encryptedSign produces a verifiable signature" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        case encryptedSign key testPass testMsg of
          Left err -> expectationFailure $ "encryptedSign failed: " ++ show err
          Right sig -> verifySignature (encryptedPublic key) testMsg sig `shouldBe` True

  it "encryptedSign fails with wrong passphrase" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        encryptedSign key (BS.replicate 32 0x00) testMsg
          `shouldBe` Left XPrvAuthenticationFailed

  it "encryptedSign produces a 64-byte signature" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        case encryptedSign key testPass testMsg of
          Left err -> expectationFailure $ "encryptedSign failed: " ++ show err
          Right (Signature s) -> BS.length s `shouldBe` 64

  it "encryptedSign after passphrase change produces a verifiable signature" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        let newPass = BS.replicate 32 0xFF
         in case encryptedChangePass testPass newPass key of
              Left err -> expectationFailure $ "encryptedChangePass failed: " ++ show err
              Right key' ->
                case encryptedSign key' newPass testMsg of
                  Left err -> expectationFailure $ "encryptedSign after changePass failed: " ++ show err
                  Right sig -> verifySignature (encryptedPublic key') testMsg sig `shouldBe` True

  it "signature from original key verifies against public key preserved by passphrase change" $
    case encryptedCreate testSeed testPass testCC of
      Left err -> expectationFailure $ "encryptedCreate failed: " ++ show err
      Right key ->
        case encryptedSign key testPass testMsg of
          Left err -> expectationFailure $ "encryptedSign failed: " ++ show err
          Right sig ->
            let newPass = BS.replicate 32 0xFF
             in case encryptedChangePass testPass newPass key of
                  Left err -> expectationFailure $ "encryptedChangePass failed: " ++ show err
                  Right key' ->
                    -- public key is preserved across passphrase change
                    verifySignature (encryptedPublic key') testMsg sig `shouldBe` True
