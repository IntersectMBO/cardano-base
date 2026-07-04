module Test.Cardano.Crypto.Wallet.V2FormatSpec (tests) where

import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Read as CBOR
import Control.Monad.Trans.Fail.String (errorFail)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Test.HUnit.Base (assertFailure)
import Test.Hspec

import Cardano.Crypto.WalletHD.Encrypted

testSeed :: BS.ByteString
testSeed = BS.replicate 32 0x02

testCC :: BS.ByteString
testCC = BS.replicate 32 0xAB

testPass :: BS.ByteString
testPass = BS.replicate 32 0x42

wrongPass :: BS.ByteString
wrongPass = BS.replicate 32 0x00

-- ---------------------------------------------------------------------------
-- Public-key golden vector
--
-- This is the ed25519 public key derived from testSeed via cardano_crypto_ed25519_extend
-- + cardano_crypto_ed25519_publickey.  It is fully deterministic (no randomness).
-- If this changes, the key derivation C code has silently changed.
-- ---------------------------------------------------------------------------

expectedPublicKey :: PublicKey
expectedPublicKey =
  errorFail $
    mkPublicKey $
      BS.pack
        [ 129
        , 57
        , 119
        , 14
        , 168
        , 125
        , 23
        , 95
        , 86
        , 163
        , 84
        , 102
        , 195
        , 76
        , 126
        , 204
        , 203
        , 141
        , 138
        , 145
        , 180
        , 238
        , 55
        , 162
        , 93
        , 246
        , 15
        , 91
        , 143
        , 201
        , 179
        , 148
        ]

tests :: Spec
tests = describe "V2Format" $ do
  let
    createTestKey :: HasCallStack => IO EncryptedKey
    createTestKey = do
      res <- encryptedCreate testSeed testPass testCC
      case res of
        Left err -> assertFailure $ "encryptedCreate failed: " ++ show err
        Right key -> pure key

  it "encryptedCreate produces EnvelopeV2 format" $ do
    key <- createTestKey
    encryptedKeyFormat key `shouldBe` EnvelopeV2

  it "v2 key validates with correct passphrase" $ do
    key <- createTestKey
    encryptedValidatePassphrase key testPass `shouldReturn` Right ()

  it "v2 key rejects wrong passphrase with XPrvAuthenticationFailed" $ do
    key <- createTestKey
    encryptedValidatePassphrase key wrongPass `shouldReturn` Left XPrvAuthenticationFailed

  it "v2 envelope is a CBOR 9-element array" $ do
    bs <- unEncryptedKey <$> createTestKey
    case CBOR.deserialiseFromBytes CBOR.decodeListLen (BL.fromStrict bs) of
      Left e -> expectationFailure $ "CBOR decode failed: " ++ show e
      Right (_, 9) -> pure ()
      Right (_, n) ->
        expectationFailure $
          "Expected 9-element CBOR array, got: " ++ show n

  it "public key and chain code in envelope match accessors" $ do
    key <- createTestKey
    let pub = encryptedPublic key
        cc = encryptedChainCode key
    case mkEncryptedKey (unEncryptedKey key) of
      Left err -> expectationFailure $ "re-parse failed: " ++ show err
      Right key' -> do
        encryptedPublic key' `shouldBe` pub
        encryptedChainCode key' `shouldBe` cc

  it "presenting a v1 raw blob returns Left XPrvDecodeError" $ do
    let v1blob = BS.replicate 128 0x00
    case mkEncryptedKey v1blob of
      Left err -> expectationFailure $ "mkEncryptedKey rejected v1 blob: " ++ show err
      Right key -> do
        r <- encryptedValidatePassphrase key testPass
        r `shouldBe` Left XPrvDecodeError

  it "truncated CBOR bytes return Left XPrvDecodeError" $ do
    key <- createTestKey
    mkEncryptedKey (BS.take 10 (unEncryptedKey key))
      `shouldBe` Left XPrvDecodeError

  it "encryptedChangePassphrase re-randomizes envelope (different bytes, same public key)" $ do
    key <- createTestKey
    res <- encryptedChangePassphrase testPass testPass key
    case res of
      Left err -> expectationFailure $ "changePass failed: " ++ show err
      Right key' -> do
        encryptedPublic key `shouldBe` encryptedPublic key'
        unEncryptedKey key `shouldNotBe` unEncryptedKey key'

  it "golden: public key matches deterministic ed25519 derivation from testSeed" $ do
    key <- createTestKey
    encryptedPublic key `shouldBe` expectedPublicKey
