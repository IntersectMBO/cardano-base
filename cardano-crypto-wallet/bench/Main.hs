-- | Benchmarks for v2 envelope KDF operations.
--
-- These benchmarks verify that the production Argon2id parameters
-- (memory=128 MiB, t=3, p=4) give adequate timing on the target hardware.
-- Expected ranges (modern desktop / CI server):
--
--   create-v2         : ~189 ms
--   validate-v2       : ~176 ms
--   sign-v2           : ~177 ms  (one KDF pass to decrypt, then ed25519 sign)
--   change-passphrase : ~361 ms  (two KDF passes: decrypt + re-encrypt)
--
-- If the measured values are far outside these ranges, review the KDF
-- parameters in 'Cardano.Crypto.WalletHD.Encrypted'.
module Main (main) where

import Criterion.Main
import qualified Data.ByteString as BS

import Cardano.Crypto.Libsodium (sodiumInit)
import Cardano.Crypto.WalletHD.Encrypted

testSeed :: BS.ByteString
testSeed = BS.replicate 32 0x01

testCC :: BS.ByteString
testCC = BS.replicate 32 0xAB

testPass :: BS.ByteString
testPass = BS.replicate 32 0x42

newPass :: BS.ByteString
newPass = BS.replicate 32 0xFF

testMsg :: BS.ByteString
testMsg = BS.replicate 64 0xDE

main :: IO ()
main = do
  sodiumInit
  ekey <- encryptedCreate testSeed testPass testCC
  key <- case ekey of
    Left err -> error $ "setup failed: " ++ show err
    Right k -> pure k
  defaultMain
    [ bench "create-v2 (encryptedCreate)" $
        whnfIO (encryptedCreate testSeed testPass testCC)
    , bench "validate-v2 (encryptedValidatePassphrase)" $
        whnfIO (encryptedValidatePassphrase key testPass)
    , bench "sign-v2 (encryptedSign)" $
        whnfIO (encryptedSign key testPass testMsg)
    , bench "change-passphrase (encryptedChangePass)" $
        whnfIO (encryptedChangePassphrase testPass newPass key)
    ]
