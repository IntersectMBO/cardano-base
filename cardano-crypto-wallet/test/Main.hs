module Main (main) where

import Test.Hspec

import Cardano.Crypto.Libsodium (sodiumInit)
import Cardano.Crypto.WalletHD.Encrypted (
  withDeterministicRandomnessForTesting,
  withFastKdfForTesting,
 )
import qualified Test.Cardano.Crypto.Wallet.RoundTripSpec as RoundTrip
import qualified Test.Cardano.Crypto.Wallet.SignSpec as Sign
import qualified Test.Cardano.Crypto.Wallet.V2FormatSpec as V2Format

main :: IO ()
main = do
  sodiumInit
  withFastKdfForTesting . withDeterministicRandomnessForTesting $
    hspec $ do
      RoundTrip.tests
      V2Format.tests
      Sign.tests
