module Main (main) where

import qualified Test.Cardano.Crypto.Leios
import Test.Hspec (hspec)
import Prelude

main :: IO ()
main = hspec Test.Cardano.Crypto.Leios.spec
