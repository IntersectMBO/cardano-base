module Main (main) where

import qualified Test.Cardano.Crypto.Peras
import Test.Hspec (hspec)
import Prelude

main :: IO ()
main = hspec Test.Cardano.Crypto.Peras.spec
