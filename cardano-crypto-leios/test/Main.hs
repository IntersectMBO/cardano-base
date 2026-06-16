module Main (main) where

import qualified Test.Cardano.Crypto.Leios
import Test.Cardano.Prelude (runTests)
import Prelude

main :: IO ()
main =
  runTests
    [ Test.Cardano.Crypto.Leios.tests
    ]
