module Main (main) where

import Test.Cardano.Base.IP (tests)
import Test.Hspec (describe, hspec)

main :: IO ()
main = hspec $ describe "cardano-base" tests
