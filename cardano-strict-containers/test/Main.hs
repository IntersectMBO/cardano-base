module Main (main) where

import qualified Test.Data.Bitmap.Strict.NonEmpty
import Test.Hspec (describe, hspec)

main :: IO ()
main = hspec $ describe "cardano-strict-containers" Test.Data.Bitmap.Strict.NonEmpty.spec
