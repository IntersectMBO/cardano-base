module Main (main) where

import qualified Test.Data.Bitmap
import Test.Hspec (describe, hspec)

main :: IO ()
main = hspec $ describe "cardano-strict-containers" Test.Data.Bitmap.spec
