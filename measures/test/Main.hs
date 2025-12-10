module Main (
  main,
  tests,
)
where

import Test.Hspec

import qualified Test.Data.Measure (tests)

main :: IO ()
main = hspec tests

tests :: Spec
tests =
  describe "measures package" $ do
    Test.Data.Measure.tests
