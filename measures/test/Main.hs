module Main
  ( main,
    tests,
  )
where

import qualified Test.Data.Measure (tests)
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "measures package"
    [ Test.Data.Measure.tests
    ]
