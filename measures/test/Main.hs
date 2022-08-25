module Main
  ( main
  , tests
  )
where

import Test.Tasty

import qualified Test.Data.Measure (tests)

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "measures package"
    [ Test.Data.Measure.tests
    ]
