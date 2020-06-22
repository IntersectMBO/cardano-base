module Main (main) where

import qualified Bench.Crypto.VRF (tests)
import Criterion.Main

main :: IO ()
main = defaultMain tests

tests :: [Benchmark] 
tests =
  [ Bench.Crypto.VRF.tests
  ]
