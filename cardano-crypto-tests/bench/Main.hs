module Main (main) where

import qualified Bench.Crypto.VRF (tests)
import qualified Bench.Crypto.KES (tests)
import Criterion.Main

main :: IO ()
main = defaultMain tests

tests :: [Benchmark] 
tests =
  [ Bench.Crypto.VRF.tests
  , Bench.Crypto.KES.tests
  ]
