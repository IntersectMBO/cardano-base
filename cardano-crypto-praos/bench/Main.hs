module Main (main) where

import Cardano.Crypto.Libsodium.Init
import Criterion.Main

import qualified Bench.Crypto.VRF (benchmarks)

main :: IO ()
main = do
  sodiumInit
  defaultMain benchmarks

benchmarks :: [Benchmark]
benchmarks =
  [ Bench.Crypto.VRF.benchmarks
  ]
