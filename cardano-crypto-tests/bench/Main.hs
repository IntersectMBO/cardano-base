module Main (main) where

import qualified Bench.Crypto.KES (benchmarks)
import qualified Bench.Crypto.VRF (benchmarks)
import Cardano.Crypto.Libsodium.Init
import Criterion.Main

main :: IO ()
main = do
  sodiumInit
  defaultMain benchmarks

benchmarks :: [Benchmark]
benchmarks =
  [ Bench.Crypto.VRF.benchmarks,
    Bench.Crypto.KES.benchmarks
  ]
