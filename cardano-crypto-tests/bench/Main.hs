module Main (main) where

import Criterion.Main
import Cardano.Crypto.Libsodium.Init

import qualified Bench.Crypto.DSIGN (benchmarks)
import qualified Bench.Crypto.KES   (benchmarks)
import qualified Bench.Crypto.VRF   (benchmarks)

main :: IO ()
main = do
  sodiumInit
  defaultMain benchmarks

benchmarks :: [Benchmark]
benchmarks =
  [ Bench.Crypto.DSIGN.benchmarks
  , Bench.Crypto.KES.benchmarks
  , Bench.Crypto.VRF.benchmarks
  ]
