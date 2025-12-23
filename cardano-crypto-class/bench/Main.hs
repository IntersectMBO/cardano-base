module Main (main) where

import Cardano.Crypto.Libsodium.Init
import Criterion.Main

import qualified Bench.Crypto.DSIGN (benchmarks)
import qualified Bench.Crypto.HASH (benchmarks)
import qualified Bench.Crypto.KES (benchmarks)

main :: IO ()
main = do
  sodiumInit
  defaultMain benchmarks

benchmarks :: [Benchmark]
benchmarks =
  [ Bench.Crypto.DSIGN.benchmarks
  , Bench.Crypto.HASH.benchmarks
  , Bench.Crypto.KES.benchmarks
  ]
