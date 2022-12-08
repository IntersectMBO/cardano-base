module Main (main) where

import Criterion.Main
import Cardano.Crypto.Libsodium.Init

import qualified Bench.Crypto.DSIGN (benchmarks)
import qualified Bench.Crypto.KES   (benchmarks)
import qualified Bench.Crypto.VRF   (benchmarks)

import Control.Concurrent.MVar

main :: IO ()
main = do
  sodiumInit
  kesLock <- newMVar ()
  defaultMain (benchmarks kesLock)

benchmarks :: MVar () -> [Benchmark]
benchmarks kesLock =
  [ Bench.Crypto.DSIGN.benchmarks
  , Bench.Crypto.KES.benchmarks kesLock
  , Bench.Crypto.VRF.benchmarks
  ]
