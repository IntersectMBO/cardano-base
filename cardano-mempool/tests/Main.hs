module Main where

import System.IO (BufferMode (LineBuffering), hSetBuffering, hSetEncoding, stdout, utf8)
import Test.Cardano.Memory.PoolTests (poolTests)
import Test.Tasty

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  hSetEncoding stdout utf8
  defaultMain poolTests
