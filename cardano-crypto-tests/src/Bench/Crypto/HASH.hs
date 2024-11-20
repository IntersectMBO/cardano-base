{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Bench.Crypto.HASH (
  benchmarks,
) where

import Cardano.Binary
import Data.Proxy

import Cardano.Crypto.Hash.Blake2b
import Cardano.Crypto.Hash.Class

import Criterion

import Bench.Crypto.BenchData

benchmarks :: Benchmark
benchmarks =
  bgroup
    "HASH"
    [ benchHASH (Proxy @Blake2b_224) "Blake2b_224"
    , benchHASH (Proxy @Blake2b_256) "Blake2b_256"
    ]

benchHASH ::
  forall proxy h.
  HashAlgorithm h =>
  proxy h ->
  [Char] ->
  Benchmark
benchHASH _ lbl =
  bgroup
    lbl
    [ bench "hashWith" $
        nf (hashWith @h id) testBytes
    , env (return (serialize' (hashWith @h id testBytes))) $
        bench "decodeHash"
          . nf (either (error . show) (id @(Hash h ByteString)) . decodeFull')
    ]
