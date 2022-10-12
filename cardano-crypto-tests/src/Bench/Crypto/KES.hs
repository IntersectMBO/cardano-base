{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE TypeFamilies #-}
{-#LANGUAGE FlexibleContexts #-}
module Bench.Crypto.KES
  ( benchmarks
  ) where

import Data.Proxy
import Data.Maybe (fromJust)
import Data.ByteString (ByteString)

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.Hash.Blake2b
import Cardano.Crypto.KES.Class
import Cardano.Crypto.KES.Sum
import Cardano.Crypto.KES.CompactSum

import Criterion

import Bench.Crypto.BenchData


benchmarks :: Benchmark
benchmarks = bgroup "KES"
  [ benchKES @Proxy @(Sum6KES Ed25519DSIGN Blake2b_256) Proxy "Sum6KES"
  , benchKES @Proxy @(CompactSum6KES Ed25519DSIGN Blake2b_256) Proxy "CompactSum6KES"
  ]

benchKES :: forall proxy v
          . ( KESAlgorithm v
            , ContextKES v ~ ()
            , Signable v ByteString
            , NFData (SignKeyKES v)
            , NFData (VerKeyKES v)
            , NFData (SigKES v)
            )
         => proxy v
         -> [Char]
         -> Benchmark
benchKES _ lbl =
  bgroup lbl
    [ bench "genKey" $
        nf (genKeyKES @v) testSeed

    , env (return (genKeyKES @v testSeed)) $ \signKey ->
      bench "signKES" $
        nf (signKES @v () 0 typicalMsg) signKey

    , env (let signKey = genKeyKES @v testSeed
               sig     = signKES @v () 0 typicalMsg signKey
               verKey  = deriveVerKeyKES signKey
            in return (verKey, sig)
          ) $ \ ~(verKey, sig) ->
      bench "verifyKES" $
        nf (verifyKES @v () verKey 0 typicalMsg) sig

    , env (return (genKeyKES @v testSeed)) $ \signKey ->
      bench "updateKES" $
        nf (\signKey' -> fromJust $ updateKES () signKey' 0) signKey
    ]
