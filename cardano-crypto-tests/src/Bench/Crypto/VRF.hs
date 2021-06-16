{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE TypeFamilies #-}
{-#LANGUAGE FlexibleContexts #-}
module Bench.Crypto.VRF
  ( benchmarks
  ) where

import Data.Proxy
import Data.ByteString (ByteString)

import Control.DeepSeq

import Cardano.Crypto.VRF.Class
import Cardano.Crypto.VRF.Simple
import Cardano.Crypto.VRF.Praos hiding (Seed)

import Criterion

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}


benchmarks :: Benchmark
benchmarks =
  bgroup "VRF"
    [ bench_vrf (Proxy @SimpleVRF) "SimpleVRF"
    , bench_vrf (Proxy @PraosVRF) "PraosVRF"
    ]

bench_vrf :: forall proxy v
           . ( VRFAlgorithm v
             , ContextVRF v ~ ()
             , Signable v ByteString
             , NFData (CertVRF v)
             , NFData (SignKeyVRF v)
             , NFData (VerKeyVRF v)
             )
          => proxy v
          -> [Char]
          -> Benchmark
bench_vrf _ lbl =
  bgroup lbl
    [ bench "genKey" $
        nf (genKeyVRF @v) testSeed

    , env (return (genKeyVRF @v testSeed)) $ \signKey ->
      bench "eval" $
        nf (evalVRF @v () typicalMsg) signKey

    , env (let (sk, vk) = genKeyPairVRF @v testSeed
               (output, cert) = evalVRF @v () typicalMsg sk
            in return (vk, output, cert)
          ) $ \ ~(vk, output, cert) ->
      bench "verify" $
        nf (verifyVRF () vk typicalMsg) (output, cert)
    ]
