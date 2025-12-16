{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Bench.Crypto.VRF (
  benchmarks,
) where

import Data.ByteString (ByteString)
import Data.Proxy

import Control.DeepSeq

import Cardano.Crypto.VRF.Class
import Cardano.Crypto.VRF.Praos hiding (Seed)
import Cardano.Crypto.VRF.Simple

import Criterion

import Bench.Crypto.BenchData

benchmarks :: Benchmark
benchmarks =
  bgroup
    "VRF"
    [ benchVRF (Proxy @SimpleVRF) "SimpleVRF"
    , benchVRF (Proxy @PraosVRF) "PraosVRF"
    ]

benchVRF ::
  forall proxy v.
  ( VRFAlgorithm v
  , ContextVRF v ~ ()
  , Signable v ByteString
  , NFData (CertVRF v)
  , NFData (SignKeyVRF v)
  , NFData (VerKeyVRF v)
  ) =>
  proxy v ->
  [Char] ->
  Benchmark
benchVRF _ lbl =
  bgroup
    lbl
    [ bench "genKey" $
        nf (genKeyVRF @v) testSeed
    , env (return (genKeyVRF @v testSeed)) $ \signKey ->
        bench "eval" $
          nf (evalVRF @v () typicalMsg) signKey
    , env
        ( let (sk, vk) = genKeyPairVRF @v testSeed
              (_output, cert) = evalVRF @v () typicalMsg sk
           in return (vk, cert)
        )
        $ \ ~(vk, cert) ->
          bench "verify" $
            nf (verifyVRF () vk typicalMsg) cert
    ]
