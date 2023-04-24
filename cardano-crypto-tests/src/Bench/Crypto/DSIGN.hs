{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE TypeFamilies #-}
{-#LANGUAGE FlexibleContexts #-}
{-#LANGUAGE FunctionalDependencies #-}
module Bench.Crypto.DSIGN
  ( benchmarks
  ) where

import Data.Proxy
import Data.ByteString (ByteString)

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.DSIGN.EcdsaSecp256k1
import Cardano.Crypto.DSIGN.SchnorrSecp256k1
import Cardano.Crypto.Hash.Blake2b

import Criterion

import Bench.Crypto.BenchData


benchmarks :: Benchmark
benchmarks = bgroup "DSIGN"
  [ benchDSIGN (Proxy :: Proxy Ed25519DSIGN) "Ed25519"
  , benchDSIGN (Proxy :: Proxy EcdsaSecp256k1DSIGN) "EcdsaSecp256k1"
  , benchDSIGN (Proxy :: Proxy SchnorrSecp256k1DSIGN) "SchnorrSecp256k1"
  , env (let signKey = genKeyDSIGN @Ed25519DSIGN testSeed
             verKey  = deriveVerKeyDSIGN signKey
             msg = exampleSignable (Proxy @Ed25519DSIGN)
             sig     = signDSIGN @Ed25519DSIGN () msg signKey
          in return (verKey, sig, msg)
        ) $ \ ~(verKey, sig, msg) ->
      bench "verifyDSIGN-Ed25519DSIGN" $
        whnf (either error id . verifyDSIGN @Ed25519DSIGN () verKey msg) sig
  ]

benchDSIGN :: forall v a
           . ( DSIGNAlgorithm v
             , ContextDSIGN v ~ ()
             , Signable v a
             , ExampleSignable v a
             , NFData (SignKeyDSIGN v)
             , NFData (VerKeyDSIGN v)
             , NFData (SigDSIGN v)
             )
          => Proxy v
          -> String
          -> Benchmark
benchDSIGN _ lbl =
  bgroup lbl
    [ bench "genKeyDSIGN" $
        nf (genKeyDSIGN @v) testSeed

    , env (return (genKeyDSIGN @v testSeed)) $ \signKey ->
      bench "signDSIGN" $
        nf (signDSIGN @v () (exampleSignable (Proxy @v))) signKey

    , env (let signKey = genKeyDSIGN @v testSeed
               verKey  = deriveVerKeyDSIGN signKey
               sig     = signDSIGN @v () (exampleSignable (Proxy @v)) signKey
            in return (verKey, sig)
          ) $ \ ~(verKey, sig) ->
      bench "verifyDSIGN" $
        nf (verifyDSIGN @v () verKey (exampleSignable (Proxy @v))) sig
    ]
{-# INLINEABLE benchDSIGN #-}
{-# SPECIALIZE benchDSIGN :: Proxy Ed25519DSIGN -> String -> Benchmark #-}

-- | A helper class to gloss over the differences in the 'Signable' constraint
-- for different 'DSIGNAlgorithm' instances. Some use 'ByteString', some use
-- 'MessageHash'.
class ExampleSignable v a | v -> a where
  exampleSignable :: Signable v a => Proxy v -> a

instance ExampleSignable Ed25519DSIGN ByteString where
  exampleSignable _ = typicalMsg

instance ExampleSignable EcdsaSecp256k1DSIGN MessageHash where
  exampleSignable _ = hashAndPack (Proxy @Blake2b_256) typicalMsg

instance ExampleSignable SchnorrSecp256k1DSIGN ByteString where
  exampleSignable _ = typicalMsg

