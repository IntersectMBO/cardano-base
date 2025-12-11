{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -Wno-orphans #-}

{- FOURMOLU_DISABLE -}

module Bench.Crypto.DSIGN
  ( benchmarks
  ) where

import Data.Proxy
import Data.ByteString (ByteString)

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DSIGN.BLS12381MinPk
import Cardano.Crypto.DSIGN.BLS12381MinSig
import Cardano.Crypto.DSIGN.Ed25519
#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN.EcdsaSecp256k1
import Cardano.Crypto.DSIGN.SchnorrSecp256k1
import Cardano.Crypto.Hash.Blake2b
#endif

import Criterion

import Bench.Crypto.BenchData


benchmarks :: Benchmark
benchmarks = bgroup "DSIGN"
  [ benchDSIGN (Proxy :: Proxy Ed25519DSIGN) "Ed25519"
  , benchDSIGN (Proxy :: Proxy BLS12381MinPkDSIGN) "BLS12381MinPk"
  , benchDSIGN (Proxy :: Proxy BLS12381MinSigDSIGN) "BLS12381MinSig"
#ifdef SECP256K1_ENABLED
  , benchDSIGN (Proxy :: Proxy EcdsaSecp256k1DSIGN) "EcdsaSecp256k1"
  , benchDSIGN (Proxy :: Proxy SchnorrSecp256k1DSIGN) "SchnorrSecp256k1"
#endif
  ]

benchDSIGN :: forall v a
           . ( DSIGNAlgorithm v
             , Signable v a
             , ExampleSignable v a
             , ExampleContext v
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
      bench "deriveVerKeyDSIGN" $
        nf (deriveVerKeyDSIGN @v) signKey

    , env (return (genKeyDSIGN @v testSeed)) $ \signKey ->
      bench "signDSIGN" $
        nf (signDSIGN @v ctx msg) signKey

    , env (let signKey = genKeyDSIGN @v testSeed
               verKey  = deriveVerKeyDSIGN signKey
               sig     = signDSIGN @v ctx msg signKey
            in return (verKey, sig)
          ) $ \ ~(verKey, sig) ->
      bench "verifyDSIGN" $
        nf (verifyDSIGN @v ctx verKey msg) sig
    ]
  where
    ctx = exampleContext (Proxy @v)
    msg = exampleSignable (Proxy @v)

-- | A helper class to gloss over the differences in the 'Signable' constraint
-- for different 'DSIGNAlgorithm' instances. Some use 'ByteString', some use
-- 'MessageHash'.
class ExampleSignable v a | v -> a where
  exampleSignable :: Signable v a => Proxy v -> a

instance ExampleSignable Ed25519DSIGN ByteString where
  exampleSignable _ = typicalMsg

instance ExampleSignable BLS12381MinPkDSIGN ByteString where
  exampleSignable _ = typicalMsg

instance ExampleSignable BLS12381MinSigDSIGN ByteString where
  exampleSignable _ = typicalMsg

#ifdef SECP256K1_ENABLED
instance ExampleSignable EcdsaSecp256k1DSIGN MessageHash where
  exampleSignable _ = hashAndPack (Proxy @Blake2b_256) typicalMsg

instance ExampleSignable SchnorrSecp256k1DSIGN ByteString where
  exampleSignable _ = typicalMsg
#endif

class ExampleContext v where
  exampleContext :: Proxy v -> ContextDSIGN v

instance ExampleContext Ed25519DSIGN where
  exampleContext _ = ()

-- BLS context is (Maybe dstTag, Maybe augMessage); for benchmarks we use the default case (Nothing, Nothing).
instance ExampleContext BLS12381MinPkDSIGN where
  exampleContext _ = (Nothing, Nothing)

instance ExampleContext BLS12381MinSigDSIGN where
  exampleContext _ = (Nothing, Nothing)

#ifdef SECP256K1_ENABLED
instance ExampleContext EcdsaSecp256k1DSIGN where
  exampleContext _ = ()

instance ExampleContext SchnorrSecp256k1DSIGN where
  exampleContext _ = ()
#endif

instance NFData (VerKeyDSIGN BLS12381MinPkDSIGN) where rnf x = x `seq` ()
instance NFData (SignKeyDSIGN BLS12381MinPkDSIGN) where rnf x = x `seq` ()
instance NFData (SigDSIGN BLS12381MinPkDSIGN) where rnf x = x `seq` ()

instance NFData (VerKeyDSIGN BLS12381MinSigDSIGN) where rnf x = x `seq` ()
instance NFData (SignKeyDSIGN BLS12381MinSigDSIGN) where rnf x = x `seq` ()
instance NFData (SigDSIGN BLS12381MinSigDSIGN) where rnf x = x `seq` ()
