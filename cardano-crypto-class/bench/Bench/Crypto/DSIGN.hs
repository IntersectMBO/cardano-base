{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

{- FOURMOLU_DISABLE -}

module Bench.Crypto.DSIGN
  ( benchmarks
  ) where

import Data.Proxy
import Data.ByteString (ByteString)
import qualified Data.Foldable as F

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DSIGN.Ed25519
#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN.EcdsaSecp256k1
import Cardano.Crypto.DSIGN.SchnorrSecp256k1
import Cardano.Crypto.Hash.Blake2b
#endif

import Criterion

import Bench.Crypto.BenchData
import Cardano.Crypto.DSIGN.BLS12381 (BLS12381MinSigDSIGN, BLS12381MinVerKeyDSIGN, BLS12381DSIGN)

benchmarks :: Benchmark
benchmarks = bgroup "DSIGN"
  [ benchDSIGN (Proxy :: Proxy Ed25519DSIGN) "Ed25519"
  , benchDSIGN (Proxy :: Proxy BLS12381MinVerKeyDSIGN) "BLS12381MinVerKey"
  , benchDSIGN (Proxy :: Proxy BLS12381MinSigDSIGN) "BLS12381MinSig"
  , benchAggDSIGN (Proxy :: Proxy BLS12381MinVerKeyDSIGN) "BLS12381MinVerKey"
  , benchAggDSIGN (Proxy :: Proxy BLS12381MinSigDSIGN) "BLS12381MinSig"
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
  let msg = exampleSignable (Proxy @v)
      ctx = exampleContext (Proxy @v)
  in
  bgroup lbl
    [ bench "genKeyDSIGN" $
        nf (genKeyDSIGN @v) testSeed

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

-- | A helper class to gloss over the differences in the 'Signable' constraint
-- for different 'DSIGNAlgorithm' instances. Some use 'ByteString', some use
-- 'MessageHash'.
class ExampleSignable v a | v -> a where
  exampleSignable :: Signable v a => Proxy v -> a

instance ExampleSignable Ed25519DSIGN ByteString where
  exampleSignable _ = typicalMsg

instance ExampleSignable (BLS12381DSIGN curve) ByteString where
  exampleSignable _ = typicalMsg

#ifdef SECP256K1_ENABLED
instance ExampleSignable EcdsaSecp256k1DSIGN MessageHash where
  exampleSignable _ = hashAndPack (Proxy @Blake2b_256) typicalMsg

instance ExampleSignable SchnorrSecp256k1DSIGN ByteString where
  exampleSignable _ = typicalMsg
#endif

-- | Provide an example context for each DSIGN algorithm.
-- similar to 'ExampleSignable', this glosses over differences in the
-- 'ContextDSIGN' associated type.
class ExampleContext v where
  exampleContext :: Proxy v -> ContextDSIGN v

instance ExampleContext Ed25519DSIGN where
  exampleContext _ = ()

#ifdef SECP256K1_ENABLED
instance ExampleContext EcdsaSecp256k1DSIGN where
  exampleContext _ = ()

instance ExampleContext SchnorrSecp256k1DSIGN where
  exampleContext _ = ()
#endif

-- | This example context sets both the dst and augmentation to Nothing.
instance ExampleContext (BLS12381DSIGN curve) where
  exampleContext _ = (Nothing, Nothing)

benchAggDSIGN :: forall v a
  . ( DSIGNAggregatable v
    , Signable v a
    , ExampleSignable v a
    , ExampleContext v
    , NFData (SignKeyDSIGN v)
    , NFData (VerKeyDSIGN v)
    , NFData (SigDSIGN v)
    , NFData (PossessionProofDSIGN v)
    )
  => Proxy v
  -> String
  -> Benchmark
benchAggDSIGN _ lbl =
  let msg = exampleSignable (Proxy @v)
      ctx = exampleContext (Proxy @v)
      ns = 1 : [100, 200 .. 1000]
  in bgroup (lbl <> "/Aggregatable") $
      [ bgroup ("n=" <> show n)
          [ env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "provePoP (all)" $
                nf (proveAllPoPs @v ctx) (caseSKs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "verifyPoP (all)" $
                nf (verifyAllPoPs @v ctx) (caseVKPoPs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "aggregateVerKeys (with PoPs)" $
                nf (aggregateVerKeysDSIGN @v ctx) (caseVKPoPs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "aggregateVerKeys (no PoPs)" $
                nf (uncheckedAggregateVerKeysDSIGN @v) (caseVKs c)

          , env (pure (mkCase @v ctx msg n)) $ \c ->
              bench "aggregateSig" $
                nf (aggregateSigsDSIGN @v) (caseSigs c)
          ]
      | n <- ns
      ]

data AggCase v = AggCase
  { caseSKs    :: ![SignKeyDSIGN v]
  , caseVKs    :: ![VerKeyDSIGN v]
  , caseVKPoPs :: ![(VerKeyDSIGN v, PossessionProofDSIGN v)]
  , caseSigs   :: ![SigDSIGN v]
  }

instance
  ( NFData (SignKeyDSIGN v)
  , NFData (VerKeyDSIGN v)
  , NFData (PossessionProofDSIGN v)
  , NFData (SigDSIGN v)
  ) => NFData (AggCase v) where
  rnf (AggCase sks vks vkp sigs) =
    rnf sks `seq`
    rnf vks `seq`
    rnf vkp `seq`
    rnf sigs

mkCase :: forall v a. (DSIGNAggregatable v, Signable v a)
  => ContextDSIGN v -> a -> Int -> AggCase v
mkCase ctx msg n =
  let sks  = replicate n (genKeyDSIGN @v testSeed)
      vks  = map deriveVerKeyDSIGN sks
      pops = map (createPossessionProofDSIGN @v ctx) sks
      sigs = map (signDSIGN @v ctx msg) sks
      vkp  = zip vks pops
  in AggCase sks vks vkp sigs

proveAllPoPs :: forall v. DSIGNAggregatable v
  => ContextDSIGN v -> [SignKeyDSIGN v] -> [PossessionProofDSIGN v]
proveAllPoPs ctx = map (createPossessionProofDSIGN @v ctx)

verifyAllPoPs :: forall v. DSIGNAggregatable v
  => ContextDSIGN v
  -> [(VerKeyDSIGN v, PossessionProofDSIGN v)]
  -> Either String ()
verifyAllPoPs ctx = F.foldl' (\acc (vk,pop) -> acc >> verifyPossessionProofDSIGN @v ctx vk pop) (Right ())
