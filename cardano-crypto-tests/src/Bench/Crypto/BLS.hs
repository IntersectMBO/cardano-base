{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- | Benchmarks for BLS12-381 in both MinPk and MinSig variants.
--   We cover POP (prove/verify), public key aggregation, and signature
--   aggregation for both same-message and distinct-message cases.
module Bench.Crypto.BLS (
  benchmarks,
) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Control.DeepSeq (NFData (..))
import Data.List (iterate')

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.DSIGN.BLS12381MinPk (BLS12381MinPkDSIGN)
import qualified Cardano.Crypto.DSIGN.BLS12381MinPk as BLSMinPk
import Cardano.Crypto.DSIGN.BLS12381MinSig (BLS12381MinSigDSIGN)
import qualified Cardano.Crypto.DSIGN.BLS12381MinSig as BLSMinSig
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Criterion

import Bench.Crypto.BenchData

benchmarks :: Benchmark
benchmarks =
  bgroup
    "BLS"
    [ benchPOPMinPk
    , benchPOPMinSig
    , benchPkAggMinPk
    , benchPkAggMinSig
    , benchSigAggSameMsgMinPk
    , benchSigAggSameMsgMinSig
    , benchSigAggDistinctMsgMinPk
    , benchSigAggDistinctMsgMinSig
    ]

benchPOPMinPk :: Benchmark
benchPOPMinPk =
  bgroup
    "BLS12381MinPk"
    [ env (return (genKeyDSIGN @BLS12381MinPkDSIGN testSeed)) $ \signKey ->
        bench "POP/prove" $
          nf (\sk -> BLSMinPk.derivePopDSIGN blsCtx sk typicalMsg) signKey
    , env
        ( let signKey = genKeyDSIGN @BLS12381MinPkDSIGN testSeed
              verKey = deriveVerKeyDSIGN @BLS12381MinPkDSIGN signKey
              pop = BLSMinPk.derivePopDSIGN blsCtx signKey typicalMsg
           in return (verKey, pop)
        )
        $ \ ~(verKey, pop) ->
          bench "POP/verify" $
            nf (\(vk, p) -> BLSMinPk.verifyPopDSIGN blsCtx vk typicalMsg p) (verKey, pop)
    ]
  where
    blsCtx = (Nothing, Nothing) :: ContextDSIGN BLS12381MinPkDSIGN

benchPOPMinSig :: Benchmark
benchPOPMinSig =
  bgroup
    "BLS12381MinSig"
    [ env (return (genKeyDSIGN @BLS12381MinSigDSIGN testSeed)) $ \signKey ->
        bench "POP/prove" $
          nf (\sk -> BLSMinSig.derivePopDSIGN blsCtx sk typicalMsg) signKey
    , env
        ( let signKey = genKeyDSIGN @BLS12381MinSigDSIGN testSeed
              verKey = deriveVerKeyDSIGN @BLS12381MinSigDSIGN signKey
              pop = BLSMinSig.derivePopDSIGN blsCtx signKey typicalMsg
           in return (verKey, pop)
        )
        $ \ ~(verKey, pop) ->
          bench "POP/verify" $
            nf (\(vk, p) -> BLSMinSig.verifyPopDSIGN blsCtx vk typicalMsg p) (verKey, pop)
    ]
  where
    blsCtx = (Nothing, Nothing) :: ContextDSIGN BLS12381MinSigDSIGN

benchPkAggMinPk :: Benchmark
benchPkAggMinPk =
  bgroup
    "BLS12381MinPk/pkAgg"
    (map mkBench ns)
  where
    mkBench n =
      env (return (deterministicVerKeys @BLS12381MinPkDSIGN n)) $ \verKeys ->
        bench ("N=" ++ show n) $
          nf (either (error . show) id . BLSMinPk.aggregateVerKeysDSIGN) verKeys
    ns = [1, 10, 100, 500, 1000]

benchPkAggMinSig :: Benchmark
benchPkAggMinSig =
  bgroup
    "BLS12381MinSig/pkAgg"
    (map mkBench ns)
  where
    mkBench n =
      env (return (deterministicVerKeys @BLS12381MinSigDSIGN n)) $ \verKeys ->
        bench ("N=" ++ show n) $
          nf (either (error . show) id . BLSMinSig.aggregateVerKeysDSIGN) verKeys
    ns = [1, 10, 100, 500, 1000]

benchSigAggSameMsgMinPk :: Benchmark
benchSigAggSameMsgMinPk =
  bgroup
    "BLS12381MinPk/sigAgg/sameMsg"
    (map mkBench ns)
  where
    mkBench n =
      env (return (sameMsgSignaturesMinPk n)) $ \sigs ->
        bench ("N=" ++ show n) $
          nf (either (error . show) id . BLSMinPk.aggregateSignaturesSameMsgDSIGN) sigs
    ns = [1, 10, 100, 500, 1000]

benchSigAggSameMsgMinSig :: Benchmark
benchSigAggSameMsgMinSig =
  bgroup
    "BLS12381MinSig/sigAgg/sameMsg"
    (map mkBench ns)
  where
    mkBench n =
      env (return (sameMsgSignaturesMinSig n)) $ \sigs ->
        bench ("N=" ++ show n) $
          nf (either (error . show) id . BLSMinSig.aggregateSignaturesSameMsgDSIGN) sigs
    ns = [1, 10, 100, 500, 1000]

benchSigAggDistinctMsgMinPk :: Benchmark
benchSigAggDistinctMsgMinPk =
  bgroup
    "BLS12381MinPk/sigAgg/distinctMsg"
    (map mkBench ns)
  where
    mkBench n =
      env (return (distinctMsgSignaturesMinPk n)) $ \msgSigs ->
        bench ("N=" ++ show n) $
          nf (either (error . show) id . aggregateSignaturesDistinctMsgMinPk) msgSigs
    ns = [1, 10, 100, 500, 1000]

benchSigAggDistinctMsgMinSig :: Benchmark
benchSigAggDistinctMsgMinSig =
  bgroup
    "BLS12381MinSig/sigAgg/distinctMsg"
    (map mkBench ns)
  where
    mkBench n =
      env (return (distinctMsgSignaturesMinSig n)) $ \msgSigs ->
        bench ("N=" ++ show n) $
          nf (either (error . show) id . aggregateSignaturesDistinctMsgMinSig) msgSigs
    ns = [1, 10, 100, 500, 1000]

deterministicVerKeys ::
  forall v.
  DSIGNAlgorithm v =>
  Int ->
  [VerKeyDSIGN v]
deterministicVerKeys n =
  take n $
    map snd (deterministicKeyPairs @v)

sameMsgSignaturesMinPk :: Int -> [SigDSIGN BLS12381MinPkDSIGN]
sameMsgSignaturesMinPk n =
  let blsCtx = (Nothing, Nothing)
      pairs = take n (deterministicKeyPairs @BLS12381MinPkDSIGN)
   in map (\(sk, _) -> signDSIGN @BLS12381MinPkDSIGN blsCtx typicalMsg sk) pairs

sameMsgSignaturesMinSig :: Int -> [SigDSIGN BLS12381MinSigDSIGN]
sameMsgSignaturesMinSig n =
  let blsCtx = (Nothing, Nothing)
      pairs = take n (deterministicKeyPairs @BLS12381MinSigDSIGN)
   in map (\(sk, _) -> signDSIGN @BLS12381MinSigDSIGN blsCtx typicalMsg sk) pairs

distinctMsgSignaturesMinPk :: Int -> [(ByteString, SigDSIGN BLS12381MinPkDSIGN)]
distinctMsgSignaturesMinPk n =
  let blsCtx = (Nothing, Nothing)
      msgs = take n distinctMessages
      pairs = take n (deterministicKeyPairs @BLS12381MinPkDSIGN)
   in zipWith (\(sk, _) msg -> (msg, signDSIGN @BLS12381MinPkDSIGN blsCtx msg sk)) pairs msgs

distinctMsgSignaturesMinSig :: Int -> [(ByteString, SigDSIGN BLS12381MinSigDSIGN)]
distinctMsgSignaturesMinSig n =
  let blsCtx = (Nothing, Nothing)
      msgs = take n distinctMessages
      pairs = take n (deterministicKeyPairs @BLS12381MinSigDSIGN)
   in zipWith (\(sk, _) msg -> (msg, signDSIGN @BLS12381MinSigDSIGN blsCtx msg sk)) pairs msgs

-- | Aggregate BLS signatures on distinct messages using the @blst@ backend.
--   We deliberately benchmark the same encode/decode path used in production,
--   where signatures are exchanged in compressed form across the network.
aggregateSignaturesDistinctMsgMinPk ::
  [(ByteString, SigDSIGN BLS12381MinPkDSIGN)] ->
  Either BLS.BLSTError (SigDSIGN BLS12381MinPkDSIGN)
aggregateSignaturesDistinctMsgMinPk =
  \xs -> do
    sigs <- traverse (BLS.signatureFromCompressedBS @BLS.Curve1 . rawSerialiseSigDSIGN . snd) xs
    aggregated <- BLS.blsAggregateSignaturesDistinctMsg @BLS.Curve1 sigs
    maybe
      (Left BLS.BLST_BAD_ENCODING)
      Right
      (rawDeserialiseSigDSIGN (BLS.signatureToCompressedBS @BLS.Curve1 aggregated))

-- | See 'aggregateSignaturesDistinctMsgMinPk' for rationale on the encode/decode path.
aggregateSignaturesDistinctMsgMinSig ::
  [(ByteString, SigDSIGN BLS12381MinSigDSIGN)] ->
  Either BLS.BLSTError (SigDSIGN BLS12381MinSigDSIGN)
aggregateSignaturesDistinctMsgMinSig =
  \xs -> do
    sigs <- traverse (BLS.signatureFromCompressedBS @BLS.Curve2 . rawSerialiseSigDSIGN . snd) xs
    aggregated <- BLS.blsAggregateSignaturesDistinctMsg @BLS.Curve2 sigs
    maybe
      (Left BLS.BLST_BAD_ENCODING)
      Right
      (rawDeserialiseSigDSIGN (BLS.signatureToCompressedBS @BLS.Curve2 aggregated))

deterministicKeyPairs ::
  forall v.
  DSIGNAlgorithm v =>
  [(SignKeyDSIGN v, VerKeyDSIGN v)]
deterministicKeyPairs =
  map (\seed -> let sk = genKeyDSIGN @v seed in (sk, deriveVerKeyDSIGN sk)) derivedSeeds

derivedSeeds :: [Seed]
derivedSeeds =
  map mkSeedFromBytes seedBytes

seedBytes :: [ByteString]
seedBytes = iterate' bumpSeed testBytes

bumpSeed :: ByteString -> ByteString
bumpSeed bs =
  let (initBytes, lastByte) = case BS.unsnoc bs of
        Just (rest, b) -> (rest, b)
        Nothing -> (bs, 0)
   in initBytes <> BS.singleton (lastByte + 1)

distinctMessages :: [ByteString]
distinctMessages = iterate' bumpMsg typicalMsg

bumpMsg :: ByteString -> ByteString
bumpMsg bs =
  let (initBytes, lastByte) = case BS.unsnoc bs of
        Just (rest, b) -> (rest, b)
        Nothing -> (bs, 0)
   in initBytes <> BS.singleton (lastByte + 1)

instance NFData BLSMinPk.PopDSIGN where
  rnf x = x `seq` ()

instance NFData BLSMinSig.PopDSIGN where
  rnf x = x `seq` ()

instance NFData (VerKeyDSIGN BLS12381MinPkDSIGN) where rnf x = x `seq` ()
instance NFData (SignKeyDSIGN BLS12381MinPkDSIGN) where rnf x = x `seq` ()
instance NFData (SigDSIGN BLS12381MinPkDSIGN) where rnf x = x `seq` ()

instance NFData (VerKeyDSIGN BLS12381MinSigDSIGN) where rnf x = x `seq` ()
instance NFData (SignKeyDSIGN BLS12381MinSigDSIGN) where rnf x = x `seq` ()
instance NFData (SigDSIGN BLS12381MinSigDSIGN) where rnf x = x `seq` ()
