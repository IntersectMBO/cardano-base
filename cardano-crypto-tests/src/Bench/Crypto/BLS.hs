{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Benchmarks comparing pairing-based verification vs the BLST core verifier.
--
-- Example:
-- cabal bench cardano-crypto-tests:bench-crypto --benchmark-options='--output bls.html'
module Bench.Crypto.BLS (
  benchmarks,
) where

import Control.DeepSeq (NFData (..))
import Criterion (Benchmark, bench, bgroup, env, nf, whnf)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Proxy (Proxy (..))

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  BLS,
  Affine,
  CoreVerifyOrder,
  Curve1,
  Curve2,
  Dual,
  FinalVerifyOrder,
  PublicKey (..),
  Signature (..),
  blsSignatureVerifyPairingAffine,
  blsSignatureVerifyCoreAffine,
  blsKeyGen,
  blsSign,
  blsSignatureVerify,
  blsSignatureVerifyCore,
  blsSkToPk,
  toAffine,
 )

benchmarks :: Benchmark
benchmarks =
  bgroup
    "BLS"
    [ curveGroup (Proxy @Curve1) "Curve1 (MinPk)"
    , curveGroup (Proxy @Curve2) "Curve2 (MinSig)"
    ]

curveGroup ::
  forall curve.
  CoreVerifyOrder curve =>
  Proxy curve ->
  String ->
  Benchmark
curveGroup proxy label =
  bgroup
    label
    [ env (pure (prepareInputs proxy shortSeed shortMsg Nothing Nothing)) $
        \bundle ->
          let standard = veStandard bundle
              affine = veAffine bundle
           in
          bgroup
            "short msg / ctx=None"
            [ bench "pairing verify" $
                nf (runPairingVerify proxy) standard
            , bench "core verify" $
                nf (runCoreVerify proxy) standard
            , bench "pairing verify (pre-affine)" $
                nf (runPairingVerifyAffine proxy) affine
            , bench "core verify (pre-affine)" $
                nf (runCoreVerifyAffine proxy) affine
            , bench "pk toAffine" $
                whnf (publicKeyAffine @curve) (viPublicKey standard)
            , bench "sig toAffine" $
                whnf (signatureAffine @curve) (viSignature standard)
            ]
    , env (pure (prepareInputs proxy longSeed longMsg (Just defaultDst) (Just defaultAug))) $
        \bundle ->
          let standard = veStandard bundle
              affine = veAffine bundle
           in
          bgroup
            "4KB msg / ctx=default+aug"
            [ bench "pairing verify" $
                nf (runPairingVerify proxy) standard
            , bench "core verify" $
                nf (runCoreVerify proxy) standard
            , bench "pairing verify (pre-affine)" $
                nf (runPairingVerifyAffine proxy) affine
            , bench "core verify (pre-affine)" $
                nf (runCoreVerifyAffine proxy) affine
            , bench "pk toAffine" $
                whnf (publicKeyAffine @curve) (viPublicKey standard)
            , bench "sig toAffine" $
                whnf (signatureAffine @curve) (viSignature standard)
            ]
    ]

data VerifyInputs curve = VerifyInputs
  { viPublicKey :: !(PublicKey curve)
  , viSignature :: !(Signature curve)
  , _viMessage :: !ByteString
  , _viDst :: !(Maybe ByteString)
  , _viAug :: !(Maybe ByteString)
  }

data VerifyInputsAffine curve
  = VerifyInputsAffine !(Affine curve) !(Affine (Dual curve)) !ByteString !(Maybe ByteString) !(Maybe ByteString)

data VerifyEnv curve = VerifyEnv
  { veStandard :: !(VerifyInputs curve)
  , veAffine :: !(VerifyInputsAffine curve)
  }

instance NFData (VerifyInputs curve) where
  rnf (VerifyInputs !_ !_ !_ !_ !_) = ()

instance NFData (VerifyInputsAffine curve) where
  rnf (VerifyInputsAffine !_ !_ !_ !_ !_) = ()

instance NFData (VerifyEnv curve) where
  rnf (VerifyEnv !_ !_) = ()

prepareInputs ::
  forall curve.
  CoreVerifyOrder curve =>
  Proxy curve ->
  ByteString ->
  ByteString ->
  Maybe ByteString ->
  Maybe ByteString ->
  VerifyEnv curve
prepareInputs proxy seed msg dst aug =
  case blsKeyGen seed Nothing of
    Left err -> error ("blsKeyGen failed: " <> show err)
    Right sk ->
      let pk = blsSkToPk sk
          sig = blsSign proxy sk msg dst aug
          pkAffine = publicKeyAffine pk
          sigAffine = signatureAffine sig
       in VerifyEnv
            { veStandard = VerifyInputs pk sig msg dst aug
            , veAffine = VerifyInputsAffine pkAffine sigAffine msg dst aug
            }

runPairingVerify ::
  forall curve.
  FinalVerifyOrder curve =>
  Proxy curve ->
  VerifyInputs curve ->
  Bool
runPairingVerify _ (VerifyInputs pk sig msg dst aug) =
  blsSignatureVerify pk msg sig dst aug

runCoreVerify ::
  forall curve.
  CoreVerifyOrder curve =>
  Proxy curve ->
  VerifyInputs curve ->
  Bool
runCoreVerify _ (VerifyInputs pk sig msg dst aug) =
  blsSignatureVerifyCore pk msg sig dst aug

runPairingVerifyAffine ::
  forall curve.
  FinalVerifyOrder curve =>
  Proxy curve ->
  VerifyInputsAffine curve ->
  Bool
runPairingVerifyAffine _ (VerifyInputsAffine pk sig msg dst aug) =
  blsSignatureVerifyPairingAffine pk sig msg dst aug

runCoreVerifyAffine ::
  forall curve.
  CoreVerifyOrder curve =>
  Proxy curve ->
  VerifyInputsAffine curve ->
  Bool
runCoreVerifyAffine _ (VerifyInputsAffine pk sig msg dst aug) =
  blsSignatureVerifyCoreAffine pk sig msg dst aug

publicKeyAffine :: BLS curve => PublicKey curve -> Affine curve
publicKeyAffine (PublicKey pk) = toAffine pk

signatureAffine :: BLS (Dual curve) => Signature curve -> Affine (Dual curve)
signatureAffine (Signature sig) = toAffine sig

defaultDst :: ByteString
defaultDst = BS8.pack "BLS_DST_CARDANO_BASE_V1"

defaultAug :: ByteString
defaultAug = BS8.pack "role=vote"

shortSeed :: ByteString
shortSeed = BS8.pack "seed-000000000000000000000000000001"

longSeed :: ByteString
longSeed = BS8.pack "seed-000000000000000000000000000002"

shortMsg :: ByteString
shortMsg = BS8.pack "message-one"

longMsg :: ByteString
longMsg = BS.replicate 4096 0x42
