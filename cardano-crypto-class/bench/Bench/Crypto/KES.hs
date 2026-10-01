{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Bench.Crypto.KES (
  benchmarks,
) where

import Data.Maybe (fromJust)
import Data.Proxy

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.Hash.Blake2b
import Cardano.Crypto.KES.Class
import Cardano.Crypto.KES.CompactSum
import Cardano.Crypto.KES.Sum

import Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.Libsodium.MLockedSeed
import Criterion
import qualified Data.ByteString as BS (ByteString, length)
import Data.Either (fromRight)
import Data.Kind (Type)
import GHC.TypeLits (KnownNat)
import System.IO.Unsafe (unsafePerformIO)

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}

{-# NOINLINE testSeedML #-}
testSeedML :: forall n. KnownNat n => MLockedSeed n
testSeedML = MLockedSeed . unsafePerformIO $ NaCl.mlsbFromByteString testBytes

benchmarks :: Benchmark
benchmarks =
  bgroup
    "KES"
    [ bgroup
        ("msg_len:" <> show (BS.length msg))
        [ benchKES @Proxy @(Sum6KES Ed25519DSIGN Blake2b_256) Proxy "Sum6KES" msg
        , benchKES @Proxy @(Sum7KES Ed25519DSIGN Blake2b_256) Proxy "Sum7KES" msg
        , benchKES @Proxy @(CompactSum6KES Ed25519DSIGN Blake2b_256) Proxy "CompactSum6KES" msg
        , benchKES @Proxy @(CompactSum7KES Ed25519DSIGN Blake2b_256) Proxy "CompactSum7KES" msg
        ]
    | msg <- [typicalMsg, testBytes]
    ]

{-# NOINLINE benchKES #-}
benchKES ::
  forall (proxy :: forall k. k -> Type) v.
  ( KESAlgorithm v
  , ContextKES v ~ ()
  , Signable v BS.ByteString
  , NFData (SignKeyKES v)
  , NFData (SigKES v)
  , NFData (VerKeyKES v)
  ) =>
  proxy v ->
  [Char] ->
  BS.ByteString ->
  Benchmark
benchKES _ lbl msg =
  bgroup
    lbl
    [ bench "genKey" $
        nfIO $
          genKeyKES @v testSeedML >>= forgetSignKeyKES @v
    , env (genKeyKES @v testSeedML) $ \signKey ->
        bench "signKES" $
          nfIO $ do
            sig <- signKES @v () 0 msg signKey
            sig <$ forgetSignKeyKES signKey
    , let prepSignedEnv = do
            signKey <- genKeyKES @v testSeedML
            verKey <- deriveVerKeyKES signKey
            sig <- signKES @v () 0 msg signKey
            forgetSignKeyKES signKey
            pure (verKey, sig)
       in env prepSignedEnv $ \ ~(verKey, sig) ->
            bench "verifyKES" $
              nf (fromRight . verifyKES @v () verKey 0 typicalMsg) sig
    , env (genKeyKES @v testSeedML) $ \signKey ->
        bench "updateKES" $
          nfIO $ do
            sk <- fromJust <$> updateKES () signKey 0
            sk <$ forgetSignKeyKES signKey
    ]
