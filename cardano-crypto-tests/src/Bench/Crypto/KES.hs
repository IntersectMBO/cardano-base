{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
module Bench.Crypto.KES
  ( benchmarks
  ) where

import Data.Proxy
import Data.Maybe (fromJust)

import Control.DeepSeq

import Cardano.Crypto.DSIGN.Ed25519ML
import Cardano.Crypto.Hash.Blake2b
import Cardano.Crypto.KES.Class
import Cardano.Crypto.KES.Sum
import Cardano.Crypto.KES.CompactSum


import Criterion
import qualified Data.ByteString as BS (ByteString)
import Data.Either (fromRight)
import Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.MLockedSeed
import System.IO.Unsafe (unsafePerformIO)
import GHC.TypeLits (KnownNat)
import Data.Kind (Type)

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}

{-# NOINLINE testSeedML #-}
testSeedML :: forall n. KnownNat n => MLockedSeed n
testSeedML = MLockedSeed . unsafePerformIO $ NaCl.mlsbFromByteString testBytes

benchmarks :: Benchmark
benchmarks = bgroup "KES"
  [ benchKES @Proxy @(Sum6KES Ed25519DSIGNM Blake2b_256) Proxy "Sum6KES"
  , benchKES @Proxy @(Sum7KES Ed25519DSIGNM Blake2b_256) Proxy "Sum7KES"
  , benchKES @Proxy @(CompactSum6KES Ed25519DSIGNM Blake2b_256) Proxy "CompactSum6KES"
  , benchKES @Proxy @(CompactSum7KES Ed25519DSIGNM Blake2b_256) Proxy "CompactSum7KES"
  ]



{-# NOINLINE benchKES #-}
benchKES :: forall (proxy :: forall k. k -> Type) v
           . ( KESSignAlgorithm IO v
             , ContextKES v ~ ()
             , Signable v BS.ByteString
             , NFData (SignKeyKES v)
             , NFData (SigKES v)
             )
          => proxy v
          -> [Char]
          -> Benchmark
benchKES _ lbl =
  bgroup lbl
    [ bench "genKey" $
        nfIO $ genKeyKES @IO @v testSeedML >>= forgetSignKeyKES @IO @v
    , bench "signKES" $
        nfIO $
          (\sk -> do { sig <- signKES @IO @v () 0 typicalMsg sk; forgetSignKeyKES sk; return sig })
            =<< (genKeyKES @IO @v testSeedML)
    , bench "verifyKES" $
        nfIO $ do
          signKey <- genKeyKES @IO @v testSeedML
          sig <- signKES @IO @v () 0 typicalMsg signKey
          verKey <- deriveVerKeyKES signKey
          forgetSignKeyKES signKey
          return . fromRight $ verifyKES @v () verKey 0 typicalMsg sig
    , bench "updateKES" $
        nfIO $ do
          signKey <- genKeyKES @IO @v testSeedML
          sk' <- fromJust <$> updateKES () signKey 0
          forgetSignKeyKES signKey
          return sk'
    ]
