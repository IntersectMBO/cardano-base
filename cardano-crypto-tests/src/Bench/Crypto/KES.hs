{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE TypeFamilies #-}
{-#LANGUAGE FlexibleContexts #-}
{-#LANGUAGE OverloadedStrings #-}
{-#LANGUAGE PolyKinds #-}
{-#LANGUAGE RankNTypes #-}
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

import Control.Concurrent.MVar
import Control.Exception (bracket)

import Criterion
import qualified Data.ByteString as BS (ByteString)
import Data.Either (fromRight)
import Cardano.Crypto.Libsodium as NaCl
import System.IO.Unsafe (unsafePerformIO)
import GHC.TypeLits (KnownNat)
import Data.Kind (Type)

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}

{-# NOINLINE testSeedMLSB #-}
testSeedMLSB :: forall n. KnownNat n => NaCl.MLockedSizedBytes n
testSeedMLSB = unsafePerformIO $ NaCl.mlsbFromByteString testBytes

withKESLock :: MVar () -> IO a -> IO a
withKESLock kesLock action =
  bracket
    (takeMVar kesLock)
    (putMVar kesLock)
    (const action)

benchmarks :: MVar () -> Benchmark
benchmarks kesLock = bgroup "KES"
  [ benchKES @Proxy @(Sum6KES Ed25519DSIGNM Blake2b_256) Proxy kesLock "Sum6KES"
  , benchKES @Proxy @(Sum7KES Ed25519DSIGNM Blake2b_256) Proxy kesLock "Sum7KES"
  , benchKES @Proxy @(CompactSum6KES Ed25519DSIGNM Blake2b_256) Proxy kesLock "CompactSum6KES"
  , benchKES @Proxy @(CompactSum7KES Ed25519DSIGNM Blake2b_256) Proxy kesLock "CompactSum7KES"
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
          -> MVar ()
          -> [Char]
          -> Benchmark
benchKES _ kesLock lbl =
  bgroup lbl
    [ bench "genKey" $
        nfIO . withKESLock kesLock $ genKeyKES @IO @v testSeedMLSB >>= forgetSignKeyKES @IO @v
    , bench "signKES" $
        nfIO . withKESLock kesLock $
          (\sk -> do { sig <- signKES @IO @v () 0 typicalMsg sk; forgetSignKeyKES sk; return sig })
            =<< (genKeyKES @IO @v testSeedMLSB)
    , bench "verifyKES" $
        nfIO . withKESLock kesLock $ do
          signKey <- genKeyKES @IO @v testSeedMLSB
          sig <- signKES @IO @v () 0 typicalMsg signKey
          verKey <- deriveVerKeyKES signKey
          forgetSignKeyKES signKey
          return . fromRight $ verifyKES @v () verKey 0 typicalMsg sig
    , bench "updateKES" $
        nfIO . withKESLock kesLock $ do
          signKey <- genKeyKES @IO @v testSeedMLSB
          sk' <- fromJust <$> updateKES () signKey 0
          forgetSignKeyKES signKey
          return sk'
    ]
