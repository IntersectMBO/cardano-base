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

import Criterion
import qualified Data.ByteString as BS (ByteString)
import Data.Either (fromRight)
import Cardano.Crypto.Libsodium as NaCl
import Test.Crypto.RunIO (RunIO (..))
import System.IO.Unsafe (unsafePerformIO)
import GHC.TypeLits (KnownNat)
import Data.Kind (Type)

import Bench.Crypto.BenchData

{- HLINT ignore "Use camelCase" -}

{-# NOINLINE testSeedMLSB #-}
testSeedMLSB :: forall n. KnownNat n => NaCl.MLockedSizedBytes n
testSeedMLSB = unsafePerformIO $ NaCl.mlsbFromByteString testBytes


benchmarks :: Benchmark
benchmarks = bgroup "KES"
  [ benchKES @Proxy @IO @(Sum6KES Ed25519DSIGNM Blake2b_256) Proxy Proxy "Sum6KES"
  , benchKES @Proxy @IO @(Sum7KES Ed25519DSIGNM Blake2b_256) Proxy Proxy "Sum7KES"
  , benchKES @Proxy @IO @(CompactSum6KES Ed25519DSIGNM Blake2b_256) Proxy Proxy "CompactSum6KES"
  , benchKES @Proxy @IO @(CompactSum7KES Ed25519DSIGNM Blake2b_256) Proxy Proxy "CompactSum7KES"
  ]



{-# NOINLINE benchKES #-}
benchKES :: forall (proxy :: forall k. k -> Type) m v
           . ( KESSignAlgorithm m v
             , ContextKES v ~ ()
             , Signable v BS.ByteString
             , NFData (SignKeyKES v)
             , NFData (SigKES v)
             , RunIO m
             )
          => proxy m
          -> proxy v
          -> [Char]
          -> Benchmark
benchKES _ _ lbl =
  bgroup lbl
    [ bench "genKey" $
        nfIO . io $ genKeyKES @m @v testSeedMLSB >>= forgetSignKeyKES @m @v
    , bench "signKES" $
        nfIO . io $
          (\sk -> do { sig <- signKES @m @v () 0 typicalMsg sk; forgetSignKeyKES sk; return sig })
            =<< (genKeyKES @m @v testSeedMLSB)
    , bench "verifyKES" $
        nfIO . io $ do
          signKey <- genKeyKES @m @v testSeedMLSB
          sig <- signKES @m @v () 0 typicalMsg signKey
          verKey <- deriveVerKeyKES signKey
          forgetSignKeyKES signKey
          return . fromRight $ verifyKES @v () verKey 0 typicalMsg sig
    , bench "updateKES" $
        nfIO . io $ do
          signKey <- genKeyKES @m @v testSeedMLSB
          sk' <- fromJust <$> updateKES () signKey 0
          forgetSignKeyKES signKey
          return sk'
    ]
