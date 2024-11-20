{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Main where

import Cardano.Memory.Pool
import Control.DeepSeq
import Control.Monad
import Control.Monad.ST (RealWorld, stToIO)
import Criterion.Main
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import GHC.IO (ioToST)
import GHC.TypeLits
import UnliftIO.Async (pooledReplicateConcurrently)

instance NFData (Pool n s) where
  rnf !_ = ()

instance NFData (ForeignPtr a) where
  rnf !_ = ()

initHaskellPool :: KnownNat n => Int -> IO (Pool n RealWorld)
initHaskellPool n = stToIO $ initPool n (ioToST . mallocForeignPtrBytes) (const (pure ()))

cmallocForeignPtr :: Int -> IO (ForeignPtr a)
cmallocForeignPtr n = do
  ptr <- mallocBytes n
  newForeignPtr finalizerFree ptr

main :: IO ()
main = do
  let n = 10240
      blockSize = 32
  defaultMain
    [ bgroup
        "Sequential"
        [ env (initHaskellPool @32 (n `div` 64)) $ \pool ->
            bench "ForeignPtr (Pool)" $ nfIO $ replicateM n (stToIO (grabNextBlock pool))
        , bench "ForeignPtr (ByteArray)" $
            nfIO (replicateM n (mallocForeignPtrBytes blockSize))
        , bench "ForeignPtr (malloc)" $
            nfIO (replicateM n (cmallocForeignPtr blockSize))
        ]
    , bgroup
        "Concurrent"
        [ env (initHaskellPool @32 (n `div` 64)) $ \pool ->
            bench "ForeignPtr (Pool)" $
              nfIO (pooledReplicateConcurrently n (stToIO (grabNextBlock pool)))
        , bench "ForeignPtr (ByteArray)" $
            nfIO (pooledReplicateConcurrently n (mallocForeignPtrBytes blockSize))
        , bench "ForeignPtr (malloc)" $
            nfIO (pooledReplicateConcurrently n (cmallocForeignPtr blockSize))
        ]
    ]
