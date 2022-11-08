{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Main where

import Foreign.Marshal.Alloc
import GHC.TypeLits
import Criterion.Main
import Cardano.Memory.Pool
import Foreign.ForeignPtr
import Control.DeepSeq
import UnliftIO.Async (pooledReplicateConcurrently)
import Control.Monad

instance NFData (Pool n) where
  rnf !_ = ()

instance NFData (ForeignPtr a) where
  rnf !_ = ()

initHaskellPool :: KnownNat n => Int -> IO (Pool n)
initHaskellPool n = initPool n mallocForeignPtrBytes (const (pure ()))

cmallocForeignPtr :: Int -> IO (ForeignPtr a)
cmallocForeignPtr n = do
  ptr <- mallocBytes n
  newForeignPtr finalizerFree ptr

main :: IO ()
main = do
  let n = 10240
      blockSize = 32
  defaultMain
    [ bgroup "Optimal"
      [ env (initHaskellPool @32 (n `div` 64)) $ \pool ->
          bench "ForeignPtr (Pool)" $ nfIO (replicateM n (grabNextBlock pool))
      , bench "ForeignPtr (ByteArray)" $
          nfIO (replicateM n (mallocForeignPtrBytes blockSize))
      , bench "ForeignPtr (malloc)" $
          nfIO (replicateM n (cmallocForeignPtr blockSize))
      ]
    , bgroup "Concurrent"
      [ env (initHaskellPool @32 (n `div` 64)) $ \pool ->
          bench "ForeignPtr (Pool)" $ nfIO (pooledReplicateConcurrently n (grabNextBlock pool))
      , bench "ForeignPtr (ByteArray)" $
          nfIO (pooledReplicateConcurrently n (mallocForeignPtrBytes blockSize))
      , bench "ForeignPtr (malloc)" $
          nfIO (pooledReplicateConcurrently n (cmallocForeignPtr blockSize))
      ]
    ]
