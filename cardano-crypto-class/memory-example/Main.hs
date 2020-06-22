{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{-# OPTIONS_GHC -Wno-deprecations #-}
module Main (main) where

import           Data.Proxy (Proxy (..))
import           Foreign.Storable (Storable (poke))
import           Control.Monad (void, when)
import           GHC.Fingerprint (Fingerprint (..))
import           System.Environment (getArgs)

#ifdef MIN_VERSION_unix
import           System.Posix.Process (getProcessID)
#endif

import qualified Data.ByteString as SB

import           Cardano.Crypto.Libsodium
import           Cardano.Crypto.Libsodium.SecureBytes.Internal (SecureFiniteBytes (..))
import           Cardano.Crypto.Hash (SHA256, Blake2b_256, digest)

main :: IO ()
main = do
#ifdef MIN_VERSION_unix
    pid <- getProcessID

    putStrLn $ "If you run this test with 'pause' argument"
    putStrLn $ "you may look at /proc/" ++ show pid ++ "/maps"
    putStrLn $ "                /proc/" ++ show pid ++ "/smaps"
#endif

    sodiumInit

    args <- getArgs

    sodiumInit
    example args allocSecureForeignPtr

    -- example SHA256 hash
    do
      let input = SB.pack [0..255]
      SFB hash <- digestSecureBS (Proxy @SHA256) input
      traceSecureForeignPtr hash
      print (digest (Proxy @SHA256) input)

    -- example Blake2b_256 hash
    do
      let input = SB.pack [0..255]
      SFB hash <- digestSecureBS (Proxy @Blake2b_256) input
      traceSecureForeignPtr hash
      print (digest (Proxy @Blake2b_256) input)

example
    :: [String]
    -> (IO (SecureForeignPtr Fingerprint))
    -> IO ()
example args alloc = do
    -- create foreign ptr to mlocked memory
    fptr <- alloc
    withSecureForeignPtr fptr $ \ptr -> poke ptr (Fingerprint 0xdead 0xc0de)

    when ("pause" `elem` args) $ do
        putStrLn "Allocated..."
        void getLine

    -- we shouldn't do this, but rather do computation inside
    -- withForeignPtr on provided Ptr a
    traceSecureForeignPtr fptr

    SFB hash <- withSecureForeignPtr fptr $ \ptr ->
        digestSecureStorable (Proxy @SHA256) ptr
    -- compare with
    -- Crypto.Hash.SHA256> hash "\x00\x00\x00\x00\x00\x00\xde\xad\x00\x00\x00\x00\x00\x00\xc0\xd
    -- (cryptohash-sha256)
    -- TODO: write proper tests.
    traceSecureForeignPtr hash

    -- force finalizers
    finalizeSecureForeignPtr fptr

    when ("pause" `elem` args) $ do
        putStrLn "Finalized..."
        void getLine

    when ("use-after-free" `elem` args) $ do
        -- in this demo we can try to print it again.
        -- this should deterministically cause segmentation fault
        traceSecureForeignPtr fptr
