{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}
module Main (main) where

import           Foreign.ForeignPtr (ForeignPtr, finalizeForeignPtr, withForeignPtr)
import           Foreign.Storable (Storable (peek, poke))
import           Control.Monad (void, when)
import           GHC.Fingerprint (Fingerprint (..))
import           System.Environment (getArgs)

#ifdef MIN_VERSION_unix
import           System.Posix.Process (getProcessID)
#endif

import           Cardano.Crypto.Libsodium (allocSecureForeignPtr, sodiumInit)

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

example
    :: [String]
    -> (IO (ForeignPtr Fingerprint))
    -> IO ()
example args alloc = do
    -- create foreign ptr to mlocked memory
    fptr <- alloc
    withForeignPtr fptr $ \ptr -> poke ptr (Fingerprint 0xdead 0xc0de)

    when ("pause" `elem` args) $ do
        putStrLn "Allocated..."
        void getLine

    -- we shouldn't do this, but rather do computation inside
    -- withForeignPtr on provided Ptr a
    fingerprint <- withForeignPtr fptr peek

    -- we have the fingeprint
    print fingerprint

    -- force finalizers
    finalizeForeignPtr fptr

    when ("pause" `elem` args) $ do
        putStrLn "Finalized..."
        void getLine

    when ("use-after-free" `elem` args) $ do
        -- in this demo we can try to print it again.
        -- this should deterministically cause segmentation fault
        fingerprint' <- withForeignPtr fptr peek
        print fingerprint'
