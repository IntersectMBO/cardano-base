{-# LANGUAGE ForeignFunctionInterface #-}
module Cardano.Crypto.RandomBytes
where

foreign import ccall "randombytes_buf" randombytes_buf :: Ptr a -> CSize -> IO ()
