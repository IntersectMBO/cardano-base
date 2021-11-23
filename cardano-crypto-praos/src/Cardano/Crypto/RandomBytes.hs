{-# LANGUAGE ForeignFunctionInterface #-}
module Cardano.Crypto.RandomBytes
where

import Foreign.C.Types
import Foreign.Ptr

foreign import ccall "randombytes_buf" randombytes_buf :: Ptr a -> CSize -> IO ()
