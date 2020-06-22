{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Cardano.Crypto.Libsodium.Memory.Internal (
  -- * High-level memory management
  SecureForeignPtr (..),
  withSecureForeignPtr,
  allocSecureForeignPtr,
  finalizeSecureForeignPtr,
  traceSecureForeignPtr,
  -- * Low-level memory function
  sodiumMalloc,
  sodiumFree,
) where

import Control.Monad (when)
import Data.Coerce (coerce)
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize (..))
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr, finalizeForeignPtr)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.Storable (Storable (alignment, sizeOf, peek))
import GHC.IO.Exception (ioException)

import Cardano.Prelude (NoUnexpectedThunks, OnlyCheckIsWHNF (..))
import Cardano.Crypto.Libsodium.C

-- | Foreign pointer to securely allocated memory.
newtype SecureForeignPtr a = SFP { _unwrapSecureForeignPtr :: ForeignPtr a }
  deriving NoUnexpectedThunks via OnlyCheckIsWHNF "SecureForeignPtr" (SecureForeignPtr a)

withSecureForeignPtr :: forall a b. SecureForeignPtr a -> (Ptr a -> IO b) -> IO b
withSecureForeignPtr = coerce (withForeignPtr @a @b)

finalizeSecureForeignPtr :: forall a. SecureForeignPtr a -> IO ()
finalizeSecureForeignPtr = coerce (finalizeForeignPtr @a)

traceSecureForeignPtr :: (Storable a, Show a) => SecureForeignPtr a -> IO ()
traceSecureForeignPtr fptr = withSecureForeignPtr fptr $ \ptr -> do
    a <- peek ptr
    print a

{-# DEPRECATED traceSecureForeignPtr "Don't leave traceSecureForeignPtr in production" #-}

-- | Allocate secure memory using 'c_sodium_malloc'.
--
-- <https://libsodium.gitbook.io/doc/memory_management>
--
allocSecureForeignPtr :: Storable a => IO (SecureForeignPtr a)
allocSecureForeignPtr = impl undefined where
    impl :: forall b. Storable b => b -> IO (SecureForeignPtr b)
    impl b = do
        ptr <- sodiumMalloc size
        fmap SFP (newForeignPtr c_sodium_free_funptr ptr)

      where
        size :: CSize
        size = fromIntegral size''

        size' :: Int
        size' = sizeOf b

        align :: Int
        align = alignment b

        size'' :: Int
        size''
            | m == 0    = size'
            | otherwise = (q + 1) * align
          where
            (q,m) = size' `divMod` align

sodiumMalloc :: CSize -> IO (Ptr a)
sodiumMalloc size = do
    ptr <- c_sodium_malloc size
    when (ptr == nullPtr) $ do
        errno <- getErrno
        ioException $ errnoToIOError "c_sodium_malloc" errno Nothing Nothing
    return ptr

sodiumFree :: Ptr a -> IO ()
sodiumFree = c_sodium_free
