{-# LANGUAGE CApiFFI             #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Cardano.Crypto.Libsodium
  ( -- * High level interface
    sodiumInit

  , allocSecureForeignPtr

    -- * Low-level interface
    -- ** Initialization
  , c_sodium_init

    -- ** Zeroing memory
  , c_sodium_memzero

    -- ** Guarded heap allocations
  , c_sodium_malloc
  , c_sodium_free_funptr
  ) where

import Control.Monad (when, unless)
import Foreign.C.Error (errnoToIOError, getErrno)
import Foreign.C.Types (CSize (..))
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr)
import Foreign.Ptr (FunPtr, Ptr, nullPtr)
import Foreign.Storable (Storable (alignment, sizeOf))
import GHC.IO.Exception (ioException)

-------------------------------------------------------------------------------
-- Initialization
-------------------------------------------------------------------------------

-- @sodiumInit@ initializes the library and should be called before any other
-- function provided by Sodium. It is safe to call this function more than once
-- and from different threads -- subsequent calls won't have any effects.
--
-- <https://libsodium.gitbook.io/doc/usage>
sodiumInit :: IO ()
sodiumInit = do
    res <- c_sodium_init
    -- sodium_init() returns 0 on success, -1 on failure, and 1 if the library
    -- had already been initialized.
    unless (res == 0 || res == 1) $ fail "sodium_init failed"

-------------------------------------------------------------------------------
-- Acquiring memory
-------------------------------------------------------------------------------

-- | Allocate secure memory using 'c_sodium_malloc'.
--
-- <https://libsodium.gitbook.io/doc/memory_management>
--
allocSecureForeignPtr :: Storable a => IO (ForeignPtr a)
allocSecureForeignPtr = impl undefined where
    impl :: forall b. Storable b => b -> IO (ForeignPtr b)
    impl b = do
        ptr <- c_sodium_malloc size
        when (ptr == nullPtr) $ do
            errno <- getErrno
            ioException $ errnoToIOError "allocSecureForeingPtr: c_sodium_malloc" errno Nothing Nothing

        newForeignPtr c_sodium_free_funptr ptr

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

-------------------------------------------------------------------------------
-- Low-level c-bindings
-------------------------------------------------------------------------------

-- | @void sodium_init():@
--
-- <https://libsodium.gitbook.io/doc/usage>
foreign import capi "sodium.h sodium_init"  c_sodium_init :: IO Int

-- | @void sodium_memzero(void * const pnt, const size_t len);@
--
-- <https://libsodium.gitbook.io/doc/memory_management#zeroing-memory>
foreign import capi "sodium.h sodium_memzero" c_sodium_memzero :: Ptr a -> CSize -> IO ()

-- | @void *sodium_malloc(size_t size);@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi "sodium.h sodium_malloc" c_sodium_malloc :: CSize -> IO (Ptr a)

-- | @void sodium_free(void *ptr);@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi "sodium.h &sodium_free" c_sodium_free_funptr :: FunPtr (Ptr a -> IO ())
