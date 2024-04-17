{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Test.Crypto.AllocLog where

import Control.Tracer
import Data.Typeable
import Foreign.Ptr
import Foreign.Concurrent

import Cardano.Crypto.Libsodium (withMLockedForeignPtr)
import Cardano.Crypto.Libsodium.Memory (MLockedAllocator(..))
import Cardano.Crypto.Libsodium.Memory.Internal (MLockedForeignPtr (..))

-- | Allocation log event. These are emitted automatically whenever mlocked
-- memory is allocated through the 'mlockedAllocForeignPtr' primitive, or
-- released through an associated finalizer (either explicitly or due to GC).
-- Additional events that are not actual allocations/deallocations, but may
-- provide useful debugging context, can be inserted as 'MarkerEv'.
data AllocEvent
  = AllocEv !WordPtr
  | FreeEv !WordPtr
  | MarkerEv !String
  deriving (Eq, Show, Typeable)

mkLoggingAllocator ::
  Tracer IO AllocEvent -> MLockedAllocator IO -> MLockedAllocator IO
mkLoggingAllocator tracer ioAllocator =
  MLockedAllocator
    { mlAllocate =
        \size -> do
            sfptr@(SFP fptr) <- mlAllocate ioAllocator size
            addr <- withMLockedForeignPtr sfptr (return . ptrToWordPtr)
            traceWith tracer (AllocEv addr)
            addForeignPtrFinalizer fptr (traceWith tracer (FreeEv addr))
            return sfptr
    }
