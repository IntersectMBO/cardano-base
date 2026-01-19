{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Crypto.Libsodium.MLockedBytes.Internal (
  -- * The MLockesSizedBytes type
  MLockedSizedBytes (..),
  SizedVoid,

  -- * Safe Functions
  mlsbNew,
  mlsbNewZero,
  mlsbZero,
  mlsbUseAsCPtr,
  mlsbUseAsSizedPtr,
  mlsbCopy,
  mlsbFinalize,
  mlsbCompare,
  mlsbEq,
  withMLSB,
  withMLSBChunk,
  mlsbNewWith,
  mlsbNewZeroWith,
  mlsbCopyWith,

  -- * Dangerous Functions
  traceMLSB,
  mlsbFromByteString,
  mlsbFromByteStringCheck,
  mlsbAsByteString,
  mlsbToByteString,
  mlsbFromByteStringWith,
  mlsbFromByteStringCheckWith,
) where

import Control.DeepSeq (NFData (..))
import Control.Monad.Class.MonadST
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Foreign.C.Types (CSize (..))
import Foreign.ForeignPtr (castForeignPtr, newForeignPtr_)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import GHC.TypeLits (KnownNat, Nat, natVal)
import NoThunks.Class (NoThunks)

import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.Libsodium.Memory
import Cardano.Crypto.Libsodium.Memory.Internal (MLockedForeignPtr (..))
import Cardano.Foreign

import Data.Bits (Bits, shiftL)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI

-- | A void type with a type-level size attached to it. We need this in order
-- to express \"pointer to a block of memory of a particular size that can be
-- manipulated through the pointer, but not as a plain Haskell value\" as
-- @Ptr (SizedVoid n)@, or @ForeignPtr (SizedVoid n)@, or
-- @MLockedForeignPtr (SizedVoid n)@.
data SizedVoid (n :: Nat)

-- | A block of raw memory of a known size, protected with @mlock()@.
newtype MLockedSizedBytes (n :: Nat) = MLSB (MLockedForeignPtr (SizedVoid n))
  deriving newtype (NoThunks)
  deriving newtype (NFData)

-- | This instance is /unsafe/, it will leak secrets from mlocked memory to the
-- Haskell heap. Do not use outside of testing.
instance KnownNat n => Show (MLockedSizedBytes n) where
  show mlsb = "MLockedSizedBytes[" ++ show (natVal mlsb) ++ "]"

-- TODO: move this to test suite, with a newtype wrapper
-- show mlsb =
--   let bytes = BS.unpack $ mlsbAsByteString mlsb
--       hexstr = concatMap (printf "%02x") bytes
--   in "MLSB " ++ hexstr

nextPowerOf2 :: forall n. (Num n, Ord n, Bits n) => n -> n
nextPowerOf2 i =
  go 1
  where
    go :: n -> n
    go c =
      let c' = c `shiftL` 1
       in if c >= i then c else go c'

traceMLSB :: KnownNat n => MLockedSizedBytes n -> IO ()
traceMLSB = print
{-# DEPRECATED traceMLSB "Don't leave traceMLockedForeignPtr in production" #-}

withMLSB :: forall b n m. MonadST m => MLockedSizedBytes n -> (Ptr (SizedVoid n) -> m b) -> m b
withMLSB (MLSB fptr) action = withMLockedForeignPtr fptr action

withMLSBChunk ::
  forall b n n' m.
  (MonadST m, KnownNat n, KnownNat n') =>
  MLockedSizedBytes n ->
  Int ->
  (MLockedSizedBytes n' -> m b) ->
  m b
withMLSBChunk mlsb offset action
  | offset < 0 =
      error "Negative offset not allowed"
  | offset > parentSize - chunkSize =
      error $ "Overrun (" ++ show offset ++ " + " ++ show chunkSize ++ " > " ++ show parentSize ++ ")"
  | otherwise =
      withMLSB mlsb $ \ptr -> do
        fptr <-
          stToIO $ unsafeIOToST (newForeignPtr_ . castPtr $ plusPtr ptr offset)
        action (MLSB $! SFP $! fptr)
  where
    chunkSize = fromIntegral @Integer @Int (natVal (Proxy @n'))
    parentSize = fromIntegral @Integer @Int (natVal mlsb)

mlsbSize :: KnownNat n => MLockedSizedBytes n -> CSize
mlsbSize mlsb = fromInteger (natVal mlsb)

-- | Allocate a new 'MLockedSizedBytes'. The caller is responsible for
-- deallocating it ('mlsbFinalize') when done with it. The contents of the
-- memory block is undefined.
mlsbNew :: forall n m. (KnownNat n, MonadST m) => m (MLockedSizedBytes n)
mlsbNew = mlsbNewWith mlockedMalloc

mlsbNewWith :: forall n m. MLockedAllocator m -> (KnownNat n, MonadST m) => m (MLockedSizedBytes n)
mlsbNewWith allocator =
  MLSB <$> mlockedAllocForeignPtrBytesWith allocator size align
  where
    size = fromInteger (natVal (Proxy @n))
    align = nextPowerOf2 size

-- | Allocate a new 'MLockedSizedBytes', and pre-fill it with zeroes.
-- The caller is responsible for deallocating it ('mlsbFinalize') when done
-- with it. (See also 'mlsbNew').
mlsbNewZero :: forall n m. (KnownNat n, MonadST m) => m (MLockedSizedBytes n)
mlsbNewZero = mlsbNewZeroWith mlockedMalloc

mlsbNewZeroWith ::
  forall n m. (KnownNat n, MonadST m) => MLockedAllocator m -> m (MLockedSizedBytes n)
mlsbNewZeroWith allocator = do
  mlsb <- mlsbNewWith allocator
  mlsbZero mlsb
  return mlsb

-- | Overwrite an existing 'MLockedSizedBytes' with zeroes.
mlsbZero :: forall n m. (KnownNat n, MonadST m) => MLockedSizedBytes n -> m ()
mlsbZero mlsb = do
  withMLSB mlsb $ \ptr -> zeroMem ptr (mlsbSize mlsb)

-- | Create a deep mlocked copy of an 'MLockedSizedBytes'.
mlsbCopy ::
  forall n m.
  (KnownNat n, MonadST m) =>
  MLockedSizedBytes n ->
  m (MLockedSizedBytes n)
mlsbCopy = mlsbCopyWith mlockedMalloc

mlsbCopyWith ::
  forall n m.
  (KnownNat n, MonadST m) =>
  MLockedAllocator m ->
  MLockedSizedBytes n ->
  m (MLockedSizedBytes n)
mlsbCopyWith allocator src = mlsbUseAsCPtr src $ \ptrSrc -> do
  dst <- mlsbNewWith allocator
  withMLSB dst $ \ptrDst -> do
    copyMem (castPtr ptrDst) (castPtr ptrSrc) (mlsbSize src)
  return dst

-- | Allocate a new 'MLockedSizedBytes', and fill it with the contents of a
-- 'ByteString'. The size of the input is not checked.
-- /Note:/ since the input 'BS.ByteString' is a plain old Haskell value, it has
-- already violated the secure-forgetting properties afforded by
-- 'MLockedSizedBytes', so this function is useless outside of testing. Use
-- 'mlsbNew' or 'mlsbNewZero' to create 'MLockedSizedBytes' values, and
-- manipulate them through 'withMLSB', 'mlsbUseAsCPtr', or 'mlsbUseAsSizedPtr'.
-- (See also 'mlsbFromByteStringCheck')
mlsbFromByteString ::
  forall n m.
  (KnownNat n, MonadST m) =>
  BS.ByteString ->
  m (MLockedSizedBytes n)
mlsbFromByteString = mlsbFromByteStringWith mlockedMalloc

mlsbFromByteStringWith ::
  forall n m.
  (KnownNat n, MonadST m) =>
  MLockedAllocator m ->
  BS.ByteString ->
  m (MLockedSizedBytes n)
mlsbFromByteStringWith allocator bs = do
  dst <- mlsbNewWith allocator
  withMLSB dst $ \ptr -> stToIO . unsafeIOToST $ do
    BS.useAsCStringLen bs $ \(ptrBS, len) -> do
      copyMem (castPtr ptr) ptrBS (min (fromIntegral @Int @CSize len) (mlsbSize dst))
  return dst

-- | Allocate a new 'MLockedSizedBytes', and fill it with the contents of a
-- 'ByteString'. The size of the input is checked.
-- /Note:/ since the input 'BS.ByteString' is a plain old Haskell value, it has
-- already violated the secure-forgetting properties afforded by
-- 'MLockedSizedBytes', so this function is useless outside of testing. Use
-- 'mlsbNew' or 'mlsbNewZero' to create 'MLockedSizedBytes' values, and
-- manipulate them through 'withMLSB', 'mlsbUseAsCPtr', or 'mlsbUseAsSizedPtr'.
-- (See also 'mlsbFromByteString')
mlsbFromByteStringCheck ::
  forall n m.
  (KnownNat n, MonadST m) =>
  BS.ByteString ->
  m (Maybe (MLockedSizedBytes n))
mlsbFromByteStringCheck = mlsbFromByteStringCheckWith mlockedMalloc

mlsbFromByteStringCheckWith ::
  forall n m.
  (KnownNat n, MonadST m) =>
  MLockedAllocator m ->
  BS.ByteString ->
  m (Maybe (MLockedSizedBytes n))
mlsbFromByteStringCheckWith allocator bs
  | BS.length bs /= size = return Nothing
  | otherwise = Just <$> mlsbFromByteStringWith allocator bs
  where
    size :: Int
    size = fromInteger (natVal (Proxy @n))

-- | /Note:/ the resulting 'BS.ByteString' will still refer to secure memory,
-- but the types don't prevent it from be exposed. Note further that any
-- subsequent operations (splicing & dicing, copying, conversion,
-- packing/unpacking, etc.) on the resulting 'BS.ByteString' may create copies
-- of the mlocked memory on the unprotected GHC heap, and thus leak secrets,
-- so use this function with extreme care.
mlsbAsByteString :: forall n. KnownNat n => MLockedSizedBytes n -> BS.ByteString
mlsbAsByteString mlsb@(MLSB (SFP fptr)) = BSI.PS (castForeignPtr fptr) 0 size
  where
    size :: Int
    size = fromIntegral @CSize @Int (mlsbSize mlsb)

-- | /Note:/ this function will leak mlocked memory to the Haskell heap
-- and should not be used in production code.
mlsbToByteString :: forall n m. (KnownNat n, MonadST m) => MLockedSizedBytes n -> m BS.ByteString
mlsbToByteString mlsb =
  withMLSB mlsb $ \ptr ->
    stToIO . unsafeIOToST $ BS.packCStringLen (castPtr ptr, size)
  where
    size :: Int
    size = fromIntegral @CSize @Int (mlsbSize mlsb)

-- | Use an 'MLockedSizedBytes' value as a raw C pointer. Care should be taken
-- to never copy the contents of the 'MLockedSizedBytes' value into managed
-- memory through the raw pointer, because that would violate the
-- secure-forgetting property of mlocked memory.
mlsbUseAsCPtr :: MonadST m => MLockedSizedBytes n -> (Ptr Word8 -> m r) -> m r
mlsbUseAsCPtr (MLSB x) k =
  withMLockedForeignPtr x (k . castPtr)

-- | Use an 'MLockedSizedBytes' value as a 'SizedPtr' of the same size. Care
-- should be taken to never copy the contents of the 'MLockedSizedBytes' value
-- into managed memory through the sized pointer, because that would violate
-- the secure-forgetting property of mlocked memory.
mlsbUseAsSizedPtr :: forall n r m. MonadST m => MLockedSizedBytes n -> (SizedPtr n -> m r) -> m r
mlsbUseAsSizedPtr (MLSB x) k =
  withMLockedForeignPtr x (k . SizedPtr . castPtr)

-- | Calls 'finalizeMLockedForeignPtr' on underlying pointer.
-- This function invalidates argument.
mlsbFinalize :: MonadST m => MLockedSizedBytes n -> m ()
mlsbFinalize (MLSB ptr) = finalizeMLockedForeignPtr ptr

-- | 'compareM' on 'MLockedSizedBytes'
mlsbCompare ::
  forall n m. (MonadST m, KnownNat n) => MLockedSizedBytes n -> MLockedSizedBytes n -> m Ordering
mlsbCompare (MLSB x) (MLSB y) =
  withMLockedForeignPtr x $ \x' ->
    withMLockedForeignPtr y $ \y' -> do
      res <- stToIO . unsafeIOToST $ c_sodium_compare x' y' size
      return $ compare res 0
  where
    size = fromInteger $ natVal (Proxy @n)

-- | 'equalsM' on 'MLockedSizedBytes'
mlsbEq ::
  forall n m. (MonadST m, KnownNat n) => MLockedSizedBytes n -> MLockedSizedBytes n -> m Bool
mlsbEq a b = (== EQ) <$> mlsbCompare a b
