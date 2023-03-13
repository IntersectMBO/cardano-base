{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
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
    takeMLSBChunk,

    -- * Dangerous Functions
    traceMLSB,
    mlsbFromByteString,
    mlsbFromByteStringCheck,
    -- mlsbAsByteString,
    mlsbToByteString,
) where

import Control.DeepSeq (NFData (..), rwhnf)
import Control.Monad.Class.MonadST
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Foreign.C.Types (CSize (..))
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import GHC.TypeLits (KnownNat, Nat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

import Cardano.Foreign
import Cardano.Crypto.MonadMLock.Class
import Cardano.Crypto.MonadMLock.Alloc
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.MEqOrd

import qualified Data.ByteString as BS
import Data.Bits (Bits, shiftL)

-- | A void type with a type-level size attached to it. We need this in order
-- to express \"pointer to a block of memory of a particular size that can be
-- manipulated through the pointer, but not as a plain Haskell value\" as
-- @Ptr (SizedVoid n)@, or @ForeignPtr (SizedVoid n)@, or
-- @MLockedForeignPtr (SizedVoid n)@.
data SizedVoid (n :: Nat)

-- | A block of raw memory of a known size, protected with @mlock()@.
newtype MLockedSizedBytes m (n :: Nat) = MLSB (MLockedForeignPtr m (SizedVoid n))

deriving via OnlyCheckWhnfNamed "MLockedSizedBytes" (MLockedForeignPtr m (SizedVoid n))
  instance NoThunks (MLockedSizedBytes m n)
  
instance NFData (MLockedSizedBytes m n) where
  rnf = rwhnf

-- | This instance is /unsafe/, it will leak secrets from mlocked memory to the
-- Haskell heap. Do not use outside of testing.
instance KnownNat n => Show (MLockedSizedBytes m n) where
  show mlsb = "MLockedSizedBytes[" ++ show (natVal mlsb) ++ "]"

-- TODO: move this to test suite, with a newtype wrapper
-- show mlsb =
--   let bytes = BS.unpack $ mlsbAsByteString mlsb
--       hexstr = concatMap (printf "%02x") bytes
--   in "MLSB " ++ hexstr

instance (MonadMLock m, MonadST m, KnownNat n) => MEq m (MLockedSizedBytes m n) where
  equalsM = mlsbEq

nextPowerOf2 :: forall n. (Num n, Ord n, Bits n) => n -> n
nextPowerOf2 i =
  go 1
  where
    go :: n -> n
    go c =
      let c' = c `shiftL` 1
      in if c >= i then c else go c'

traceMLSB :: KnownNat n => MLockedSizedBytes m n -> IO ()
traceMLSB = print
{-# DEPRECATED traceMLSB "Don't leave traceMLockedForeignPtr in production" #-}

withMLSB :: forall b n m. (MonadMLock m) => MLockedSizedBytes m n -> (Ptr (SizedVoid n) -> m b) -> m b
withMLSB (MLSB fptr) = withMLockedForeignPtr fptr

takeMLSBChunk :: forall n n' m
               . ( KnownNat n
                 , KnownNat n'
                 , MonadMLock m
                 )
              => MLockedSizedBytes m n
              -> Int
              -> m (MLockedSizedBytes m n')
takeMLSBChunk mlsb offset
  | offset < 0
  = error "Underflow"
  | offset > srcSize - size
  = error "Overflow"
  | otherwise = do
      result <- mlsbNew
      withMLSB mlsb $ \srcPtr -> 
        withMLSB result $ \dstPtr ->
          copyMem dstPtr (plusPtr srcPtr offset) (fromIntegral size)
      return result
  where
    size = fromIntegral (natVal (Proxy @n'))
    srcSize = fromIntegral (natVal (Proxy @n))
                 
mlsbSize :: KnownNat n => MLockedSizedBytes m n -> CSize
mlsbSize mlsb = fromInteger (natVal mlsb)

-- | Allocate a new 'MLockedSizedBytes'. The caller is responsible for
-- deallocating it ('mlsbFinalize') when done with it. The contents of the
-- memory block is undefined.
mlsbNew :: forall n m. (KnownNat n, MonadMLock m) => m (MLockedSizedBytes m n)
mlsbNew =
  MLSB <$> mlockedAllocForeignPtrBytes size align
  where
    size = fromInteger (natVal (Proxy @n))
    align = nextPowerOf2 size

-- | Allocate a new 'MLockedSizedBytes', and pre-fill it with zeroes.
-- The caller is responsible for deallocating it ('mlsbFinalize') when done
-- with it. (See also 'mlsbNew').
mlsbNewZero :: forall n m. (KnownNat n, MonadMLock m) => m (MLockedSizedBytes m n)
mlsbNewZero = do
  mlsb <- mlsbNew
  mlsbZero mlsb
  return mlsb

-- | Overwrite an existing 'MLockedSizedBytes' with zeroes.
mlsbZero :: forall n m. (KnownNat n, MonadMLock m) => MLockedSizedBytes m n -> m ()
mlsbZero mlsb = do
  withMLSB mlsb $ \ptr -> zeroMem ptr (mlsbSize mlsb)

-- | Create a deep mlocked copy of an 'MLockedSizedBytes'.
mlsbCopy :: forall n m. (KnownNat n, MonadMLock m) => MLockedSizedBytes m n -> m (MLockedSizedBytes m n)
mlsbCopy src = mlsbUseAsCPtr src $ \ptrSrc -> do
  dst <- mlsbNew
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
mlsbFromByteString :: forall n m. (KnownNat n, MonadMLock m, MonadST m)
                   => BS.ByteString -> m (MLockedSizedBytes m n)
mlsbFromByteString bs = do
  dst <- mlsbNew
  withMLSB dst $ \ptr -> do
    withLiftST $ \liftST -> liftST . unsafeIOToST $ do
      BS.useAsCStringLen bs $ \(ptrBS, len) -> do
        copyMem (castPtr ptr) ptrBS (min (fromIntegral len) (mlsbSize dst))
  return dst

-- | Allocate a new 'MLockedSizedBytes', and fill it with the contents of a
-- 'ByteString'. The size of the input is checked.
-- /Note:/ since the input 'BS.ByteString' is a plain old Haskell value, it has
-- already violated the secure-forgetting properties afforded by
-- 'MLockedSizedBytes', so this function is useless outside of testing. Use
-- 'mlsbNew' or 'mlsbNewZero' to create 'MLockedSizedBytes' values, and
-- manipulate them through 'withMLSB', 'mlsbUseAsCPtr', or 'mlsbUseAsSizedPtr'.
-- (See also 'mlsbFromByteString')
mlsbFromByteStringCheck :: forall n m. (KnownNat n, MonadMLock m, MonadST m) => BS.ByteString -> m (Maybe (MLockedSizedBytes m n))
mlsbFromByteStringCheck bs
    | BS.length bs /= size = return Nothing
    | otherwise = Just <$> mlsbFromByteString bs
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

-- -- | /Note:/ the resulting 'BS.ByteString' will still refer to secure memory,
-- -- but the types don't prevent it from be exposed. Note further that any
-- -- subsequent operations (splicing & dicing, copying, conversion,
-- -- packing/unpacking, etc.) on the resulting 'BS.ByteString' may create copies
-- -- of the mlocked memory on the unprotected GHC heap, and thus leak secrets,
-- -- so use this function with extreme care.
-- mlsbAsByteString :: forall n. KnownNat n => MLockedSizedBytes m n -> BS.ByteString
-- mlsbAsByteString mlsb@(MLSB (SFP fptr)) = BSI.PS (castForeignPtr fptr) 0 size
--   where
--     size  :: Int
--     size = fromIntegral (mlsbSize mlsb)

-- | /Note:/ this function will leak mlocked memory to the Haskell heap
-- and should not be used in production code.
mlsbToByteString :: forall n m. (KnownNat n, MonadMLock m, MonadST m) => MLockedSizedBytes m n -> m BS.ByteString
mlsbToByteString mlsb =
  withMLSB mlsb $ \ptr ->
    withLiftST $ \liftST -> liftST . unsafeIOToST $ BS.packCStringLen (castPtr ptr, size)
  where
    size  :: Int
    size = fromIntegral (mlsbSize mlsb)

-- | Use an 'MLockedSizedBytes' value as a raw C pointer. Care should be taken
-- to never copy the contents of the 'MLockedSizedBytes' value into managed
-- memory through the raw pointer, because that would violate the
-- secure-forgetting property of mlocked memory.
mlsbUseAsCPtr :: MonadMLock m => MLockedSizedBytes m n -> (Ptr Word8 -> m r) -> m r
mlsbUseAsCPtr (MLSB x) k =
  withMLockedForeignPtr x (k . castPtr)

-- | Use an 'MLockedSizedBytes' value as a 'SizedPtr' of the same size. Care
-- should be taken to never copy the contents of the 'MLockedSizedBytes' value
-- into managed memory through the sized pointer, because that would violate
-- the secure-forgetting property of mlocked memory.
mlsbUseAsSizedPtr :: forall n r m. (MonadMLock m) => MLockedSizedBytes m n -> (SizedPtr n -> m r) -> m r
mlsbUseAsSizedPtr (MLSB x) k =
  withMLockedForeignPtr x (k . SizedPtr . castPtr)

-- | Calls 'finalizeMLockedForeignPtr' on underlying pointer.
-- This function invalidates argument.
--
mlsbFinalize :: MonadMLock m => MLockedSizedBytes m n -> m ()
mlsbFinalize (MLSB ptr) = finalizeMLockedForeignPtr ptr

-- | 'compareM' on 'MLockedSizedBytes'
mlsbCompare :: forall n m. (MonadMLock m, MonadST m, KnownNat n) => MLockedSizedBytes m n -> MLockedSizedBytes m n -> m Ordering
mlsbCompare (MLSB x) (MLSB y) =
  withMLockedForeignPtr x $ \x' ->
    withMLockedForeignPtr y $ \y' -> do
      res <- withLiftST $ \fromST -> fromST . unsafeIOToST $ c_sodium_compare x' y' size
      return $ compare res 0
  where
    size = fromInteger $ natVal (Proxy @n)

-- | 'equalsM' on 'MLockedSizedBytes'
mlsbEq :: forall n m. (MonadMLock m, MonadST m, KnownNat n) => MLockedSizedBytes m n -> MLockedSizedBytes m n -> m Bool
mlsbEq a b = (== EQ) <$> mlsbCompare a b
