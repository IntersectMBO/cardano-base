{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE KindSignatures #-}
module Cardano.Crypto.Libsodium.MLockedBytes.Internal (
    MLockedSizedBytes (..),
    mlsbNew,
    mlsbNewZero,
    mlsbZero,
    mlsbFromByteString,
    mlsbFromByteStringCheck,
    mlsbAsByteString,
    mlsbToByteString,
    mlsbUseAsCPtr,
    mlsbUseAsSizedPtr,
    mlsbCopy,
    mlsbFinalize,
    traceMLSB,
) where

import Control.DeepSeq (NFData (..))
import Data.Proxy (Proxy (..))
import Foreign.C.Types (CSize (..))
import Foreign.ForeignPtr (castForeignPtr)
import Foreign.Ptr (Ptr, castPtr)
import GHC.TypeLits (KnownNat, Nat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafeDupablePerformIO)
import Data.Word (Word8)
import Control.Monad (void)
import Text.Printf

import Cardano.Foreign
import Cardano.Crypto.Libsodium.Memory.Internal
import Cardano.Crypto.Libsodium.C

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import Foreign.Storable (Storable (..))
import Data.Bits (shiftL)

-- | A void type with a type-level size attached to it. We need this in order
-- to express \"pointer to a block of memory of a particular size that can be
-- manipulated through the pointer, but not as a plain Haskell value\" as
-- @Ptr (SizedVoid n)@, or @ForeignPtr (SizedVoid n)@, or
-- @MLockedForeignPtr (SizedVoid n)@.
data SizedVoid (n :: Nat)

-- | Storable instance is necessary for 'allocMLockedForeignPtr'; 'peek' and
-- 'poke' error out, but cannot actually be used due to 'SizedVoid' not having
-- any inhabitants.
instance KnownNat n => Storable (SizedVoid n) where
  sizeOf _ = fromIntegral (natVal (Proxy @n))
  alignment _ = nextPowerOf2 (fromIntegral (natVal (Proxy @n)))
  peek _ = error "Do not peek SizedVoid"
  poke _ _ = error "Do not poke SizedVoid"

nextPowerOf2 :: Int -> Int
nextPowerOf2 i =
  go 1
  where
    go :: Int -> Int
    go c =
      let c' = c `shiftL` 1
      in if c' > i then c else go c'

newtype MLockedSizedBytes (n :: Nat) = MLSB (MLockedForeignPtr (SizedVoid n))
  deriving NoThunks via OnlyCheckWhnfNamed "MLockedSizedBytes" (MLockedSizedBytes n)
  deriving newtype NFData

instance KnownNat n => Eq (MLockedSizedBytes n) where
    x == y = compare x y == EQ

instance KnownNat n => Ord (MLockedSizedBytes n) where
    compare (MLSB x) (MLSB y) = unsafeDupablePerformIO $
        withMLockedForeignPtr x $ \x' ->
        withMLockedForeignPtr y $ \y' -> do
            res <- c_sodium_compare x' y' (CSize (fromIntegral size))
            return (compare res 0)
      where
        size = natVal (Proxy @n)

instance KnownNat n => Show (MLockedSizedBytes n) where
    show mlsb =
      let bytes = BS.unpack $ mlsbAsByteString mlsb
          hexstr = concatMap (printf "%02x") bytes
      in "MLSB " ++ hexstr

traceMLSB :: KnownNat n => MLockedSizedBytes n -> IO ()
traceMLSB = print
{-# DEPRECATED traceMLSB "Don't leave traceMLockedForeignPtr in production" #-}

withMLSB :: forall b n. MLockedSizedBytes n -> (Ptr (SizedVoid n) -> IO b) -> IO b
withMLSB (MLSB fptr) action = withMLockedForeignPtr fptr action

mlsbNew :: forall n. KnownNat n => IO (MLockedSizedBytes n)
mlsbNew = MLSB <$> allocMLockedForeignPtr

mlsbNewZero :: forall n. KnownNat n => IO (MLockedSizedBytes n)
mlsbNewZero = do
  mlsb <- mlsbNew
  mlsbZero mlsb
  return mlsb

mlsbZero :: forall n. KnownNat n => MLockedSizedBytes n -> IO ()
mlsbZero mlsb = do
  withMLSB mlsb $ \ptr -> do
      _ <- c_memset (castPtr ptr) 0 size
      return ()
  where
    size  :: CSize
    size = fromInteger (natVal (Proxy @n))

mlsbCopy :: forall n. KnownNat n => MLockedSizedBytes n -> IO (MLockedSizedBytes n)
mlsbCopy src = mlsbUseAsCPtr src $ \ptrSrc -> do
  dst <- allocMLockedForeignPtr
  withMLockedForeignPtr dst $ \ptrDst -> do
    void $ c_memcpy (castPtr ptrDst) ptrSrc size
  return (MLSB dst)
  where
    size :: CSize
    size = fromInteger (natVal (Proxy @n))

mlsbFromByteString :: forall n. KnownNat n => BS.ByteString -> IO (MLockedSizedBytes n)
mlsbFromByteString bs = BS.useAsCStringLen bs $ \(ptrBS, len) -> do
    fptr <- allocMLockedForeignPtr
    withMLockedForeignPtr fptr $ \ptr -> do
        void $ c_memcpy (castPtr ptr) ptrBS (fromIntegral (min len size))
    return (MLSB fptr)
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

mlsbFromByteStringCheck :: forall n. KnownNat n => BS.ByteString -> IO (Maybe (MLockedSizedBytes n))
mlsbFromByteStringCheck bs
    | BS.length bs /= size = return Nothing
    | otherwise = fmap Just $ BS.useAsCStringLen bs $ \(ptrBS, len) -> do
    fptr <- allocMLockedForeignPtr
    withMLockedForeignPtr fptr $ \ptr -> do
        _ <- c_memcpy (castPtr ptr) ptrBS (fromIntegral (min len size))
        return ()
    return (MLSB fptr)
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

-- | /Note:/ the resulting 'BS.ByteString' will still refer to secure memory,
-- but the types don't prevent it from be exposed. Note further that any
-- subsequent operations (splicing & dicing, copying, conversion,
-- packing/unpacking, etc.) on the resulting 'BS.ByteString' may create copies
-- of the mlocked memory on the unprotected GHC heap, and thus leak secrets,
-- so use this function with extreme care.
mlsbAsByteString :: forall n. KnownNat n => MLockedSizedBytes n -> BS.ByteString
mlsbAsByteString (MLSB (SFP fptr)) = BSI.PS (castForeignPtr fptr) 0 size
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))


-- | /Note:/ this function will leak mlocked memory to the Haskell heap
-- and should not be used in production code.
mlsbToByteString :: forall n. (KnownNat n) => MLockedSizedBytes n -> IO BS.ByteString
mlsbToByteString mlsb =
  withMLSB mlsb $ \ptr ->
    BS.packCStringLen (castPtr ptr, size)
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

mlsbUseAsCPtr :: MLockedSizedBytes n -> (Ptr Word8 -> IO r) -> IO r
mlsbUseAsCPtr (MLSB x) k =
  withMLockedForeignPtr x (k . castPtr)

mlsbUseAsSizedPtr :: forall n r. MLockedSizedBytes n -> (SizedPtr n -> IO r) -> IO r
mlsbUseAsSizedPtr (MLSB x) k =
  withMLockedForeignPtr x (k . SizedPtr . castPtr)

-- | Calls 'finalizeMLockedForeignPtr' on underlying pointer.
-- This function invalidates argument.
--
mlsbFinalize :: MLockedSizedBytes n -> IO ()
mlsbFinalize (MLSB ptr) = finalizeMLockedForeignPtr ptr
