{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
module Cardano.Crypto.Libsodium.MLockedBytes.Internal (
    MLockedSizedBytes (..),
    mlsbNew,
    mlsbFromByteString,
    mlsbFromByteStringCheck,
    mlsbToByteString,
    mlsbAsByteString,
    mlsbUseAsCPtr,
    mlsbUseAsSizedPtr,
    mlsbCopy,
    mlsbMemcpy,
    mlsbFinalize,

    mlsbReadFd,
    mlsbReadFromFd,
    mlsbWriteFd,
) where

import Control.DeepSeq (NFData (..))
import Data.Proxy (Proxy (..))
import Foreign.C.Types (CSize (..))
import Foreign.ForeignPtr (castForeignPtr)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import GHC.TypeLits (KnownNat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafeDupablePerformIO)
import Data.Word (Word8)
import Control.Monad (void, when)
import Text.Printf
import System.Posix.Types (Fd (..))

import Cardano.Foreign
import Cardano.Crypto.Libsodium.Memory.Internal
import Cardano.Crypto.Libsodium.C
import Cardano.Crypto.PinnedSizedBytes

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI

newtype MLockedSizedBytes n = MLSB (MLockedForeignPtr (PinnedSizedBytes n))
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
    -- showsPrec d _ = showParen (d > 10)
    --     $ showString "_ :: MLockedSizedBytes "
    --     . showsPrec 11 (natVal (Proxy @n))
    show mlsb =
      let bytes = BS.unpack $ mlsbAsByteString mlsb
          hexstr = concatMap (printf "%02x") bytes
      in "MLSB " ++ hexstr

-- | Note: this doesn't need to allocate mlocked memory,
-- but we do that for consistency
-- mlsbZero :: forall n. KnownNat n => MLockedSizedBytes n
-- mlsbZero = unsafeDupablePerformIO mlsbNew

mlsbNew :: forall n. KnownNat n => IO (MLockedSizedBytes n)
mlsbNew = do
    fptr <- allocMLockedForeignPtr
    withMLockedForeignPtr fptr $ \ptr -> do
        _ <- c_memset (castPtr ptr) 0 size
        return ()
    return (MLSB fptr)
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

mlsbMemcpy :: forall srcSize dstSize.
              ( KnownNat srcSize
              , KnownNat dstSize
              )
           => MLockedSizedBytes dstSize
           -> Word
           -> MLockedSizedBytes srcSize
           -> Word
           -> Word
           -> IO ()
mlsbMemcpy dst dstOffset src srcOffset cpySize = do
  when (dstOffset + cpySize > fromIntegral (natVal (Proxy @dstSize))) (error "mlsbMemcpy: Invalid destination size or offset")
  when (srcOffset + cpySize > fromIntegral (natVal (Proxy @srcSize))) (error "mlsbMemcpy: Invalid source size or offset")
  mlsbUseAsCPtr dst $ \dstPtr ->
    mlsbUseAsCPtr src $ \srcPtr ->
      void $ c_memcpy
        (plusPtr dstPtr $ fromIntegral dstOffset)
        (plusPtr srcPtr $ fromIntegral srcOffset)
        (fromIntegral cpySize)

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
-- but the types don't prevent it from be exposed.
--
mlsbAsByteString :: forall n. KnownNat n => MLockedSizedBytes n -> BS.ByteString
mlsbAsByteString (MLSB (SFP fptr)) =
  BSI.PS (castForeignPtr fptr) 0 size
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

mlsbToByteString :: forall n. KnownNat n => MLockedSizedBytes n -> IO BS.ByteString
mlsbToByteString mlsb =
  mlsbUseAsCPtr mlsb $ \ptr ->
    BS.packCStringLen (castPtr ptr, size)
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

mlsbUseAsCPtr :: MLockedSizedBytes n -> (Ptr Word8 -> IO r) -> IO r
mlsbUseAsCPtr (MLSB x) k = withMLockedForeignPtr x (k . castPtr)

mlsbUseAsSizedPtr :: MLockedSizedBytes n -> (SizedPtr n -> IO r) -> IO r
mlsbUseAsSizedPtr (MLSB x) k = withMLockedForeignPtr x (k . ptrPsbToSizedPtr)

-- | Calls 'finalizeMLockedForeignPtr' on underlying pointer.
-- This function invalidates argument.
--
mlsbFinalize :: MLockedSizedBytes n -> IO ()
mlsbFinalize (MLSB ptr) = finalizeMLockedForeignPtr ptr

-- | Write an 'MLockedSizedBytes' value directly to a file descriptor. This
-- will not allocate any intermediate variables; as long as the file descriptor
-- itself does not write anything to disk or unprotected memory, the mlocked
-- memory is safe.
mlsbWriteFd :: forall n. KnownNat n => Fd -> MLockedSizedBytes n -> IO ()
mlsbWriteFd (Fd fd) mlsb =
  mlsbUseAsCPtr mlsb $ \ptr ->
    go ptr $ fromIntegral (natVal (Proxy @n))
  where
    go ptr size = do
      bytesWritten <- c_mlocked_fd_write fd ptr size
      when (bytesWritten < 0) (error "Failed to write MLSB")
      if fromIntegral bytesWritten == size then
        return ()
      else
        go (plusPtr ptr $ fromIntegral bytesWritten) (size - fromIntegral bytesWritten)

-- | Read an 'MLockedSizedBytes' value directly from a file descriptor. This
-- will not allocate any intermediate variables; as long as the file descriptor
-- itself does not write anything to disk or unprotected memory, the mlocked
-- memory is safe.
-- You have to provide a sufficiently sized 'MLockedSizedBytes' yourself; the
-- size parameter determines the number of bytes read from the descriptor.
mlsbReadFd :: forall n. KnownNat n => Fd -> MLockedSizedBytes n -> IO ()
mlsbReadFd (Fd fd) mlsb =
  mlsbUseAsCPtr mlsb $ \ptr ->
    go ptr $ fromIntegral (natVal (Proxy @n))
  where
    go ptr size = do
      bytesRead <- c_mlocked_fd_read fd ptr size
      when (bytesRead < 0) (error "Failed to write MLSB")
      if fromIntegral bytesRead == size then
        return ()
      else
        go (plusPtr ptr $ fromIntegral bytesRead) (size - fromIntegral bytesRead)

-- | Read an 'MLockedSizedBytes' value directly from a file descriptor. This
-- will not allocate any intermediate variables; as long as the file descriptor
-- itself does not write anything to disk or unprotected memory, the mlocked
-- memory is safe.
-- A sufficiently sized 'MLockedSizedBytes' will be created for you; the
-- size parameter determines the number of bytes read from the descriptor. The
-- caller is responsible for calling 'mlsbFinalize' on the resulting value
-- when it is no longer used.
mlsbReadFromFd :: forall n. KnownNat n => Fd -> IO (MLockedSizedBytes n)
mlsbReadFromFd fd = do
  mlsb <- mlsbNew
  mlsbReadFd fd mlsb
  return mlsb
