{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Direct (de-)serialisation to / from raw memory.
--
-- The purpose of the typeclasses in this module is to abstract over data
-- structures that can expose the data they store as one or more raw 'Ptr's,
-- without any additional memory copying or conversion to intermediate data
-- structures.
--
-- This is useful for transmitting data like KES SignKeys over a socket
-- connection: by accessing the memory directly and copying it into or out of
-- a file descriptor, without going through an intermediate @ByteString@
-- representation (or other data structure that resides in the GHC heap), we
-- can more easily assure that the data is never written to disk, including
-- swap, which is an important requirement for KES.
module Cardano.Crypto.DirectSerialise
where

import Cardano.Crypto.Libsodium.Memory (copyMem)
import Control.Exception
import Control.Monad (when)
import Control.Monad.Class.MonadST (MonadST, stToIO)
import Control.Monad.Class.MonadThrow (MonadThrow)
import Data.STRef (newSTRef, readSTRef, writeSTRef)
import Foreign.C.Types
import Foreign.Ptr

data SizeCheckException = SizeCheckException
  { expectedSize :: Int
  , actualSize :: Int
  }
  deriving (Show)

instance Exception SizeCheckException

sizeCheckFailed :: Int -> Int -> m ()
sizeCheckFailed ex ac =
  throw $ SizeCheckException ex ac

-- | Direct deserialization from raw memory.
--
-- @directDeserialise f@ should allocate a new value of type 'a', and
-- call @f@ with a pointer to the raw memory to be filled. @f@ may be called
-- multiple times, for data structures that store their data in multiple
-- non-contiguous blocks of memory.
--
-- The order in which memory blocks are visited matters.
class DirectDeserialise a where
  directDeserialise :: (MonadST m, MonadThrow m) => (Ptr CChar -> CSize -> m ()) -> m a

-- | Direct serialization to raw memory.
--
-- @directSerialise f x@ should call @f@ to expose the raw memory underyling
-- @x@. For data types that store their data in multiple non-contiguous blocks
-- of memory, @f@ may be called multiple times, once for each block.
--
-- The order in which memory blocks are visited matters.
class DirectSerialise a where
  directSerialise :: (MonadST m, MonadThrow m) => (Ptr CChar -> CSize -> m ()) -> a -> m ()

-- | Helper function for bounds-checked serialization.
-- Verifies that no more than the maximum number of bytes are written, and
-- returns the actual number of bytes written.
directSerialiseTo ::
  forall m a.
  DirectSerialise a =>
  MonadST m =>
  MonadThrow m =>
  (Int -> Ptr CChar -> CSize -> m ()) ->
  Int ->
  a ->
  m Int
directSerialiseTo writeBytes dstsize val = do
  posRef <- stToIO $ newSTRef 0
  let pusher :: Ptr CChar -> CSize -> m ()
      pusher src srcsize = do
        pos <- stToIO $ readSTRef posRef
        let pos' = pos + fromIntegral @CSize @Int srcsize
        when (pos' > dstsize) $
          sizeCheckFailed (dstsize - pos) (pos' - pos)
        writeBytes pos src srcsize
        stToIO $ writeSTRef posRef pos'
  directSerialise pusher val
  stToIO $ readSTRef posRef

-- | Helper function for size-checked serialization.
-- Verifies that exactly the specified number of bytes are written.
directSerialiseToChecked ::
  forall m a.
  DirectSerialise a =>
  MonadST m =>
  MonadThrow m =>
  (Int -> Ptr CChar -> CSize -> m ()) ->
  Int ->
  a ->
  m ()
directSerialiseToChecked writeBytes dstsize val = do
  bytesWritten <- directSerialiseTo writeBytes dstsize val
  when (bytesWritten /= dstsize) $
    sizeCheckFailed dstsize bytesWritten

-- | Helper function for the common use case of serializing to an in-memory
-- buffer.
-- Verifies that no more than the maximum number of bytes are written, and
-- returns the actual number of bytes written.
directSerialiseBuf ::
  forall m a.
  DirectSerialise a =>
  MonadST m =>
  MonadThrow m =>
  Ptr CChar ->
  Int ->
  a ->
  m Int
directSerialiseBuf dst =
  directSerialiseTo (copyMem . plusPtr dst)

-- | Helper function for size-checked serialization to an in-memory buffer.
-- Verifies that exactly the specified number of bytes are written.
directSerialiseBufChecked ::
  forall m a.
  DirectSerialise a =>
  MonadST m =>
  MonadThrow m =>
  Ptr CChar ->
  Int ->
  a ->
  m ()
directSerialiseBufChecked buf dstsize val = do
  bytesWritten <- directSerialiseBuf buf dstsize val
  when (bytesWritten /= dstsize) $
    sizeCheckFailed dstsize bytesWritten

-- | Helper function for size-checked deserialization.
-- Verifies that no more than the maximum number of bytes are read, and returns
-- the actual number of bytes read.
directDeserialiseFrom ::
  forall m a.
  DirectDeserialise a =>
  MonadST m =>
  MonadThrow m =>
  (Int -> Ptr CChar -> CSize -> m ()) ->
  Int ->
  m (a, Int)
directDeserialiseFrom readBytes srcsize = do
  posRef <- stToIO $ newSTRef 0
  let puller :: Ptr CChar -> CSize -> m ()
      puller dst dstsize = do
        pos <- stToIO $ readSTRef posRef
        let pos' = pos + fromIntegral @CSize @Int dstsize
        when (pos' > srcsize) $
          sizeCheckFailed (srcsize - pos) (pos' - pos)
        readBytes pos dst dstsize
        stToIO $ writeSTRef posRef pos'
  (,) <$> directDeserialise puller <*> stToIO (readSTRef posRef)

-- | Helper function for size-checked deserialization.
-- Verifies that exactly the specified number of bytes are read.
directDeserialiseFromChecked ::
  forall m a.
  DirectDeserialise a =>
  MonadST m =>
  MonadThrow m =>
  (Int -> Ptr CChar -> CSize -> m ()) ->
  Int ->
  m a
directDeserialiseFromChecked readBytes srcsize = do
  (r, bytesRead) <- directDeserialiseFrom readBytes srcsize
  when (bytesRead /= srcsize) $
    sizeCheckFailed srcsize bytesRead
  return r

-- | Helper function for the common use case of deserializing from an in-memory
-- buffer.
-- Verifies that no more than the maximum number of bytes are read, and returns
-- the actual number of bytes read.
directDeserialiseBuf ::
  forall m a.
  DirectDeserialise a =>
  MonadST m =>
  MonadThrow m =>
  Ptr CChar ->
  Int ->
  m (a, Int)
directDeserialiseBuf src =
  directDeserialiseFrom (\pos dst -> copyMem dst (plusPtr src pos))

-- | Helper function for size-checked deserialization from an in-memory buffer.
-- Verifies that exactly the specified number of bytes are read.
directDeserialiseBufChecked ::
  forall m a.
  DirectDeserialise a =>
  MonadST m =>
  MonadThrow m =>
  Ptr CChar ->
  Int ->
  m a
directDeserialiseBufChecked buf srcsize = do
  (r, bytesRead) <- directDeserialiseBuf buf srcsize
  when (bytesRead /= srcsize) $
    sizeCheckFailed srcsize bytesRead
  return r
