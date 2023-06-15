{-# LANGUAGE MultiParamTypeClasses #-}

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

import Foreign.Ptr
import Foreign.C.Types

-- | Direct deserialization from raw memory.
--
-- @directDeserialise f@ should allocate a new value of type 'a', and
-- call @f@ with a pointer to the raw memory to be filled. @f@ may be called
-- multiple times, for data structures that store their data in multiple
-- non-contiguous blocks of memory.
--
-- The order in which memory blocks are visited matters.
class DirectDeserialise m a where
  directDeserialise :: (Ptr CChar -> CSize -> m ()) -> m a

-- | Direct serialization to raw memory.
--
-- @directSerialise f x@ should call @f@ to expose the raw memory underyling
-- @x@. For data types that store their data in multiple non-contiguous blocks
-- of memory, @f@ may be called multiple times, once for each block.
--
-- The order in which memory blocks are visited matters.
class DirectSerialise m a where
  directSerialise :: (Ptr CChar -> CSize -> m ()) -> a -> m ()
