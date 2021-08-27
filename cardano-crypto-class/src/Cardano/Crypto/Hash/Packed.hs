{-# LANGUAGE DeriveGeneric #-}
module Cardano.Crypto.Hash.Packed where

import qualified Data.Primitive.ByteArray as BA
import qualified Data.ByteString.Short as SBS
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short.Internal as SBSI
import           NoThunks.Class (NoThunks)
import           GHC.Generics (Generic)
import           Data.Word (Word64, Word8)
import qualified Control.Monad.ST as ST
import           Control.DeepSeq (NFData)

data Bytes32 = Bytes32
    {-# UNPACK #-} !Word8 -- length
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
  deriving (Eq, Generic)


instance Ord Bytes32 where
  -- Note: the derived ord instance would produce different orderings
  -- on machines with different byte orders.
  compare x y = compare (unpack x) (unpack y)

instance NoThunks Bytes32
instance NFData Bytes32


unpack :: Bytes32 -> ShortByteString
unpack (Bytes32 len x0 x1 x2 x3) = baToSBS $ ST.runST $ do
  tmp <- BA.newByteArray 32
  BA.writeByteArray tmp 0 x0
  BA.writeByteArray tmp 1 x1
  BA.writeByteArray tmp 2 x2
  BA.writeByteArray tmp 3 x3
  frozen <- BA.unsafeFreezeByteArray tmp
  -- fromIntegral does not overflow because Int is wider than Word8
  pure $ BA.cloneByteArray frozen 0 (fromIntegral len)

unsafePack :: ShortByteString -> Bytes32
unsafePack sbs = if len > 32 then err else ST.runST $ do
  tmp <- BA.newByteArray 32
  BA.copyByteArray tmp 0 ba 0 len
  BA.fillByteArray tmp len (32 - len) 0
  -- fromIntegral does not overflow because length is nonnegative and
  -- len > 32 raises an error
  Bytes32 (fromIntegral len)
    <$> BA.readByteArray tmp 0
    <*> BA.readByteArray tmp 1
    <*> BA.readByteArray tmp 2
    <*> BA.readByteArray tmp 3
  where
  len = SBS.length sbs
  ba = baFromSBS sbs
  err = error $ "Attempted to convert bytestring of length "
     <> show len
     <> " into Bytes32, but max length is 32."

baToSBS :: BA.ByteArray -> ShortByteString
baToSBS (BA.ByteArray bytes) = SBSI.SBS bytes

baFromSBS :: ShortByteString -> BA.ByteArray
baFromSBS (SBSI.SBS bytes) = BA.ByteArray bytes
