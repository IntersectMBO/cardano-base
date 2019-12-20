{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables        #-}

-- | Abstract hashing functionality.
module Cardano.Crypto.Hash.Class
  ( HashAlgorithm (..)
  , ByteString
  , Hash
  , getHash
  , hash
  , hashPair
  , hashWithSerialiser
  , fromHash
  , xor
  )
where

import Cardano.Binary
  ( Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , decodeBytes
  , serializeEncoding'
  )
import Control.DeepSeq (NFData)
import qualified Data.Bits as Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as SB
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as SB8
import Data.List (foldl')
import Data.Proxy (Proxy (..))
import Data.String (IsString (..))
import Data.Typeable (Typeable)
import Data.Word (Word8)
import GHC.Generics (Generic)
import GHC.Stack
import Numeric.Natural

import Cardano.Prelude (NoUnexpectedThunks)

class Typeable h => HashAlgorithm h where

  byteCount :: proxy h -> Natural

  digest :: HasCallStack => proxy h -> ByteString -> ByteString

newtype Hash h a = Hash {getHash :: ByteString}
  deriving (Eq, Ord, Generic, NFData, NoUnexpectedThunks)

instance Show (Hash h a) where
  show = SB8.unpack . B16.encode . getHash

instance IsString (Hash h a) where
  fromString = Hash . fst . B16.decode . SB8.pack

instance (HashAlgorithm h, Typeable a) => ToCBOR (Hash h a) where
  toCBOR = toCBOR . getHash

instance (HashAlgorithm h, Typeable a) => FromCBOR (Hash h a) where
  fromCBOR = do
    bs <- decodeBytes
    let la = SB.length bs
        le :: Int
        le = fromIntegral $ byteCount (Proxy :: Proxy h)
    if la == le
    then return $ Hash bs
    else fail $ "expected " ++ show le ++ " byte(s), but got " ++ show la

hash :: forall h a. (HashAlgorithm h, ToCBOR a) => a -> Hash h a
hash = hashWithSerialiser toCBOR

hashWithSerialiser :: forall h a. HashAlgorithm h => (a -> Encoding) -> a -> Hash h a
hashWithSerialiser toEnc = Hash . digest (Proxy :: Proxy h) . serializeEncoding' . toEnc

fromHash :: Hash h a -> Natural
fromHash = foldl' f 0 . SB.unpack . getHash
  where
    f :: Natural -> Word8 -> Natural
    f n b = n * 256 + fromIntegral b

-- | XOR two hashes together
--
--   This functionality is required for VRF calculation.
xor :: Hash h a -> Hash h a -> Hash h a
xor (Hash x) (Hash y) = Hash $ SB.pack $ SB.zipWith Bits.xor x y

hashPair :: forall h a b c. HashAlgorithm h => Hash h a -> Hash h b -> Hash h c
hashPair (Hash a) (Hash b) = Hash $ digest (Proxy :: Proxy h) $ a <> b
