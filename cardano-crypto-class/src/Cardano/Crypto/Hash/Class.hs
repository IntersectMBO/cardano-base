{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables        #-}

-- | Abstract hashing functionality.
module Cardano.Crypto.Hash.Class
  ( HashAlgorithm (..)
  , ByteString
  , Hash(..)
  , hash
  , hashRaw
  , hashPair
  , hashWithSerialiser
  , fromHash
  , hashFromBytes
  , getHashBytesAsHex
  , hashFromBytesAsHex
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

  hashAlgorithmName :: proxy h -> String

  sizeHash :: proxy h -> Word

  byteCount :: proxy h -> Natural
  byteCount = fromIntegral . sizeHash

  digest :: HasCallStack => proxy h -> ByteString -> ByteString

{-# DEPRECATED byteCount "Use sizeHash" #-}

newtype Hash h a = UnsafeHash {getHash :: ByteString}
  deriving (Eq, Ord, Generic, NFData, NoUnexpectedThunks)

instance Show (Hash h a) where
  show = SB8.unpack . getHashBytesAsHex

instance IsString (Hash h a) where
  fromString = UnsafeHash . fst . B16.decode . SB8.pack
  --Ugg this does not check anything

instance (HashAlgorithm h, Typeable a) => ToCBOR (Hash h a) where
  toCBOR = toCBOR . getHash

instance (HashAlgorithm h, Typeable a) => FromCBOR (Hash h a) where
  fromCBOR = do
    bs <- decodeBytes
    let la = SB.length bs
        le :: Int
        le = fromIntegral $ byteCount (Proxy :: Proxy h)
    if la == le
    then return $ UnsafeHash bs
    else fail $ "expected " ++ show le ++ " byte(s), but got " ++ show la

hash :: forall h a. (HashAlgorithm h, ToCBOR a) => a -> Hash h a
hash = hashWithSerialiser toCBOR

hashWithSerialiser :: forall h a. HashAlgorithm h => (a -> Encoding) -> a -> Hash h a
hashWithSerialiser toEnc
  = UnsafeHash . digest (Proxy :: Proxy h) . serializeEncoding' . toEnc

hashRaw :: forall h a. HashAlgorithm h => (a -> ByteString) -> a -> Hash h a
hashRaw serialise = UnsafeHash . digest (Proxy :: Proxy h) . serialise

fromHash :: Hash h a -> Natural
fromHash = foldl' f 0 . SB.unpack . getHash
  where
    f :: Natural -> Word8 -> Natural
    f n b = n * 256 + fromIntegral b
--TODO: make this efficient ^^


-- | Convert the hash to hex encoding, as a ByteString.
--
getHashBytesAsHex :: Hash h a -> ByteString
getHashBytesAsHex = B16.encode . getHash

hashFromBytesAsHex :: HashAlgorithm h => ByteString -> Maybe (Hash h a)
hashFromBytesAsHex hexrep
  | (bytes, trailing) <- B16.decode hexrep
  , SB.null trailing
  = hashFromBytes bytes

  | otherwise
  = Nothing

hashFromBytes :: forall h a. HashAlgorithm h => ByteString -> Maybe (Hash h a)
hashFromBytes bytes
  | SB.length bytes == fromIntegral (byteCount (Proxy :: Proxy h))
  = Just (UnsafeHash bytes)

  | otherwise
  = Nothing

-- | XOR two hashes together
--
--   This functionality is required for VRF calculation.
xor :: Hash h a -> Hash h a -> Hash h a
xor (UnsafeHash x) (UnsafeHash y) = UnsafeHash $ SB.pack $ SB.zipWith Bits.xor x y
--TODO: make this efficient ^^

hashPair :: forall h a b c. HashAlgorithm h => Hash h a -> Hash h b -> Hash h c
hashPair (UnsafeHash a) (UnsafeHash b) = UnsafeHash $ digest (Proxy :: Proxy h) $ a <> b
