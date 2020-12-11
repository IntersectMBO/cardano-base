{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract hashing functionality.
module Cardano.Crypto.Hash.Class
  ( HashAlgorithm (..)
  , sizeHash
  , ByteString
  , Hash(..)

    -- * Core operations
  , hashWith
  , hashWithSerialiser

    -- * Conversions
  , castHash
  , hashToBytes
  , hashFromBytes
  , hashToBytesShort
  , hashFromBytesShort

    -- * Rendering and parsing
  , hashToBytesAsHex
  , hashFromBytesAsHex
  , hashToTextAsHex
  , hashFromTextAsHex
  , hashToStringAsHex
  , hashFromStringAsHex

    -- * Other operations
  , xor

    -- * Deprecated
  , hash
  , fromHash
  , hashRaw
  , getHash
  , getHashBytesAsHex
  )
where

import Control.Monad (join)
import Data.List (foldl')
import Data.Maybe (maybeToList)
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import GHC.TypeLits (Nat, KnownNat, natVal)

import           Data.Word (Word8)
import qualified Data.Bits as Bits
import           Numeric.Natural (Natural)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Short as SBS
import           Data.ByteString.Short (ShortByteString)

import           Data.String (IsString (..))
import qualified Data.Text.Encoding as Text
import qualified Data.Text as Text
import           Data.Text (Text)

import qualified Data.Aeson as Aeson
import           Data.Aeson
                   (FromJSON (..), FromJSONKey (..), ToJSON (..), ToJSONKey (..))
import qualified Data.Aeson.Types as Aeson
import qualified Data.Aeson.Encoding as Aeson

import           Control.DeepSeq (NFData)

import           NoThunks.Class (NoThunks)

import           Cardano.Binary
                   (Encoding, FromCBOR (..), ToCBOR (..), Size, decodeBytes,
                    serializeEncoding')

class (KnownNat (SizeHash h), Typeable h) => HashAlgorithm h where
      --TODO: eliminate this Typeable constraint needed only for the ToCBOR
      -- the ToCBOR should not need it either
  -- size of hash digest
  type SizeHash h :: Nat

  hashAlgorithmName :: proxy h -> String

  digest :: proxy h -> ByteString -> ByteString

-- | The size in bytes of the output of 'digest'
sizeHash :: forall h proxy. HashAlgorithm h => proxy h -> Word
sizeHash _ = fromInteger (natVal (Proxy @(SizeHash h)))

newtype Hash h a = UnsafeHash ShortByteString
  deriving (Eq, Ord, Generic, NFData, NoThunks)


--
-- Core operations
--

-- | Hash the given value, using a serialisation function to turn it into bytes.
--
hashWith :: forall h a. HashAlgorithm h => (a -> ByteString) -> a -> Hash h a
hashWith serialise =
    UnsafeHash
  . SBS.toShort
  . digest (Proxy :: Proxy h)
  . serialise


-- | A variation on 'hashWith', but specially for CBOR encodings.
--
hashWithSerialiser :: forall h a. HashAlgorithm h => (a -> Encoding) -> a -> Hash h a
hashWithSerialiser toEnc = hashWith (serializeEncoding' . toEnc)


--
-- Conversions
--

-- | Cast the type of the hashed data.
--
-- The 'Hash' type has a phantom type parameter to indicate what type the
-- hash is of. It is sometimes necessary to fake this and hash a value of one
-- type and use it where as hash of a different type is expected.
--
castHash :: Hash h a -> Hash h b
castHash (UnsafeHash h) = UnsafeHash h


-- | The representation of the hash as bytes.
--
hashToBytes :: Hash h a -> ByteString
hashToBytes (UnsafeHash h) = SBS.fromShort h


-- | Make a hash from it bytes representation.
--
-- It must be a a bytestring of the correct length, as given by 'sizeHash'.
--
hashFromBytes :: forall h a. HashAlgorithm h => ByteString -> Maybe (Hash h a)
hashFromBytes bytes
  | BS.length bytes == fromIntegral (sizeHash (Proxy :: Proxy h))
  = Just (UnsafeHash (SBS.toShort bytes))

  | otherwise
  = Nothing

-- | Make a hash from it bytes representation, as a 'ShortByteString'.
--
-- It must be a a bytestring of the correct length, as given by 'sizeHash'.
--
hashFromBytesShort :: forall h a. HashAlgorithm h
                   => ShortByteString -> Maybe (Hash h a)
hashFromBytesShort bytes
  | SBS.length bytes == fromIntegral (sizeHash (Proxy :: Proxy h))
  = Just (UnsafeHash bytes)

  | otherwise
  = Nothing


-- | The representation of the hash as bytes, as a 'ShortByteString'.
--
hashToBytesShort :: Hash h a -> ShortByteString
hashToBytesShort (UnsafeHash h) = h


--
-- Rendering and parsing
--

-- | Convert the hash to hex encoding, as 'String'.
hashToStringAsHex :: Hash h a -> String
hashToStringAsHex = Text.unpack . hashToTextAsHex

-- | Make a hash from hex-encoded 'String' representation.
--
-- This can fail for the same reason as 'hashFromBytes', or because the input
-- is invalid hex. The whole byte string must be valid hex, not just a prefix.
--
hashFromStringAsHex :: HashAlgorithm h => String -> Maybe (Hash h a)
hashFromStringAsHex = hashFromTextAsHex . Text.pack

-- | Convert the hash to hex encoding, as 'Text'.
--
hashToTextAsHex :: Hash h a -> Text
hashToTextAsHex = Text.decodeUtf8 . hashToBytesAsHex

-- | Make a hash from hex-encoded 'Text' representation.
--
-- This can fail for the same reason as 'hashFromBytes', or because the input
-- is invalid hex. The whole byte string must be valid hex, not just a prefix.
--
hashFromTextAsHex :: HashAlgorithm h => Text -> Maybe (Hash h a)
hashFromTextAsHex = hashFromBytesAsHex . Text.encodeUtf8

-- | Convert the hash to hex encoding, as 'ByteString'.
--
hashToBytesAsHex :: Hash h a -> ByteString
hashToBytesAsHex = Base16.encode . hashToBytes

-- | Make a hash from hex-encoded 'ByteString' representation.
--
-- This can fail for the same reason as 'hashFromBytes', or because the input
-- is invalid hex. The whole byte string must be valid hex, not just a prefix.
--
hashFromBytesAsHex :: HashAlgorithm h => ByteString -> Maybe (Hash h a)
hashFromBytesAsHex = join . either (const Nothing) (Just . hashFromBytes) . Base16.decode

instance Show (Hash h a) where
  show = show . hashToStringAsHex

instance HashAlgorithm h => Read (Hash h a) where
  readsPrec p str = [ (h, y) | (x, y) <- readsPrec p str, h <- maybeToList (hashFromStringAsHex x) ]

instance HashAlgorithm h => IsString (Hash h a) where
  fromString str =
    case hashFromBytesAsHex (BSC.pack str) of
      Just x  -> x
      Nothing -> error ("fromString: cannot decode hash " ++ show str)

instance ToJSONKey (Hash crypto a) where
  toJSONKey = Aeson.ToJSONKeyText hashToText (Aeson.text . hashToText)

instance HashAlgorithm crypto => FromJSONKey (Hash crypto a) where
  fromJSONKey = Aeson.FromJSONKeyTextParser parseHash

instance ToJSON (Hash crypto a) where
  toJSON = toJSON . hashToText

instance HashAlgorithm crypto => FromJSON (Hash crypto a) where
  parseJSON = Aeson.withText "hash" parseHash

-- utils used in the instances above
hashToText :: Hash crypto a -> Text
hashToText = Text.decodeLatin1 . hashToBytesAsHex

parseHash :: HashAlgorithm crypto => Text -> Aeson.Parser (Hash crypto a)
parseHash t =
    case Base16.decode (Text.encodeUtf8 t) of
      Right bytes -> maybe badSize return (hashFromBytes bytes)
      Left _ -> badHex
  where
    badHex :: Aeson.Parser b
    badHex = fail "Hashes are expected in hex encoding"

    badSize :: Aeson.Parser (Hash crypto a)
    badSize = fail "Hash is the wrong length"

--
-- CBOR serialisation
--

instance (HashAlgorithm h, Typeable a) => ToCBOR (Hash h a) where
  toCBOR (UnsafeHash h) = toCBOR h

  -- | 'Size' expression for @Hash h a@, which is expressed using the 'ToCBOR'
  -- instance for 'ByteString' (as is the above 'toCBOR' method).  'Size'
  -- computation of length of the bytestring is passed as the first argument to
  -- 'encodedSizeExpr'.  The 'ByteString' instance will use it to calculate
  -- @'size' ('Proxy' @('LengthOf' 'ByteString'))@.
  --
  encodedSizeExpr _size proxy =
      encodedSizeExpr (const hashSize) (hashToBytes <$> proxy)
    where
      hashSize :: Size
      hashSize = fromIntegral (sizeHash (Proxy :: Proxy h))

instance (HashAlgorithm h, Typeable a) => FromCBOR (Hash h a) where
  fromCBOR = do
    bs <- decodeBytes
    case hashFromBytes bs of
      Just x  -> return x
      Nothing -> fail $ "hash bytes wrong size, expected " ++ show expected
                     ++ " but got " ++ show actual
        where
          expected = sizeHash (Proxy :: Proxy h)
          actual   = BS.length bs


--
-- Deprecated
--

{-# DEPRECATED hash "Use hashWith or hashWithSerialiser" #-}
hash :: forall h a. (HashAlgorithm h, ToCBOR a) => a -> Hash h a
hash = hashWithSerialiser toCBOR

{-# DEPRECATED fromHash "Use bytesToNatural . hashToBytes" #-}
fromHash :: Hash h a -> Natural
fromHash = foldl' f 0 . BS.unpack . hashToBytes
  where
    f :: Natural -> Word8 -> Natural
    f n b = n * 256 + fromIntegral b

{-# DEPRECATED hashRaw "Use hashWith" #-}
hashRaw :: forall h a. HashAlgorithm h => (a -> ByteString) -> a -> Hash h a
hashRaw = hashWith

{-# DEPRECATED getHash "Use hashToBytes" #-}
getHash :: Hash h a -> ByteString
getHash = hashToBytes

{-# DEPRECATED getHashBytesAsHex "Use hashToBytesAsHex" #-}
getHashBytesAsHex :: Hash h a -> ByteString
getHashBytesAsHex = hashToBytesAsHex

-- | XOR two hashes together
--TODO: fully deprecate this, or rename it and make it efficient.
xor :: Hash h a -> Hash h a -> Hash h a
xor (UnsafeHash x) (UnsafeHash y) =
    UnsafeHash
  . SBS.toShort
  . BS.pack
  $ BS.zipWith Bits.xor (SBS.fromShort x) (SBS.fromShort y)
