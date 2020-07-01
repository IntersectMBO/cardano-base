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
  , byteCount
  , ByteString
  , Hash(..)
  , castHash
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
  , Size
  , decodeBytes
  , serializeEncoding'
  )
import Control.DeepSeq (NFData)
import Data.Aeson (FromJSON (..), FromJSONKey (..), ToJSON (..), ToJSONKey (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import qualified Data.Aeson.Encoding as Aeson
import qualified Data.Bits as Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as SB
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as SB8
import Data.List (foldl')
import Data.Proxy (Proxy (..))
import Data.String (IsString (..))
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Typeable (Typeable)
import Data.Word (Word8)
import GHC.Generics (Generic)
import GHC.Stack
import GHC.TypeLits (Nat, KnownNat, natVal)
import Numeric.Natural

import Cardano.Prelude (Base16ParseError, NoUnexpectedThunks, parseBase16)

class (Typeable h, KnownNat (SizeHash h)) => HashAlgorithm h where
  -- size of hash digest
  type SizeHash h :: Nat

  hashAlgorithmName :: proxy h -> String

  digest :: HasCallStack => proxy h -> ByteString -> ByteString


byteCount :: HashAlgorithm h => proxy h -> Natural
byteCount = fromIntegral . sizeHash
{-# DEPRECATED byteCount "Use sizeHash" #-}

-- | The size in bytes of the output of 'digest'
sizeHash :: forall h proxy. HashAlgorithm h => proxy h -> Word
sizeHash _ = fromInteger (natVal (Proxy @(SizeHash h)))

newtype Hash h a = UnsafeHash {getHash :: ByteString}
  deriving (Eq, Ord, Generic, NFData, NoUnexpectedThunks)

instance Show (Hash h a) where
  show = SB8.unpack . getHashBytesAsHex

instance IsString (Hash h a) where
  fromString = UnsafeHash . fst . B16.decode . SB8.pack
  --Ugg this does not check anything

instance (HashAlgorithm h, Typeable a) => ToCBOR (Hash h a) where
  toCBOR = toCBOR . getHash

  -- | 'Size' expression for @Hash h a@, which is expressed using the 'ToCBOR'
  -- instance for 'ByteString' (as is the above 'toCBOR' method).  'Size'
  -- computation of length of the bytestring is passed as the first argument to
  -- 'encodedSizeExpr'.  The 'ByteString' instance will use it to calculate
  -- @'size' ('Proxy' @('LengthOf' 'ByteString'))@.
  --
  encodedSizeExpr _size proxy =
      encodedSizeExpr (\_ -> hashSize) (getHash <$> proxy)
    where
      hashSize :: Size
      hashSize = fromIntegral (sizeHash (Proxy :: Proxy h))

instance (HashAlgorithm h, Typeable a) => FromCBOR (Hash h a) where
  fromCBOR = do
    bs <- decodeBytes
    let la = SB.length bs
        le :: Int
        le = fromIntegral $ sizeHash (Proxy :: Proxy h)
    if la == le
    then return $ UnsafeHash bs
    else fail $ "expected " ++ show le ++ " byte(s), but got " ++ show la

instance ToJSONKey (Hash crypto a) where
  toJSONKey = Aeson.ToJSONKeyText hashToText (Aeson.text . hashToText)

instance HashAlgorithm crypto => FromJSONKey (Hash crypto a) where
  fromJSONKey = Aeson.FromJSONKeyTextParser parseHash

instance ToJSON (Hash crypto a) where
  toJSON = toJSON . hashToText

instance HashAlgorithm crypto => FromJSON (Hash crypto a) where
  parseJSON = Aeson.withText "hash" parseHash

hashToText :: Hash crypto a -> Text
hashToText = Text.decodeLatin1 . getHashBytesAsHex

parseHash :: HashAlgorithm crypto => Text -> Aeson.Parser (Hash crypto a)
parseHash t = do
    bytes <- either badHex return (parseBase16 t)
    maybe badSize return (hashFromBytes bytes)
  where
    badHex :: Base16ParseError -> Aeson.Parser ByteString
    badHex _ = fail "Hashes are expected in hex encoding"

    badSize :: Aeson.Parser (Hash crypto a)
    badSize  = fail "Hash is the wrong length"

castHash :: Hash h a -> Hash h b
castHash (UnsafeHash h) = UnsafeHash h

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
  | SB.length bytes == fromIntegral (sizeHash (Proxy :: Proxy h))
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
