# Cardano-binary

**CBOR serialization and deserialization for Cardano blockchain data structures**

This package provides the core serialization infrastructure used throughout the Cardano ecosystem. It's built on top of the [cborg](https://hackage.haskell.org/package/cborg) library and provides Cardano-specific abstractions for binary data handling.

## Quick Start

### Basic Serialization

```haskell
{-# LANGUAGE DeriveGeneric #-}
import Cardano.Binary
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import Data.Word (Word32)
import GHC.Generics (Generic)

-- Define a simple data type
data Person = Person
  { name :: Text
  , age  :: Word32
  } deriving (Generic, Show)

-- Implement serialization instances
instance ToCBOR Person where
  toCBOR (Person n a) =
    encodeListLen 2 <> toCBOR n <> toCBOR a

instance FromCBOR Person where
  fromCBOR = do
    enforceSize "Person" 2
    Person <$> fromCBOR <*> fromCBOR

-- Usage example
example :: IO ()
example = do
  let person = Person "Alice" 30
  let encoded = serialize person
  let decoded = deserialize encoded

  putStrLn $ "Encoded size: " ++ show (LBS.length encoded) ++ " bytes"
  case decoded of
    Right p -> putStrLn $ "Decoded: " ++ show p
    Left err -> putStrLn $ "Error: " ++ show err
```

### Working with Cardano Types

```haskell
import Cardano.Binary
import Cardano.Crypto.Hash (Hash, Blake2b_256)
import qualified Data.ByteString as BS

-- Serialize a hash
hashExample :: Hash Blake2b_256 BS.ByteString -> LBS.ByteString
hashExample h = serialize h

-- Deserialize with error handling
parseHash :: LBS.ByteString -> Either DecoderError (Hash Blake2b_256 BS.ByteString)
parseHash = deserialize
```

## 📚 Core Concepts

### ToCBOR Class - Serialization

The `ToCBOR` type class defines how to encode Haskell values to CBOR:

```haskell
class Typeable a => ToCBOR a where
  toCBOR :: a -> Encoding
  encodedSizeExpr :: (forall t. ToCBOR t => Proxy t -> Size) -> Proxy a -> Size
```

**Key functions:**
- `toCBOR` - Convert value to CBOR encoding
- `encodedSizeExpr` - Static size bounds computation
- `serialize` - High-level serialization to ByteString

### FromCBOR Class - Deserialization

The `FromCBOR` type class defines how to decode CBOR back to Haskell values:

```haskell
class Typeable a => FromCBOR a where
  fromCBOR :: Decoder s a
  label :: Proxy a -> Text  -- For error messages
```

**Key functions:**
- `fromCBOR` - CBOR decoder for the type
- `deserialize` - High-level deserialization from ByteString
- `label` - Human-readable type name for errors

### Error Handling

Comprehensive error types for robust deserialization:

```haskell
data DecoderError
  = DecoderErrorSizeMismatch Text Int Int    -- Expected vs actual size
  | DecoderErrorCustom Text Text            -- Custom validation errors
  | DecoderErrorUnknownTag Text Word8       -- Unknown CBOR tags
  | DecoderErrorLeftover Text BS.ByteString -- Unexpected remaining data
  -- ... and more
```

## 🔧 Common Patterns

### 1. Simple Product Types

```haskell
data Point = Point Int Int deriving (Generic, Show)

instance ToCBOR Point where
  toCBOR (Point x y) =
    encodeListLen 2 <> toCBOR x <> toCBOR y

instance FromCBOR Point where
  fromCBOR = do
    enforceSize "Point" 2
    Point <$> fromCBOR <*> fromCBOR
```

### 2. Sum Types with Tags

```haskell
data Shape = Circle Double | Rectangle Double Double
  deriving (Show)

instance ToCBOR Shape where
  toCBOR (Circle r) =
    encodeListLen 2 <> toCBOR (0 :: Word8) <> toCBOR r
  toCBOR (Rectangle w h) =
    encodeListLen 3 <> toCBOR (1 :: Word8) <> toCBOR w <> toCBOR h

instance FromCBOR Shape where
  fromCBOR = do
    len <- decodeListLen
    tag <- fromCBOR :: Decoder s Word8
    case (len, tag) of
      (2, 0) -> Circle <$> fromCBOR
      (3, 1) -> Rectangle <$> fromCBOR <*> fromCBOR
      _ -> fail $ "Invalid Shape tag: " ++ show tag
```

### 3. Optional Fields

```haskell
data User = User
  { userId :: Word32
  , userName :: Text
  , userEmail :: Maybe Text
  } deriving (Show)

instance ToCBOR User where
  toCBOR (User uid name email) =
    encodeListLen 3 <>
    toCBOR uid <>
    toCBOR name <>
    encodeMaybe toCBOR email  -- Built-in Maybe encoding

instance FromCBOR User where
  fromCBOR = do
    enforceSize "User" 3
    User <$> fromCBOR <*> fromCBOR <*> fromCBORMaybe
```

## 🧪 Testing Your Instances

Always test your ToCBOR/FromCBOR instances for correctness:

```haskell
-- Round-trip property
prop_roundTrip :: (ToCBOR a, FromCBOR a, Eq a) => a -> Bool
prop_roundTrip x =
  case deserialize (serialize x) of
    Right y -> x == y
    Left _ -> False
```

## 🔍 Key Modules

- **`Cardano.Binary`** - Main module, re-exports everything
- **`Cardano.Binary.ToCBOR`** - Serialization type class and utilities
- **`Cardano.Binary.FromCBOR`** - Deserialization type class and error types
- **`Cardano.Binary.Serialize`** - High-level serialize/deserialize functions

## ⚠️ Performance Notes

1. **Lazy vs Strict ByteStrings**: Use lazy ByteStrings for large data
2. **Size Pre-computation**: Implement `encodedSizeExpr` for better performance
3. **Memory**: CBOR encoding can be more compact than JSON but uses more CPU

## 🔗 Integration with Other Packages

### With cardano-crypto-class

```haskell
import Cardano.Crypto.Hash
import Cardano.Binary

-- Hashes have built-in ToCBOR/FromCBOR instances
hashRoundTrip :: Hash Blake2b_256 ByteString -> Bool
hashRoundTrip h =
  case deserialize (serialize h) of
    Right h' -> h == h'
    Left _ -> False
```

## 📋 Best Practices

1. **Always implement both ToCBOR and FromCBOR** for your types
2. **Use `enforceSize` for fixed-length encodings** to catch errors early
3. **Test round-trip properties** for all instances
4. **Consider versioning** for evolving data formats
5. **Use tagged unions** for sum types to enable future extensions

## 🚨 Common Pitfalls

1. **Forgetting to enforce size** in decoders - can lead to confusing errors
2. **Inconsistent encoding order** between ToCBOR and FromCBOR
3. **Not handling version evolution** - consider backwards compatibility
4. **Poor error messages** - always provide descriptive labels

## 📜 Further Reading

- [API Documentation](http://base.cardano.intersectmbo.org/cardano-binary/)
- [CBOR RFC](https://tools.ietf.org/html/rfc7049) - CBOR specification
- [cborg package](https://hackage.haskell.org/package/cborg) - Underlying CBOR library

---

> **📝 Note**: Examples above are designed to be educational. Always test serialization instances thoroughly with your specific data types.
