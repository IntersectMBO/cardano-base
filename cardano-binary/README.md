# cardano-binary

CBOR serialisation and deserialisation for Cardano data types.

[![Hackage](https://img.shields.io/hackage/v/cardano-binary)](https://hackage.haskell.org/package/cardano-binary)

## Overview

Every piece of data that moves across the Cardano network or is stored
on-chain is encoded as
[CBOR](https://www.rfc-editor.org/rfc/rfc7049) (Concise Binary Object
Representation). `cardano-binary` wraps the `cborg` library with
Cardano-specific types, structured error handling, and the two core typeclasses
— `ToCBOR` and `FromCBOR` — that the rest of the ecosystem implements.

## Developer Onboarding

If you are just starting with `cardano-binary`:
1. **Understand `ToCBOR` and `FromCBOR`**: These are your daily drivers. Learn how to implement them manually (see [Writing a custom `ToCBOR` instance](#writing-a-custom-tocbor-instance)).
2. **Prefer strictness**: Always default to `serialize'` and `decodeFull'` unless you have a specific streaming requirement.
3. **Use Golden Tests**: See the [Testing](#testing) section to ensure your serializations do not break between releases.

## Installation

Add to your `cabal.project`:

```
repository cardano-haskell-packages
  url: https://chap.intersectmbo.org/
  secure: True
```

Add to your `.cabal` file:

```cabal
build-depends: cardano-binary >= 1.9
```

## Core API

### Encoding — `ToCBOR`

```haskell
class ToCBOR a where
  -- | Produce a CBOR Encoding for this value.
  toCBOR :: a -> Encoding

  -- | Optional: estimate the encoded byte size.
  -- Used for buffer pre-allocation.
  encodedSizeExpr
    :: (forall t. ToCBOR t => Proxy t -> Size)
    -> Proxy a
    -> Size
  encodedSizeExpr _ _ = 0  -- default: no estimate
```

### Decoding — `FromCBOR`

```haskell
class FromCBOR a where
  -- | Decode a value from a CBOR stream.
  fromCBOR :: Decoder s a

  -- | Human-readable type label used in error messages.
  label :: Proxy a -> Text
  label _ = "unknown"
```

### Top-level encode / decode functions

| Function | Type | Notes |
|----------|------|-------|
| `serialize'` | `ToCBOR a => a -> ByteString` | Strict output. Prefer this. |
| `serialize` | `ToCBOR a => a -> LByteString` | Lazy output. |
| `decodeFull'` | `FromCBOR a => ByteString -> Either DecoderError a` | Strict input. |
| `decodeFull` | `FromCBOR a => LByteString -> Either DecoderError a` | Lazy input. |
| `decodeFullDecoder'` | `Text -> Decoder s a -> ByteString -> Either DecoderError a` | Custom decoder with label. |

## Usage Examples

### Basic round-trip

```haskell
import Cardano.Binary

-- Encode a value to bytes and decode it back
roundTrip :: (ToCBOR a, FromCBOR a, Show a, Eq a) => a -> IO ()
roundTrip val = do
  let encoded = serialize' val
  case decodeFull' encoded of
    Left  err    -> putStrLn $ "Decode error: " <> show err
    Right result ->
      if result == val
        then putStrLn "Round-trip OK"
        else putStrLn "Round-trip MISMATCH"

-- >>> roundTrip (42 :: Int)
-- Round-trip OK

-- >>> roundTrip ("hello" :: Text)
-- Round-trip OK
```

### Writing a custom `ToCBOR` instance

CBOR has native support for lists, maps, integers, byte strings, and text.
Use `encodeListLen` to open a fixed-length array, then encode each field:

```haskell
import Cardano.Binary
import Data.Text (Text)

data Person = Person
  { personName :: Text
  , personAge  :: Int
  } deriving (Eq, Show)

instance ToCBOR Person where
  toCBOR (Person name age) =
       encodeListLen 2   -- CBOR array of length 2
    <> toCBOR name       -- field 1: Text
    <> toCBOR age        -- field 2: Int

instance FromCBOR Person where
  fromCBOR = do
    decodeListLenOf 2    -- expect array of exactly length 2
    Person
      <$> fromCBOR       -- decode name
      <*> fromCBOR       -- decode age

  label _ = "Person"

-- Test it:
-- serialize' (Person "Alice" 30)
--   => "\130eAlice\x18\x1e"  (CBOR bytes)
```

### Error handling

`DecoderError` carries a structured description of what went wrong:

```haskell
import Cardano.Binary

safeDecode :: ByteString -> IO ()
safeDecode bytes =
  case decodeFull' @Int bytes of
    Left (DecoderErrorDeserialiseFailure lbl failure) ->
      putStrLn $ "Failed to decode " <> show lbl
               <> ": " <> show failure
    Left (DecoderErrorLeftover lbl leftover) ->
      putStrLn $ "Decoded " <> show lbl
               <> " but leftover bytes remain: " <> show leftover
    Left err ->
      putStrLn $ "Decode error: " <> show err
    Right val ->
      print val
```

### Using `Encoding` combinators directly

When you need fine-grained control over the CBOR structure:

```haskell
import Cardano.Binary
import qualified Data.Map.Strict as Map

-- Encode a Map as a CBOR map
encodeMap :: (ToCBOR k, ToCBOR v) => Map.Map k v -> Encoding
encodeMap m =
     encodeMapLen (fromIntegral (Map.size m))
  <> Map.foldlWithKey'
       (\acc k v -> acc <> toCBOR k <> toCBOR v)
       mempty
       m
```

## Integration with `cardano-crypto-class`

Hash values implement `ToCBOR` and `FromCBOR` out of the box:

```haskell
import Cardano.Binary
import Cardano.Crypto.Hash

hashRoundTrip :: Hash Blake2b_256 ByteString -> Either DecoderError (Hash Blake2b_256 ByteString)
hashRoundTrip h = decodeFull' (serialize' h)
```

## Testing

This package provides test helpers in `cardano-binary:testlib`:

```haskell
import Test.Cardano.Binary.Helpers.GoldenRoundTrip

-- Golden test: encode value, compare to stored bytes, decode back
goldenRoundTrip :: (ToCBOR a, FromCBOR a, Eq a) => FilePath -> a -> TestTree
```

Run the test suite:

```bash
cabal test cardano-binary:tests
```

## Notes

- CBOR tags are not used by default; Cardano uses plain arrays and maps.
- The `Size` type in `encodedSizeExpr` is an abstract expression tree used
  for static size analysis of network messages — it is not evaluated at runtime.
- Always use `decodeFull'` (strict) over `decodeFull` (lazy) unless you are
  working with streaming data, to avoid retaining the input `ByteString` in
  memory longer than necessary.
