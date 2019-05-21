{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE NumDecimals       #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module Test.Cardano.Binary.Serialization
  (tests)
  where

import Cardano.Binary hiding (Range)
import Codec.CBOR.Encoding as E
import Codec.CBOR.Decoding as D

import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as BS.Lazy

import Cardano.Prelude

import Hedgehog 
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

tests :: IO Bool
tests = checkParallel $$(discover)

data TestStruct = TestStruct
  { tsUnit                  ::  ()
  , tsBool                  :: !Bool
  , tsInteger               :: !Integer
  , tsWord                  :: !Word
  , tsWord8                 :: !Word8
  , tsWord16                :: !Word16
  , tsWord32                :: !Word32
  , tsWord64                :: !Word64
  , tsInt                   :: !Int
  , tsFloat                 :: !Float
  , tsInt32                 :: !Int32
  , tsInt64                 :: !Int64
  , tsTupleBoolBool         :: !(Bool, Bool)
  , tsTupleBoolBoolBool     :: !(Bool, Bool, Bool)
  , tsTupleBoolBoolBoolBool :: !(Bool, Bool, Bool, Bool)
  , tsByteString            :: !ByteString
  , tsText                  :: !Text
  , tsListBool              :: ![Bool]
  , tsEitherBoolBool        :: !(Either Bool Bool)
  , tsNonEmptyBool          :: !(NonEmpty Bool)
  , tsMaybeBool             :: !(Maybe Bool)
  , tsMapBoolBool           :: !(Map Bool Bool)
  , tsMapSetBool            :: !(Set Bool)
  , tsRaw                   :: !Raw
  , tsVectorBool            :: !(V.Vector Bool)
  , tsLByteString           :: BS.Lazy.ByteString
  }
  deriving (Show, Eq)

genTestStruct :: Gen TestStruct
genTestStruct = TestStruct 
    <$> pure ()
    <*> Gen.bool
    <*> Gen.integral (Range.linearFrom 0 (-1e40) 1e40 :: Range Integer)
    <*> Gen.word Range.constantBounded
    <*> Gen.word8 Range.constantBounded
    <*> Gen.word16 Range.constantBounded
    <*> Gen.word32 Range.constantBounded
    <*> Gen.word64 Range.constantBounded
    <*> Gen.int Range.constantBounded
    <*> Gen.float (Range.constant (-1e12) 1e12)
    <*> Gen.int32 Range.constantBounded
    <*> Gen.int64 Range.constantBounded
    <*> ((,) <$> Gen.bool <*> Gen.bool)
    <*> ((,,) <$> Gen.bool <*> Gen.bool <*> Gen.bool)
    <*> ((,,,) <$> Gen.bool <*> Gen.bool <*> Gen.bool <*> Gen.bool)
    <*> Gen.bytes (Range.linear 0 20)
    <*> Gen.text (Range.linear 0 20) Gen.unicode
    <*> Gen.list (Range.constant 0 10) Gen.bool
    <*> Gen.choice [Right <$> Gen.bool, Left <$> Gen.bool]
    <*> Gen.nonEmpty (Range.linear 1 20) Gen.bool
    <*> Gen.maybe Gen.bool
    <*> Gen.map (Range.constant 0 2) ((,) <$> Gen.bool <*> Gen.bool)
    <*> Gen.set (Range.constant 0 2) Gen.bool
    <*> (Raw <$> ( Gen.bytes (Range.linear 0 20)))
    <*> (V.fromList <$> ( Gen.list (Range.constant 0 10) Gen.bool))
    <*> (BS.Lazy.fromStrict <$> Gen.bytes (Range.linear 0 20))

instance ToCBOR TestStruct where
  toCBOR ts = E.encodeListLen 1 
    <> toCBOR ( tsUnit                  ts) 
    <> toCBOR ( tsBool                  ts) 
    <> toCBOR ( tsInteger               ts) 
    <> toCBOR ( tsWord                  ts) 
    <> toCBOR ( tsWord8                 ts) 
    <> toCBOR ( tsWord16                ts) 
    <> toCBOR ( tsWord32                ts) 
    <> toCBOR ( tsWord64                ts) 
    <> toCBOR ( tsInt                   ts) 
    <> toCBOR ( tsFloat                 ts) 
    <> toCBOR ( tsInt32                 ts) 
    <> toCBOR ( tsInt64                 ts) 
    <> toCBOR ( tsTupleBoolBool         ts) 
    <> toCBOR ( tsTupleBoolBoolBool     ts) 
    <> toCBOR ( tsTupleBoolBoolBoolBool ts) 
    <> toCBOR ( tsByteString            ts) 
    <> toCBOR ( tsText                  ts) 
    <> toCBOR ( tsListBool              ts) 
    <> toCBOR ( tsEitherBoolBool        ts) 
    <> toCBOR ( tsNonEmptyBool          ts) 
    <> toCBOR ( tsMaybeBool             ts) 
    <> toCBOR ( tsMapBoolBool           ts) 
    <> toCBOR ( tsMapSetBool            ts) 
    <> toCBOR ( tsRaw                   ts)
    <> toCBOR ( tsVectorBool            ts)
    <> toCBOR ( tsLByteString           ts)

instance FromCBOR TestStruct where
  fromCBOR = do
    D.decodeListLenOf 1 
    TestStruct 
      <$> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR
      <*> fromCBOR

prop_roundTripSerialize' :: Property
prop_roundTripSerialize' = property $ do
  ts <- forAll genTestStruct
  (unsafeDeserialize' . serialize' $ ts) === ts

prop_roundTripCrcProtected :: Property
prop_roundTripCrcProtected = property $ do
  ts <- forAll genTestStruct
  let crcEncodedBS = serializeEncoding . encodeCrcProtected $ ts
  decodeFullDecoder "" decodeCrcProtected crcEncodedBS === Right ts

prop_roundTripKnownCBORData :: Property
prop_roundTripKnownCBORData = property $ do
  ts <- forAll genTestStruct
  let encoded = serializeEncoding . encodeKnownCborDataItem $ ts
  decodeFullDecoder "" decodeKnownCborDataItem encoded === Right ts
