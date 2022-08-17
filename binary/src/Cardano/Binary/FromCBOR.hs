{-# LANGUAGE BangPatterns              #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE NumDecimals               #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}

module Cardano.Binary.FromCBOR
  ( FromCBOR(..)
  , DecoderError(..)
  , enforceSize
  , matchSize
  , module D
  , fromCBORMaybe
  , decodeListWith
    -- * Helper tools to build instances
  , decodeMapSkel
  , cborError
  , toCborError
  )
where

import Prelude hiding ((.))

import Codec.CBOR.Decoding as D
import Codec.CBOR.ByteArray as BA ( ByteArray(BA) )
import Control.Category (Category((.)))
import Control.Exception (Exception)
import Control.Monad (when)
import qualified Codec.CBOR.Read as CBOR.Read
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Short as SBS
import qualified Data.ByteString.Short.Internal as SBS
import Data.Fixed (Fixed(..), Nano, Pico)
import Data.Int (Int32, Int64)
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import qualified Data.Map as M
import qualified Data.Primitive.ByteArray as Prim
import Data.Ratio ( Ratio, (%) )
import qualified Data.Set as S
import Data.Tagged (Tagged(..))
import Data.Text (Text)
import qualified Data.Text  as T
import Data.Time.Calendar.OrdinalDate ( fromOrdinalDate )
import Data.Time.Clock (NominalDiffTime, UTCTime(..), picosecondsToDiffTime)
import Data.Typeable ( Typeable, typeRep, Proxy )
import qualified Data.Vector as Vector
import qualified Data.Vector.Generic as Vector.Generic
import Data.Void (Void)
import Data.Word ( Word8, Word16, Word32, Word64 )
import Formatting
    ( bprint, int, shown, stext, build, formatToString )
import qualified Formatting.Buildable as B (Buildable(..))
import Numeric.Natural (Natural)


{- HLINT ignore "Reduce duplication" -}
{- HLINT ignore "Redundant <$>" -}

--------------------------------------------------------------------------------
-- FromCBOR
--------------------------------------------------------------------------------

class Typeable a => FromCBOR a where
  fromCBOR :: D.Decoder s a

  label :: Proxy a -> Text
  label = T.pack . show . typeRep


--------------------------------------------------------------------------------
-- DecoderError
--------------------------------------------------------------------------------

data DecoderError
  = DecoderErrorCanonicityViolation Text
  | DecoderErrorCustom Text Text
  -- ^ Custom decoding error, usually due to some validation failure
  | DecoderErrorDeserialiseFailure Text CBOR.Read.DeserialiseFailure
  | DecoderErrorEmptyList Text
  | DecoderErrorLeftover Text BS.ByteString
  | DecoderErrorSizeMismatch Text Int Int
  -- ^ A size mismatch @DecoderErrorSizeMismatch label expectedSize actualSize@
  | DecoderErrorUnknownTag Text Word8
  | DecoderErrorVoid
  deriving (Eq, Show)

instance Exception DecoderError

instance B.Buildable DecoderError where
  build = \case
    DecoderErrorCanonicityViolation lbl ->
      bprint ("Canonicity violation while decoding " . stext) lbl

    DecoderErrorCustom lbl err -> bprint
      ("An error occured while decoding " . stext . ".\n"
      . "Error: " . stext)
      lbl
      err

    DecoderErrorDeserialiseFailure lbl failure -> bprint
      ( "Deserialisation failure while decoding " . stext . ".\n"
      . "CBOR failed with error: " . shown
      )
      lbl
      failure

    DecoderErrorEmptyList lbl ->
      bprint ("Found unexpected empty list while decoding " . stext) lbl

    DecoderErrorLeftover lbl leftover -> bprint
      ( "Found unexpected leftover bytes while decoding " . stext . "./n"
      . "Leftover: " . shown
      )
      lbl
      leftover

    DecoderErrorSizeMismatch lbl requested actual -> bprint
      ( "Size mismatch when decoding " . stext . ".\n"
      . "Expected " . int . ", but found " . int . "."
      )
      lbl
      requested
      actual

    DecoderErrorUnknownTag lbl t ->
      bprint ("Found unknown tag " . int . " while decoding " . stext) t lbl

    DecoderErrorVoid -> bprint "Attempted to decode Void"


--------------------------------------------------------------------------------
-- Useful primitives
--------------------------------------------------------------------------------

-- | Enforces that the input size is the same as the decoded one, failing in
--   case it's not
enforceSize :: Text -> Int -> D.Decoder s ()
enforceSize lbl requestedSize = D.decodeListLen >>= matchSize lbl requestedSize

-- | Compare two sizes, failing if they are not equal
matchSize :: Text -> Int -> Int -> D.Decoder s ()
matchSize lbl requestedSize actualSize =
  when (actualSize /= requestedSize) $ cborError $ DecoderErrorSizeMismatch
    lbl
    requestedSize
    actualSize

-- | @'D.Decoder'@ for list.
decodeListWith :: D.Decoder s a -> D.Decoder s [a]
decodeListWith d = do
  D.decodeListLenIndef
  D.decodeSequenceLenIndef (flip (:)) [] reverse d


--------------------------------------------------------------------------------
-- Primitive types
--------------------------------------------------------------------------------

instance FromCBOR () where
  fromCBOR = D.decodeNull

instance FromCBOR Bool where
  fromCBOR = D.decodeBool


--------------------------------------------------------------------------------
-- Numeric data
--------------------------------------------------------------------------------

instance FromCBOR Integer where
  fromCBOR = D.decodeInteger

instance FromCBOR Word where
  fromCBOR = D.decodeWord

instance FromCBOR Word8 where
  fromCBOR = D.decodeWord8

instance FromCBOR Word16 where
  fromCBOR = D.decodeWord16

instance FromCBOR Word32 where
  fromCBOR = D.decodeWord32

instance FromCBOR Word64 where
  fromCBOR = D.decodeWord64

instance FromCBOR Int where
  fromCBOR = D.decodeInt

instance FromCBOR Float where
  fromCBOR = D.decodeFloat

instance FromCBOR Int32 where
  fromCBOR = D.decodeInt32

instance FromCBOR Int64 where
  fromCBOR = D.decodeInt64

instance (Integral a, FromCBOR a) => FromCBOR (Ratio a) where
  fromCBOR = do
    enforceSize "Ratio" 2
    n <- fromCBOR
    d <- fromCBOR
    if d <= 0
      then cborError $ DecoderErrorCustom "Ratio" "invalid denominator"
      else return $! n % d

instance FromCBOR Nano where
  fromCBOR = MkFixed <$> fromCBOR

instance FromCBOR Pico where
  fromCBOR = MkFixed <$> fromCBOR

-- | For backwards compatibility we round pico precision to micro
instance FromCBOR NominalDiffTime where
  fromCBOR = fromRational . (% 1e6) <$> fromCBOR

instance FromCBOR Natural where
  fromCBOR = do
      !n <- fromCBOR
      if n >= 0
        then return $! fromInteger n
        else cborError $ DecoderErrorCustom "Natural" "got a negative number"

instance FromCBOR Void where
  fromCBOR = cborError DecoderErrorVoid


--------------------------------------------------------------------------------
-- Tagged
--------------------------------------------------------------------------------

instance (Typeable s, FromCBOR a) => FromCBOR (Tagged s a) where
  fromCBOR = Tagged <$> fromCBOR


--------------------------------------------------------------------------------
-- Containers
--------------------------------------------------------------------------------

instance (FromCBOR a, FromCBOR b) => FromCBOR (a,b) where
  fromCBOR = do
    D.decodeListLenOf 2
    !x <- fromCBOR
    !y <- fromCBOR
    return (x, y)

instance (FromCBOR a, FromCBOR b, FromCBOR c) => FromCBOR (a,b,c) where

  fromCBOR = do
    D.decodeListLenOf 3
    !x <- fromCBOR
    !y <- fromCBOR
    !z <- fromCBOR
    return (x, y, z)

instance (FromCBOR a, FromCBOR b, FromCBOR c, FromCBOR d) => FromCBOR (a,b,c,d) where
  fromCBOR = do
    D.decodeListLenOf 4
    !a <- fromCBOR
    !b <- fromCBOR
    !c <- fromCBOR
    !d <- fromCBOR
    return (a, b, c, d)

instance
  (FromCBOR a, FromCBOR b, FromCBOR c, FromCBOR d, FromCBOR e)
  => FromCBOR (a, b, c, d, e)
 where
  fromCBOR = do
    D.decodeListLenOf 5
    !a <- fromCBOR
    !b <- fromCBOR
    !c <- fromCBOR
    !d <- fromCBOR
    !e <- fromCBOR
    return (a, b, c, d, e)

instance
  ( FromCBOR a
  , FromCBOR b
  , FromCBOR c
  , FromCBOR d
  , FromCBOR e
  , FromCBOR f
  , FromCBOR g
  )
  => FromCBOR (a, b, c, d, e, f, g)
  where
  fromCBOR = do
    D.decodeListLenOf 7
    !a <- fromCBOR
    !b <- fromCBOR
    !c <- fromCBOR
    !d <- fromCBOR
    !e <- fromCBOR
    !f <- fromCBOR
    !g <- fromCBOR
    return (a, b, c, d, e, f, g)

instance FromCBOR BS.ByteString where
  fromCBOR = D.decodeBytes

instance FromCBOR Text where
  fromCBOR = D.decodeString

instance FromCBOR BSL.ByteString where
  fromCBOR = BSL.fromStrict <$> fromCBOR

instance FromCBOR SBS.ShortByteString where
  fromCBOR = do
    BA.BA (Prim.ByteArray ba) <- D.decodeByteArray
    return $ SBS.SBS ba

instance FromCBOR a => FromCBOR [a] where
  fromCBOR = decodeListWith fromCBOR

instance (FromCBOR a, FromCBOR b) => FromCBOR (Either a b) where
  fromCBOR = do
    D.decodeListLenOf 2
    t <- D.decodeWord
    case t of
      0 -> do
        !x <- fromCBOR
        return (Left x)
      1 -> do
        !x <- fromCBOR
        return (Right x)
      _ -> cborError $ DecoderErrorUnknownTag "Either" (fromIntegral t)

instance FromCBOR a => FromCBOR (NonEmpty a) where
  fromCBOR = nonEmpty <$> fromCBOR >>= toCborError . \case
    Nothing -> Left $ DecoderErrorEmptyList "NonEmpty"
    Just xs -> Right xs

instance FromCBOR a => FromCBOR (Maybe a) where
  fromCBOR = fromCBORMaybe fromCBOR

fromCBORMaybe :: D.Decoder s a -> D.Decoder s (Maybe a)
fromCBORMaybe fromCBORA = do
  n <- D.decodeListLen
  case n of
    0 -> return Nothing
    1 -> do
      !x <- fromCBORA
      return (Just x)
    _ -> cborError $ DecoderErrorUnknownTag "Maybe" (fromIntegral n)

decodeContainerSkelWithReplicate
  :: FromCBOR a
  => D.Decoder s Int
  -- ^ How to get the size of the container
  -> (Int -> D.Decoder s a -> D.Decoder s container)
  -- ^ replicateM for the container
  -> ([container] -> container)
  -- ^ concat for the container
  -> D.Decoder s container
decodeContainerSkelWithReplicate decodeLen replicateFun fromList = do
  -- Look at how much data we have at the moment and use it as the limit for
  -- the size of a single call to replicateFun. We don't want to use
  -- replicateFun directly on the result of decodeLen since this might lead to
  -- DOS attack (attacker providing a huge value for length). So if it's above
  -- our limit, we'll do manual chunking and then combine the containers into
  -- one.
  size  <- decodeLen
  limit <- D.peekAvailable
  if size <= limit
    then replicateFun size fromCBOR
    else do
        -- Take the max of limit and a fixed chunk size (note: limit can be
        -- 0). This basically means that the attacker can make us allocate a
        -- container of size 128 even though there's no actual input.
      let
        chunkSize = max limit 128
        (d, m)    = size `divMod` chunkSize
        buildOne s = replicateFun s fromCBOR
      containers <- sequence $ buildOne m : replicate d (buildOne chunkSize)
      return $! fromList containers
{-# INLINE decodeContainerSkelWithReplicate #-}

-- | Checks canonicity by comparing the new key being decoded with
--   the previous one, to enfore these are sorted the correct way.
--   See: https://tools.ietf.org/html/rfc7049#section-3.9
--   "[..]The keys in every map must be sorted lowest value to highest.[...]"
decodeMapSkel
  :: (Ord k, FromCBOR k, FromCBOR v) => ([(k, v)] -> m) -> D.Decoder s m
decodeMapSkel fromDistinctAscList = do
  n <- D.decodeMapLen
  case n of
    0 -> return (fromDistinctAscList [])
    _ -> do
      (firstKey, firstValue) <- decodeEntry
      fromDistinctAscList
        <$> decodeEntries (n - 1) firstKey [(firstKey, firstValue)]
 where
    -- Decode a single (k,v).
  decodeEntry :: (FromCBOR k, FromCBOR v) => D.Decoder s (k, v)
  decodeEntry = do
    !k <- fromCBOR
    !v <- fromCBOR
    return (k, v)

  -- Decode all the entries, enforcing canonicity by ensuring that the
  -- previous key is smaller than the next one.
  decodeEntries
    :: (FromCBOR k, FromCBOR v, Ord k)
    => Int
    -> k
    -> [(k, v)]
    -> D.Decoder s [(k, v)]
  decodeEntries 0               _           acc  = pure $ reverse acc
  decodeEntries !remainingPairs previousKey !acc = do
    p@(newKey, _) <- decodeEntry
    -- Order of keys needs to be strictly increasing, because otherwise it's
    -- possible to supply lists with various amount of duplicate keys which
    -- will result in the same map as long as the last value of the given
    -- key on the list is the same in all of them.
    if newKey > previousKey
      then decodeEntries (remainingPairs - 1) newKey (p : acc)
      else cborError $ DecoderErrorCanonicityViolation "Map"
{-# INLINE decodeMapSkel #-}

instance (Ord k, FromCBOR k, FromCBOR v) => FromCBOR (M.Map k v) where
  fromCBOR = decodeMapSkel M.fromDistinctAscList

-- We stitch a `258` in from of a (Hash)Set, so that tools which
-- programmatically check for canonicity can recognise it from a normal
-- array. Why 258? This will be formalised pretty soon, but IANA allocated
-- 256...18446744073709551615 to "First come, first served":
-- https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml Currently `258` is
-- the first unassigned tag and as it requires 2 bytes to be encoded, it sounds
-- like the best fit.
setTag :: Word
setTag = 258

decodeSetTag :: D.Decoder s ()
decodeSetTag = do
  t <- D.decodeTag
  when (t /= setTag) $ cborError $ DecoderErrorUnknownTag "Set" (fromIntegral t)

decodeSetSkel :: (Ord a, FromCBOR a) => ([a] -> c) -> D.Decoder s c
decodeSetSkel fromDistinctAscList = do
  decodeSetTag
  n <- D.decodeListLen
  case n of
    0 -> return (fromDistinctAscList [])
    _ -> do
      firstValue <- fromCBOR
      fromDistinctAscList <$> decodeEntries (n - 1) firstValue [firstValue]
 where
  decodeEntries :: (FromCBOR v, Ord v) => Int -> v -> [v] -> D.Decoder s [v]
  decodeEntries 0                 _             acc  = pure $ reverse acc
  decodeEntries !remainingEntries previousValue !acc = do
    newValue <- fromCBOR
    -- Order of values needs to be strictly increasing, because otherwise
    -- it's possible to supply lists with various amount of duplicates which
    -- will result in the same set.
    if newValue > previousValue
      then decodeEntries (remainingEntries - 1) newValue (newValue : acc)
      else cborError $ DecoderErrorCanonicityViolation "Set"
{-# INLINE decodeSetSkel #-}

instance (Ord a, FromCBOR a) => FromCBOR (S.Set a) where
  fromCBOR = decodeSetSkel S.fromDistinctAscList

-- | Generic decoder for vectors. Its intended use is to allow easy
-- definition of 'Serialise' instances for custom vector
decodeVector :: (FromCBOR a, Vector.Generic.Vector v a) => D.Decoder s (v a)
decodeVector = decodeContainerSkelWithReplicate
  D.decodeListLen
  Vector.Generic.replicateM
  Vector.Generic.concat
{-# INLINE decodeVector #-}

instance (FromCBOR a) => FromCBOR (Vector.Vector a) where
  fromCBOR = decodeVector
  {-# INLINE fromCBOR #-}


--------------------------------------------------------------------------------
-- Time
--------------------------------------------------------------------------------

instance FromCBOR UTCTime where
  fromCBOR = do
    enforceSize "UTCTime" 3
    year <- decodeInteger
    dayOfYear <- decodeInt
    timeOfDayPico <- decodeInteger
    return $ UTCTime
      (fromOrdinalDate year dayOfYear)
      (picosecondsToDiffTime timeOfDayPico)

-- | Convert an 'Either'-encoded failure to a 'cborg' decoder failure
toCborError :: B.Buildable e => Either e a -> D.Decoder s a
toCborError = either cborError pure

-- | Convert a @Buildable@ error into a 'cborg' decoder error
cborError :: B.Buildable e => e -> D.Decoder s a
cborError = fail . formatToString build