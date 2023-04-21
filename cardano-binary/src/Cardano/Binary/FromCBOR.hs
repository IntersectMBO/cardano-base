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
  , decodeMaybe
  , fromCBORMaybe
  , decodeNullMaybe
  , decodeSeq
  , decodeListWith
  , decodeNominalDiffTime
  , decodeNominalDiffTimeMicro
    -- * Helper tools to build instances
  , decodeMapSkel
  , decodeCollection
  , decodeCollectionWithLen
  , cborError
  , toCborError
  )
where

import Prelude hiding ((.))

import Codec.CBOR.Decoding as D
import Codec.CBOR.ByteArray as BA ( ByteArray(BA) )
import Codec.CBOR.Term
import Control.Category (Category((.)))
import Control.Exception (Exception)
import Control.Monad (when, replicateM)
import qualified Codec.CBOR.Read as CBOR.Read
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Short as SBS
import Data.ByteString.Short.Internal (ShortByteString (SBS))
import Data.Fixed (Fixed(..))
import Data.Int (Int32, Int64)
import Data.List.NonEmpty (NonEmpty, nonEmpty)
import qualified Data.Map as M
import qualified Data.Primitive.ByteArray as Prim
import Data.Ratio ((%))
import qualified Data.Sequence as Seq
import qualified Data.Set as S
import Data.Tagged (Tagged(..))
import Data.Text (Text)
import qualified Data.Text  as T
import Data.Time.Calendar.OrdinalDate ( fromOrdinalDate )
import Data.Time.Clock (NominalDiffTime, UTCTime(..), secondsToNominalDiffTime, picosecondsToDiffTime)
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


class Typeable a => FromCBOR a where
  fromCBOR :: D.Decoder s a

  label :: Proxy a -> Text
  label = T.pack . show . typeRep

instance FromCBOR Term where
  fromCBOR = decodeTerm
  {-# INLINE fromCBOR #-}

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
{-# INLINE enforceSize #-}

-- | Compare two sizes, failing if they are not equal
matchSize :: Text -> Int -> Int -> D.Decoder s ()
matchSize lbl requestedSize actualSize =
  when (actualSize /= requestedSize) $ cborError $ DecoderErrorSizeMismatch
    lbl
    requestedSize
    actualSize
{-# INLINE matchSize #-}

-- | @'D.Decoder'@ for list.
decodeListWith :: D.Decoder s a -> D.Decoder s [a]
decodeListWith d = do
  D.decodeListLenIndef
  D.decodeSequenceLenIndef (flip (:)) [] reverse d
{-# INLINE decodeListWith #-}


--------------------------------------------------------------------------------
-- Primitive types
--------------------------------------------------------------------------------

instance FromCBOR () where
  fromCBOR = D.decodeNull
  {-# INLINE fromCBOR #-}

instance FromCBOR Bool where
  fromCBOR = D.decodeBool
  {-# INLINE fromCBOR #-}


--------------------------------------------------------------------------------
-- Numeric data
--------------------------------------------------------------------------------

instance FromCBOR Integer where
  fromCBOR = D.decodeInteger
  {-# INLINE fromCBOR #-}

instance FromCBOR Word where
  fromCBOR = D.decodeWord
  {-# INLINE fromCBOR #-}

instance FromCBOR Word8 where
  fromCBOR = D.decodeWord8
  {-# INLINE fromCBOR #-}

instance FromCBOR Word16 where
  fromCBOR = D.decodeWord16
  {-# INLINE fromCBOR #-}

instance FromCBOR Word32 where
  fromCBOR = D.decodeWord32
  {-# INLINE fromCBOR #-}

instance FromCBOR Word64 where
  fromCBOR = D.decodeWord64
  {-# INLINE fromCBOR #-}

instance FromCBOR Int where
  fromCBOR = D.decodeInt
  {-# INLINE fromCBOR #-}

instance FromCBOR Int32 where
  fromCBOR = D.decodeInt32
  {-# INLINE fromCBOR #-}

instance FromCBOR Int64 where
  fromCBOR = D.decodeInt64
  {-# INLINE fromCBOR #-}

instance FromCBOR Float where
  fromCBOR = D.decodeFloat
  {-# INLINE fromCBOR #-}

instance FromCBOR Double where
  fromCBOR = D.decodeDouble
  {-# INLINE fromCBOR #-}

instance FromCBOR Rational where
  fromCBOR = do
    enforceSize "Rational" 2
    n <- fromCBOR
    d <- fromCBOR
    if d <= 0
      then cborError $ DecoderErrorCustom "Rational" "invalid denominator"
      else return $! n % d

instance Typeable a => FromCBOR (Fixed a) where
  fromCBOR = MkFixed <$> fromCBOR
  {-# INLINE fromCBOR #-}

decodeNominalDiffTime :: Decoder s NominalDiffTime
decodeNominalDiffTime = secondsToNominalDiffTime <$> fromCBOR
{-# INLINE decodeNominalDiffTime #-}

-- | For backwards compatibility we round pico precision to micro
decodeNominalDiffTimeMicro :: Decoder s NominalDiffTime
decodeNominalDiffTimeMicro = fromRational . (% 1e6) <$> fromCBOR
{-# INLINE decodeNominalDiffTimeMicro #-}

instance FromCBOR Natural where
  fromCBOR = do
      !n <- fromCBOR
      if n >= 0
        then return $! fromInteger n
        else cborError $ DecoderErrorCustom "Natural" "got a negative number"
  {-# INLINE fromCBOR #-}

instance FromCBOR Void where
  fromCBOR = cborError DecoderErrorVoid
  {-# INLINE fromCBOR #-}


--------------------------------------------------------------------------------
-- Tagged
--------------------------------------------------------------------------------

instance (Typeable s, FromCBOR a) => FromCBOR (Tagged s a) where
  fromCBOR = Tagged <$> fromCBOR
  {-# INLINE fromCBOR #-}


--------------------------------------------------------------------------------
-- Containers
--------------------------------------------------------------------------------

instance (FromCBOR a, FromCBOR b) => FromCBOR (a,b) where
  fromCBOR = do
    D.decodeListLenOf 2
    !x <- fromCBOR
    !y <- fromCBOR
    return (x, y)
  {-# INLINE fromCBOR #-}

instance (FromCBOR a, FromCBOR b, FromCBOR c) => FromCBOR (a,b,c) where

  fromCBOR = do
    D.decodeListLenOf 3
    !x <- fromCBOR
    !y <- fromCBOR
    !z <- fromCBOR
    return (x, y, z)
  {-# INLINE fromCBOR #-}

instance (FromCBOR a, FromCBOR b, FromCBOR c, FromCBOR d) => FromCBOR (a,b,c,d) where
  fromCBOR = do
    D.decodeListLenOf 4
    !a <- fromCBOR
    !b <- fromCBOR
    !c <- fromCBOR
    !d <- fromCBOR
    return (a, b, c, d)
  {-# INLINE fromCBOR #-}

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
  {-# INLINE fromCBOR #-}

instance
  (FromCBOR a, FromCBOR b, FromCBOR c, FromCBOR d, FromCBOR e, FromCBOR f)
  => FromCBOR (a, b, c, d, e, f)
 where
  fromCBOR = do
    D.decodeListLenOf 6
    !a <- fromCBOR
    !b <- fromCBOR
    !c <- fromCBOR
    !d <- fromCBOR
    !e <- fromCBOR
    !f <- fromCBOR
    return (a, b, c, d, e, f)
  {-# INLINE fromCBOR #-}

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
  {-# INLINE fromCBOR #-}

instance
  ( FromCBOR a
  , FromCBOR b
  , FromCBOR c
  , FromCBOR d
  , FromCBOR e
  , FromCBOR f
  , FromCBOR g
  , FromCBOR h
  )
  => FromCBOR (a, b, c, d, e, f, g, h)
  where
  fromCBOR = do
    D.decodeListLenOf 8
    !a <- fromCBOR
    !b <- fromCBOR
    !c <- fromCBOR
    !d <- fromCBOR
    !e <- fromCBOR
    !f <- fromCBOR
    !g <- fromCBOR
    !h <- fromCBOR
    return (a, b, c, d, e, f, g, h)
  {-# INLINE fromCBOR #-}

instance FromCBOR BS.ByteString where
  fromCBOR = D.decodeBytes
  {-# INLINE fromCBOR #-}

instance FromCBOR Text where
  fromCBOR = D.decodeString
  {-# INLINE fromCBOR #-}

instance FromCBOR BSL.ByteString where
  fromCBOR = BSL.fromStrict <$> fromCBOR
  {-# INLINE fromCBOR #-}

instance FromCBOR SBS.ShortByteString where
  fromCBOR = do
    BA.BA (Prim.ByteArray ba) <- D.decodeByteArray
    return $ SBS ba
  {-# INLINE fromCBOR #-}

instance FromCBOR a => FromCBOR [a] where
  fromCBOR = decodeListWith fromCBOR
  {-# INLINE fromCBOR #-}

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
  {-# INLINE fromCBOR #-}

instance FromCBOR a => FromCBOR (NonEmpty a) where
  fromCBOR = nonEmpty <$> fromCBOR >>= toCborError . \case
    Nothing -> Left $ DecoderErrorEmptyList "NonEmpty"
    Just xs -> Right xs
  {-# INLINE fromCBOR #-}


instance FromCBOR a => FromCBOR (Maybe a) where
  fromCBOR = decodeMaybe fromCBOR
  {-# INLINE fromCBOR #-}

fromCBORMaybe :: D.Decoder s a -> D.Decoder s (Maybe a)
fromCBORMaybe = decodeMaybe
{-# DEPRECATED fromCBORMaybe "In favor of `decodeMaybe`" #-}

decodeMaybe :: D.Decoder s a -> D.Decoder s (Maybe a)
decodeMaybe decodeValue = do
  n <- D.decodeListLen
  case n of
    0 -> return Nothing
    1 -> do
      !x <- decodeValue
      return (Just x)
    _ -> cborError $ DecoderErrorUnknownTag "Maybe" (fromIntegral n)
{-# INLINE decodeMaybe #-}

decodeNullMaybe :: D.Decoder s a -> D.Decoder s (Maybe a)
decodeNullMaybe decoder = do
  D.peekTokenType >>= \case
    D.TypeNull -> do
      D.decodeNull
      pure Nothing
    _ -> Just <$> decoder
{-# INLINE decodeNullMaybe #-}


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
{-# INLINEABLE decodeContainerSkelWithReplicate #-}

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
  {-# INLINE decodeEntry #-}

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
{-# INLINEABLE decodeMapSkel #-}

instance (Ord k, FromCBOR k, FromCBOR v) => FromCBOR (M.Map k v) where
  fromCBOR = decodeMapSkel M.fromDistinctAscList
  {-# INLINE fromCBOR #-}

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
{-# INLINE decodeSetTag #-}

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
  {-# INLINE fromCBOR #-}

-- | Generic decoder for vectors. Its intended use is to allow easy
-- definition of 'Serialise' instances for custom vector
decodeVector :: (FromCBOR a, Vector.Generic.Vector v a) => D.Decoder s (v a)
decodeVector = decodeContainerSkelWithReplicate
  D.decodeListLen
  Vector.Generic.replicateM
  Vector.Generic.concat
{-# INLINE decodeVector #-}

instance FromCBOR a => FromCBOR (Vector.Vector a) where
  fromCBOR = decodeVector
  {-# INLINE fromCBOR #-}

instance FromCBOR a => FromCBOR (Seq.Seq a) where
  fromCBOR = decodeSeq fromCBOR
  {-# INLINE fromCBOR #-}

decodeSeq :: Decoder s a -> Decoder s (Seq.Seq a)
decodeSeq decoder = Seq.fromList <$> decodeCollection decodeListLenOrIndef decoder
{-# INLINE decodeSeq #-}

decodeCollection :: Decoder s (Maybe Int) -> Decoder s a -> Decoder s [a]
decodeCollection lenOrIndef el = snd <$> decodeCollectionWithLen lenOrIndef el
{-# INLINE decodeCollection #-}

decodeCollectionWithLen ::
  Decoder s (Maybe Int) ->
  Decoder s v ->
  Decoder s (Int, [v])
decodeCollectionWithLen lenOrIndef el = do
  lenOrIndef >>= \case
    Just len -> (,) len <$> replicateM len el
    Nothing -> loop (0, []) (not <$> decodeBreakOr) el
  where
    loop (!n, !acc) condition action =
      condition >>= \case
        False -> pure (n, reverse acc)
        True -> action >>= \v -> loop (n + 1, v : acc) condition action
{-# INLINEABLE decodeCollectionWithLen #-}

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
  {-# INLINE fromCBOR #-}

-- | Convert an 'Either'-encoded failure to a 'MonadFail' failure using the `B.Buildable`
-- insatance
toCborError :: (MonadFail m, B.Buildable e) => Either e a -> m a
toCborError = either cborError pure

-- | Convert a `B.Buildable` error message into a 'MonadFail' failure.
cborError :: (MonadFail m, B.Buildable e) => e -> m a
cborError = fail . formatToString build
