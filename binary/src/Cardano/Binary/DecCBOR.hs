{-# LANGUAGE BangPatterns              #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE NumDecimals               #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}

module Cardano.Binary.DecCBOR
  ( DecCBOR(..)
  , DecoderError(..)
  , enforceSize
  , matchSize
  , module D
  , decCBORMaybe
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
import Codec.CBOR.Term
import Control.Category (Category((.)))
import Control.Exception (Exception)
import Control.Monad (when, replicateM)
import qualified Codec.CBOR.Read as CBOR.Read
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Short as SBS
import Data.ByteString.Short.Internal (ShortByteString (SBS))
import Data.Fixed (Fixed(..), Nano, Pico)
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


class Typeable a => DecCBOR a where
  decCBOR :: D.Decoder s a

  label :: Proxy a -> Text
  label = T.pack . show . typeRep

instance DecCBOR Term where
  decCBOR = decodeTerm

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

instance DecCBOR () where
  decCBOR = D.decodeNull

instance DecCBOR Bool where
  decCBOR = D.decodeBool


--------------------------------------------------------------------------------
-- Numeric data
--------------------------------------------------------------------------------

instance DecCBOR Integer where
  decCBOR = D.decodeInteger

instance DecCBOR Word where
  decCBOR = D.decodeWord

instance DecCBOR Word8 where
  decCBOR = D.decodeWord8

instance DecCBOR Word16 where
  decCBOR = D.decodeWord16

instance DecCBOR Word32 where
  decCBOR = D.decodeWord32

instance DecCBOR Word64 where
  decCBOR = D.decodeWord64

instance DecCBOR Int where
  decCBOR = D.decodeInt

instance DecCBOR Int32 where
  decCBOR = D.decodeInt32

instance DecCBOR Int64 where
  decCBOR = D.decodeInt64

instance DecCBOR Float where
  decCBOR = D.decodeFloat

instance DecCBOR Double where
  decCBOR = D.decodeDouble

instance DecCBOR Rational where
  decCBOR = do
    enforceSize "Ratio" 2
    n <- decCBOR
    d <- decCBOR
    if d <= 0
      then cborError $ DecoderErrorCustom "Rational" "invalid denominator"
      else return $! n % d

instance DecCBOR Nano where
  decCBOR = MkFixed <$> decCBOR

instance DecCBOR Pico where
  decCBOR = MkFixed <$> decCBOR

-- | For backwards compatibility we round pico precision to micro
instance DecCBOR NominalDiffTime where
  decCBOR = fromRational . (% 1e6) <$> decCBOR

instance DecCBOR Natural where
  decCBOR = do
      !n <- decCBOR
      if n >= 0
        then return $! fromInteger n
        else cborError $ DecoderErrorCustom "Natural" "got a negative number"

instance DecCBOR Void where
  decCBOR = cborError DecoderErrorVoid


--------------------------------------------------------------------------------
-- Tagged
--------------------------------------------------------------------------------

instance (Typeable s, DecCBOR a) => DecCBOR (Tagged s a) where
  decCBOR = Tagged <$> decCBOR


--------------------------------------------------------------------------------
-- Containers
--------------------------------------------------------------------------------

instance (DecCBOR a, DecCBOR b) => DecCBOR (a,b) where
  decCBOR = do
    D.decodeListLenOf 2
    !x <- decCBOR
    !y <- decCBOR
    return (x, y)

instance (DecCBOR a, DecCBOR b, DecCBOR c) => DecCBOR (a,b,c) where

  decCBOR = do
    D.decodeListLenOf 3
    !x <- decCBOR
    !y <- decCBOR
    !z <- decCBOR
    return (x, y, z)

instance (DecCBOR a, DecCBOR b, DecCBOR c, DecCBOR d) => DecCBOR (a,b,c,d) where
  decCBOR = do
    D.decodeListLenOf 4
    !a <- decCBOR
    !b <- decCBOR
    !c <- decCBOR
    !d <- decCBOR
    return (a, b, c, d)

instance
  (DecCBOR a, DecCBOR b, DecCBOR c, DecCBOR d, DecCBOR e)
  => DecCBOR (a, b, c, d, e)
 where
  decCBOR = do
    D.decodeListLenOf 5
    !a <- decCBOR
    !b <- decCBOR
    !c <- decCBOR
    !d <- decCBOR
    !e <- decCBOR
    return (a, b, c, d, e)

instance
  (DecCBOR a, DecCBOR b, DecCBOR c, DecCBOR d, DecCBOR e, DecCBOR f)
  => DecCBOR (a, b, c, d, e, f)
 where
  decCBOR = do
    D.decodeListLenOf 6
    !a <- decCBOR
    !b <- decCBOR
    !c <- decCBOR
    !d <- decCBOR
    !e <- decCBOR
    !f <- decCBOR
    return (a, b, c, d, e, f)

instance
  ( DecCBOR a
  , DecCBOR b
  , DecCBOR c
  , DecCBOR d
  , DecCBOR e
  , DecCBOR f
  , DecCBOR g
  )
  => DecCBOR (a, b, c, d, e, f, g)
  where
  decCBOR = do
    D.decodeListLenOf 7
    !a <- decCBOR
    !b <- decCBOR
    !c <- decCBOR
    !d <- decCBOR
    !e <- decCBOR
    !f <- decCBOR
    !g <- decCBOR
    return (a, b, c, d, e, f, g)

instance
  ( DecCBOR a
  , DecCBOR b
  , DecCBOR c
  , DecCBOR d
  , DecCBOR e
  , DecCBOR f
  , DecCBOR g
  , DecCBOR h
  )
  => DecCBOR (a, b, c, d, e, f, g, h)
  where
  decCBOR = do
    D.decodeListLenOf 8
    !a <- decCBOR
    !b <- decCBOR
    !c <- decCBOR
    !d <- decCBOR
    !e <- decCBOR
    !f <- decCBOR
    !g <- decCBOR
    !h <- decCBOR
    return (a, b, c, d, e, f, g, h)

instance DecCBOR BS.ByteString where
  decCBOR = D.decodeBytes

instance DecCBOR Text where
  decCBOR = D.decodeString

instance DecCBOR BSL.ByteString where
  decCBOR = BSL.fromStrict <$> decCBOR

instance DecCBOR SBS.ShortByteString where
  decCBOR = do
    BA.BA (Prim.ByteArray ba) <- D.decodeByteArray
    return $ SBS ba

instance DecCBOR a => DecCBOR [a] where
  decCBOR = decodeListWith decCBOR

instance (DecCBOR a, DecCBOR b) => DecCBOR (Either a b) where
  decCBOR = do
    D.decodeListLenOf 2
    t <- D.decodeWord
    case t of
      0 -> do
        !x <- decCBOR
        return (Left x)
      1 -> do
        !x <- decCBOR
        return (Right x)
      _ -> cborError $ DecoderErrorUnknownTag "Either" (fromIntegral t)

instance DecCBOR a => DecCBOR (NonEmpty a) where
  decCBOR = nonEmpty <$> decCBOR >>= toCborError . \case
    Nothing -> Left $ DecoderErrorEmptyList "NonEmpty"
    Just xs -> Right xs

instance DecCBOR a => DecCBOR (Maybe a) where
  decCBOR = decCBORMaybe decCBOR

decCBORMaybe :: D.Decoder s a -> D.Decoder s (Maybe a)
decCBORMaybe decCBORA = do
  n <- D.decodeListLen
  case n of
    0 -> return Nothing
    1 -> do
      !x <- decCBORA
      return (Just x)
    _ -> cborError $ DecoderErrorUnknownTag "Maybe" (fromIntegral n)

decodeContainerSkelWithReplicate
  :: DecCBOR a
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
    then replicateFun size decCBOR
    else do
        -- Take the max of limit and a fixed chunk size (note: limit can be
        -- 0). This basically means that the attacker can make us allocate a
        -- container of size 128 even though there's no actual input.
      let
        chunkSize = max limit 128
        (d, m)    = size `divMod` chunkSize
        buildOne s = replicateFun s decCBOR
      containers <- sequence $ buildOne m : replicate d (buildOne chunkSize)
      return $! fromList containers
{-# INLINE decodeContainerSkelWithReplicate #-}

-- | Checks canonicity by comparing the new key being decoded with
--   the previous one, to enfore these are sorted the correct way.
--   See: https://tools.ietf.org/html/rfc7049#section-3.9
--   "[..]The keys in every map must be sorted lowest value to highest.[...]"
decodeMapSkel
  :: (Ord k, DecCBOR k, DecCBOR v) => ([(k, v)] -> m) -> D.Decoder s m
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
  decodeEntry :: (DecCBOR k, DecCBOR v) => D.Decoder s (k, v)
  decodeEntry = do
    !k <- decCBOR
    !v <- decCBOR
    return (k, v)

  -- Decode all the entries, enforcing canonicity by ensuring that the
  -- previous key is smaller than the next one.
  decodeEntries
    :: (DecCBOR k, DecCBOR v, Ord k)
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

instance (Ord k, DecCBOR k, DecCBOR v) => DecCBOR (M.Map k v) where
  decCBOR = decodeMapSkel M.fromDistinctAscList

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

decodeSetSkel :: (Ord a, DecCBOR a) => ([a] -> c) -> D.Decoder s c
decodeSetSkel fromDistinctAscList = do
  decodeSetTag
  n <- D.decodeListLen
  case n of
    0 -> return (fromDistinctAscList [])
    _ -> do
      firstValue <- decCBOR
      fromDistinctAscList <$> decodeEntries (n - 1) firstValue [firstValue]
 where
  decodeEntries :: (DecCBOR v, Ord v) => Int -> v -> [v] -> D.Decoder s [v]
  decodeEntries 0                 _             acc  = pure $ reverse acc
  decodeEntries !remainingEntries previousValue !acc = do
    newValue <- decCBOR
    -- Order of values needs to be strictly increasing, because otherwise
    -- it's possible to supply lists with various amount of duplicates which
    -- will result in the same set.
    if newValue > previousValue
      then decodeEntries (remainingEntries - 1) newValue (newValue : acc)
      else cborError $ DecoderErrorCanonicityViolation "Set"
{-# INLINE decodeSetSkel #-}

instance (Ord a, DecCBOR a) => DecCBOR (S.Set a) where
  decCBOR = decodeSetSkel S.fromDistinctAscList

-- | Generic decoder for vectors. Its intended use is to allow easy
-- definition of 'Serialise' instances for custom vector
decodeVector :: (DecCBOR a, Vector.Generic.Vector v a) => D.Decoder s (v a)
decodeVector = decodeContainerSkelWithReplicate
  D.decodeListLen
  Vector.Generic.replicateM
  Vector.Generic.concat
{-# INLINE decodeVector #-}

instance DecCBOR a => DecCBOR (Vector.Vector a) where
  decCBOR = decodeVector
  {-# INLINE decCBOR #-}

instance DecCBOR a => DecCBOR (Seq.Seq a) where
  decCBOR = decodeSeq decCBOR
  {-# INLINE decCBOR #-}

decodeSeq :: Decoder s a -> Decoder s (Seq.Seq a)
decodeSeq decoder = Seq.fromList <$> decodeCollection decodeListLenOrIndef decoder

decodeCollection :: Decoder s (Maybe Int) -> Decoder s a -> Decoder s [a]
decodeCollection lenOrIndef el = snd <$> decodeCollectionWithLen lenOrIndef el

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

--------------------------------------------------------------------------------
-- Time
--------------------------------------------------------------------------------

instance DecCBOR UTCTime where
  decCBOR = do
    enforceSize "UTCTime" 3
    year <- decodeInteger
    dayOfYear <- decodeInt
    timeOfDayPico <- decodeInteger
    return $ UTCTime
      (fromOrdinalDate year dayOfYear)
      (picosecondsToDiffTime timeOfDayPico)

-- | Convert an 'Either'-encoded failure to a 'cborg' decoder failure
toCborError :: (MonadFail m, B.Buildable e) => Either e a -> m a
toCborError = either cborError pure

-- | Convert a @Buildable@ error into a 'cborg' decoder error
cborError :: (MonadFail m, B.Buildable e) => e -> m a
cborError = fail . formatToString build
