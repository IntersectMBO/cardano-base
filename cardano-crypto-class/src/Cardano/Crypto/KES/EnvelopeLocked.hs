{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | A text-envelope reader and writer for KES signing key files that work on
-- locked memory.
--
-- The file written by @cardano-cli node key-gen-KES@ is a three-field JSON
-- text envelope:
--
-- > {
-- >     "type": "KesSigningKey_ed25519_kes_2^6",
-- >     "description": "KES Signing Key",
-- >     "cborHex": "5902 60 <608 bytes>"
-- > }
--
-- The hex text in @cborHex@ /is/ the secret, so neither the file contents
-- nor the decoded key may pass through the GHC heap. The reader here
-- therefore scans the raw file bytes in place for the field values (it only
-- ever produces offsets), hex-decodes the @cborHex@ span straight into locked
-- memory, decodes the fixed CBOR shape by hand, and hands back the key bytes
-- in a fresh locked buffer. The writer builds the JSON text in a locked
-- buffer, hands it to a continuation, and erases it afterwards. Both are
-- deliberately hand-rolled for this one fixed shape rather than pulling a
-- JSON or CBOR library into the path of the key.
--
-- Two envelope types are understood, distinguished by the @type@ string:
--
-- * 'KESKeyEvolutionZero', @KesSigningKey_\<algorithm\>@: the key as
--   generated, at evolution 0. Its @cborHex@ is one CBOR byte string holding
--   the raw serialisation of the key.
--
-- * 'KESKeyWithPeriod', @KesSigningKeyWithPeriod_\<algorithm\>@: a key that
--   has been evolved. Its @cborHex@ is a two-element CBOR array: the
--   /absolute/ KES period the key is valid for (an unsigned integer), then
--   the same byte string.
--
-- Errors never carry any of the input; they consist of field names, offsets
-- and lengths only, so they can be logged.
module Cardano.Crypto.KES.EnvelopeLocked (
  -- * Envelope types
  KESEnvelopeType (..),
  kesEvolutionZeroTypeString,
  kesWithPeriodTypeString,

  -- * Errors
  KESEnvelopeError (..),

  -- * Reading
  LockedKESEnvelope (..),
  readLockedKESEnvelope,
  finalizeLockedKESEnvelope,

  -- * Writing
  writeLockedKESEnvelope,
) where

import Control.Monad (filterM, unless, when, zipWithM)
import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow, finally)
import Control.Monad.Except (ExceptT (..), runExceptT, throwError)
import Control.Monad.IO.Class (liftIO)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Unsafe as BS
import Data.Char (ord)
import Data.Word (Word64, Word8)
import Foreign.C.Types (CChar, CSize)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peekByteOff)

import Cardano.Crypto.Libsodium.Hex (
  HexDecodeError,
  hexDecodeToMLocked,
  hexEncodeMLocked,
 )
import Cardano.Crypto.Libsodium.Memory (
  MLockedAllocator (..),
  MLockedForeignPtr,
  copyMem,
  finalizeMLockedForeignPtr,
  mlockedMalloc,
  withMLockedForeignPtr,
  zeroMem,
 )
import Cardano.Crypto.Libsodium.Memory.Internal (unsafeIOToMonadST)

{-------------------------------------------------------------------------------
  Envelope types
-------------------------------------------------------------------------------}

-- | Which of the two KES signing key envelopes a file holds.
data KESEnvelopeType
  = -- | @KesSigningKey_\<algorithm\>@: the key at evolution 0, no period.
    KESKeyEvolutionZero
  | -- | @KesSigningKeyWithPeriod_\<algorithm\>@: an evolved key together
    -- with the absolute KES period it is valid for.
    KESKeyWithPeriod
  deriving (Show, Eq)

-- | The @type@ string of an evolution-zero envelope for the given algorithm
-- name (@algorithmNameKES@, e.g. @ed25519_kes_2^6@). This is the type
-- @cardano-cli@ writes.
kesEvolutionZeroTypeString :: String -> ByteString
kesEvolutionZeroTypeString name = "KesSigningKey_" <> BC.pack name

-- | The @type@ string of a period-carrying envelope for the given algorithm
-- name.
kesWithPeriodTypeString :: String -> ByteString
kesWithPeriodTypeString name = "KesSigningKeyWithPeriod_" <> BC.pack name

{-------------------------------------------------------------------------------
  Errors
-------------------------------------------------------------------------------}

-- | Why a KES signing key text envelope could not be used. The constructors
-- carry field names, offsets and lengths only, never any of the file's
-- contents, so the error can be logged safely.
data KESEnvelopeError
  = -- | The file is not a JSON object with exactly the string fields
    -- @type@, @description@ and @cborHex@.
    EnvelopeNotAnObject
  | -- | The named field is absent.
    EnvelopeMissingField !String
  | -- | The @type@ field is neither of the two KES signing key types for
    -- the expected algorithm.
    EnvelopeUnknownType
  | -- | The @cborHex@ field is not valid hex.
    EnvelopeBadHex !HexDecodeError
  | -- | The decoded @cborHex@ does not have the CBOR shape of its type: one
    -- byte string for 'KESKeyEvolutionZero', a two-element array of an
    -- unsigned integer and a byte string for 'KESKeyWithPeriod'.
    EnvelopeBadCbor
  | -- | The key bytes do not have the expected length: expected and actual
    -- length in bytes. The reader does not know the algorithm's key size,
    -- so this is raised by the caller that does.
    EnvelopeBadLength !Int !Int
  deriving (Show, Eq)

{-------------------------------------------------------------------------------
  Reading
-------------------------------------------------------------------------------}

-- | The contents of a KES signing key envelope, with the key bytes in locked
-- memory. The caller owns 'lkeKey' and must release it with
-- 'finalizeLockedKESEnvelope', which erases it.
data LockedKESEnvelope = LockedKESEnvelope
  { lkeType :: !KESEnvelopeType
  , lkePeriod :: !(Maybe Word64)
  -- ^ The absolute KES period; 'Just' exactly for 'KESKeyWithPeriod'.
  , lkeKey :: !(MLockedForeignPtr CChar)
  -- ^ The raw key bytes, CBOR framing already stripped. In the layout of
  -- @rawSerialiseSignKeyKES@ \/ 'Cardano.Crypto.DirectSerialise.DirectSerialise'.
  , lkeKeyLen :: !Int
  -- ^ The number of key bytes. Not checked against any key size here.
  }

-- | Read a KES signing key envelope from the raw file bytes at the given
-- pointer (which should themselves be in locked memory, since the hex text is
-- the secret). The first argument is the algorithm name
-- (@algorithmNameKES@), which fixes the two acceptable @type@ strings.
--
-- On success the key bytes are in a fresh locked buffer owned by the caller.
-- Every intermediate buffer is erased before this returns, and on an error
-- nothing is left allocated.
readLockedKESEnvelope ::
  MonadST m =>
  String ->
  Ptr Word8 ->
  Int ->
  m (Either KESEnvelopeError LockedKESEnvelope)
readLockedKESEnvelope name ptr len = unsafeIOToMonadST $ runExceptT $ do
  -- Locate the field values. Only offsets leave this step.
  spans <- ExceptT (scanKESEnvelope ptr len)

  -- Check the envelope type before touching the key material.
  isEvolutionZero <- liftIO $ spanEqualsBS ptr (esType spans) (kesEvolutionZeroTypeString name)
  isWithPeriod <- liftIO $ spanEqualsBS ptr (esType spans) (kesWithPeriodTypeString name)
  envelopeType <-
    if
      | isEvolutionZero -> pure KESKeyEvolutionZero
      | isWithPeriod -> pure KESKeyWithPeriod
      | otherwise -> throwError EnvelopeUnknownType

  -- Hex-decode the @cborHex@ value in place into a locked buffer, decode the
  -- CBOR framing and copy the key bytes out into their own locked buffer.
  let (hexOff, hexLen) = esCborHex spans
  (decodedBuf, decodedLen) <-
    ExceptT $ either (Left . EnvelopeBadHex) Right <$> hexDecodeToMLocked (ptr `plusPtr` hexOff) hexLen
  ExceptT $
    ( withMLockedForeignPtr decodedBuf $ \decoded -> runExceptT $ do
        (period, (keyOff, keyLen)) <- ExceptT (decodeCbor envelopeType decoded decodedLen)
        keyBuf <- liftIO $ mlAllocate mlockedMalloc (fromIntegral @Int @CSize (max 1 keyLen))
        liftIO $ withMLockedForeignPtr keyBuf $ \key ->
          copyMem key (decoded `plusPtr` keyOff) (fromIntegral @Int @CSize keyLen)
        pure
          LockedKESEnvelope
            { lkeType = envelopeType
            , lkePeriod = period
            , lkeKey = keyBuf
            , lkeKeyLen = keyLen
            }
    )
      `finally` do
        withMLockedForeignPtr decodedBuf $ \decoded ->
          zeroMem decoded (fromIntegral @Int @CSize decodedLen)
        finalizeMLockedForeignPtr decodedBuf

-- | Erase and release the key buffer of a 'LockedKESEnvelope'.
finalizeLockedKESEnvelope :: MonadST m => LockedKESEnvelope -> m ()
finalizeLockedKESEnvelope env = do
  withMLockedForeignPtr (lkeKey env) $ \key ->
    zeroMem key (fromIntegral @Int @CSize (lkeKeyLen env))
  finalizeMLockedForeignPtr (lkeKey env)

{-------------------------------------------------------------------------------
  Writing
-------------------------------------------------------------------------------}

-- | Produce the text envelope for the given key bytes, in exactly the layout
-- @cardano-cli@ writes (four-space indentation, the fields in the order
-- @type@, @description@, @cborHex@, a trailing newline). The first argument
-- is the algorithm name; the second selects the envelope type: 'Nothing'
-- writes 'KESKeyEvolutionZero', @'Just' period@ writes 'KESKeyWithPeriod'
-- with that absolute KES period.
--
-- The JSON text is assembled in a locked buffer and handed to the
-- continuation together with its length; it is erased once the continuation
-- returns, whether normally or by an exception. The key bytes are read from
-- the given pointer and are never copied to the heap.
writeLockedKESEnvelope ::
  (MonadST m, MonadThrow m) =>
  String ->
  Maybe Word64 ->
  Ptr CChar ->
  Int ->
  (Ptr Word8 -> Int -> m a) ->
  m a
writeLockedKESEnvelope name mPeriod key keyLen k = do
  jsonBuf <- mlAllocate mlockedMalloc (fromIntegral @Int @CSize (max 1 jsonLen))
  ( do
      unsafeIOToMonadST $ withMLockedForeignPtr jsonBuf $ \json -> do
        -- The CBOR bytes, then their hex, each in its own locked buffer.
        cborBuf <- mlAllocate mlockedMalloc (fromIntegral @Int @CSize cborLen)
        (hexBuf, hexLen) <-
          ( withMLockedForeignPtr cborBuf $ \cbor -> do
              pokeBytes cbor 0 cborPrefix
              copyMem (cbor `plusPtr` BS.length cborPrefix) (castPtr key) (fromIntegral @Int @CSize keyLen)
              hexEncodeMLocked cbor cborLen
          )
            `finally` do
              withMLockedForeignPtr cborBuf $ \cbor -> zeroMem cbor (fromIntegral @Int @CSize cborLen)
              finalizeMLockedForeignPtr cborBuf
        -- The JSON text around it.
        ( do
            pokeBytes json 0 jsonPrefix
            withMLockedForeignPtr hexBuf $ \hex ->
              copyMem (json `plusPtr` BS.length jsonPrefix) hex (fromIntegral @Int @CSize hexLen)
            pokeBytes json (BS.length jsonPrefix + hexLen) jsonSuffix
          )
          `finally` do
            withMLockedForeignPtr hexBuf $ \hex -> zeroMem hex (fromIntegral @Int @CSize hexLen)
            finalizeMLockedForeignPtr hexBuf
      withMLockedForeignPtr jsonBuf $ \json -> k json jsonLen
    )
    `finally` do
      withMLockedForeignPtr jsonBuf $ \json -> zeroMem json (fromIntegral @Int @CSize jsonLen)
      finalizeMLockedForeignPtr jsonBuf
  where
    typeString = case mPeriod of
      Nothing -> kesEvolutionZeroTypeString name
      Just _ -> kesWithPeriodTypeString name

    -- The CBOR framing in front of the key bytes: for an evolved key the
    -- two-element array header and the period, then the byte-string header.
    cborPrefix :: ByteString
    cborPrefix =
      maybe mempty (\p -> BS.singleton 0x82 <> cborUInt p) mPeriod
        <> cborByteStringHeader keyLen
    cborLen = BS.length cborPrefix + keyLen

    jsonPrefix, jsonSuffix :: ByteString
    jsonPrefix =
      BS.concat
        [ "{\n    \"type\": \""
        , typeString
        , "\",\n    \"description\": \"KES Signing Key\",\n    \"cborHex\": \""
        ]
    jsonSuffix = "\"\n}\n"
    jsonLen = BS.length jsonPrefix + 2 * cborLen + BS.length jsonSuffix

-- | Copy a (public) 'ByteString' to the given offset of a buffer.
pokeBytes :: Ptr Word8 -> Int -> ByteString -> IO ()
pokeBytes dst off bs =
  BS.unsafeUseAsCStringLen bs $ \(src, n) ->
    copyMem (dst `plusPtr` off) (castPtr src) (fromIntegral @Int @CSize n)

-- | Canonical (shortest) CBOR encoding of an unsigned integer.
cborUInt :: Word64 -> ByteString
cborUInt n = cborHead 0x00 n

-- | Canonical CBOR header of a definite-length byte string.
cborByteStringHeader :: Int -> ByteString
cborByteStringHeader n = cborHead 0x40 (fromIntegral @Int @Word64 n)

-- | A CBOR initial byte of the given major type (already shifted) with the
-- shortest argument encoding of @n@.
cborHead :: Word8 -> Word64 -> ByteString
cborHead major n
  | n < 24 = BS.singleton (major .|. fromIntegral n)
  | n < 0x100 = BS.pack [major .|. 24, fromIntegral n]
  | n < 0x10000 = BS.pack ((major .|. 25) : bigEndian 2 n)
  | n < 0x100000000 = BS.pack ((major .|. 26) : bigEndian 4 n)
  | otherwise = BS.pack ((major .|. 27) : bigEndian 8 n)
  where
    bigEndian :: Int -> Word64 -> [Word8]
    bigEndian width v = [fromIntegral (v `shiftR` (8 * i)) | i <- [width - 1, width - 2 .. 0]]

{-------------------------------------------------------------------------------
  CBOR decoding
-------------------------------------------------------------------------------}

-- | Decode the CBOR framing of a decoded @cborHex@ buffer according to the
-- envelope type: the period (for 'KESKeyWithPeriod') and the offset and
-- length of the key bytes. The whole buffer must be consumed.
decodeCbor ::
  KESEnvelopeType -> Ptr Word8 -> Int -> IO (Either KESEnvelopeError (Maybe Word64, Span))
decodeCbor envelopeType ptr len = runExceptT $ do
  (period, afterPeriod) <- case envelopeType of
    KESKeyEvolutionZero -> pure (Nothing, 0)
    KESKeyWithPeriod -> do
      -- A two-element array: period, key bytes.
      b0 <- peek8 0
      unless (b0 == 0x82) badCbor
      (p, next) <- cborArgument 0x00 1
      pure (Just p, next)
  (keyLen, keyOff) <- cborArgument 0x40 afterPeriod
  let keyLen' = fromIntegral @Word64 @Int keyLen
  unless (keyLen < fromIntegral @Int @Word64 (maxBound :: Int) && keyOff + keyLen' == len) badCbor
  pure (period, (keyOff, keyLen'))
  where
    badCbor :: ExceptT KESEnvelopeError IO a
    badCbor = throwError EnvelopeBadCbor

    peek8 :: Int -> ExceptT KESEnvelopeError IO Word8
    peek8 i
      | i < 0 || i >= len = badCbor
      | otherwise = liftIO (peekByteOff ptr i)

    -- The argument of a CBOR item of the given major type (already
    -- shifted) starting at the given offset: the value and the offset just
    -- after the head. Only definite-length forms (additional information
    -- 0..27) are accepted.
    cborArgument :: Word8 -> Int -> ExceptT KESEnvelopeError IO (Word64, Int)
    cborArgument major i = do
      b <- peek8 i
      unless (b .&. 0xe0 == major) badCbor
      let info = b .&. 0x1f
      if
        | info < 24 -> pure (fromIntegral info, i + 1)
        | info == 24 -> bigEndian 1 (i + 1)
        | info == 25 -> bigEndian 2 (i + 1)
        | info == 26 -> bigEndian 4 (i + 1)
        | info == 27 -> bigEndian 8 (i + 1)
        | otherwise -> badCbor

    bigEndian :: Int -> Int -> ExceptT KESEnvelopeError IO (Word64, Int)
    bigEndian width i = go 0 0
      where
        go !acc !j
          | j >= width = pure (acc, i + width)
          | otherwise = do
              b <- peek8 (i + j)
              go ((acc `shiftL` 8) .|. fromIntegral b) (j + 1)

{-------------------------------------------------------------------------------
  Scanning the JSON text
-------------------------------------------------------------------------------}

-- | Byte offset and length of a field value, into the raw file bytes.
type Span = (Int, Int)

-- | Where the field values of a KES signing key text envelope are.
data EnvelopeSpans = EnvelopeSpans
  { esType :: !Span
  , esCborHex :: !Span
  }

-- | Find the field values of the three-field text envelope in the raw file
-- bytes. This is a hand-rolled scanner rather than a JSON parser on purpose:
-- it only ever produces offsets, so the hex-encoded key never has to be
-- copied out of the (locked) file buffer.
--
-- Accepted: a JSON object with exactly the string members @type@,
-- @description@ and @cborHex@, in any order, with any JSON whitespace around
-- the tokens. The spans point at the raw string contents between the quotes;
-- escape sequences are skipped over but not interpreted (a value with an
-- escape in it simply fails the checks that follow).
scanKESEnvelope :: Ptr Word8 -> Int -> IO (Either KESEnvelopeError EnvelopeSpans)
scanKESEnvelope ptr len = runExceptT $ do
  start <- skipWs 0 >>= expectByte 0x7b >>= skipWs -- '{'
  (fields, afterObject) <- members start []
  end <- skipWs afterObject
  unless (end == len) notAnObject
  esType <- field "type" fields
  _ <- field "description" fields
  esCborHex <- field "cborHex" fields
  pure EnvelopeSpans {esType, esCborHex}
  where
    notAnObject :: ExceptT KESEnvelopeError IO a
    notAnObject = throwError EnvelopeNotAnObject

    -- Every read is bounds-checked; running off the end is a malformed file.
    peek8 :: Int -> ExceptT KESEnvelopeError IO Word8
    peek8 i
      | i < 0 || i >= len = notAnObject
      | otherwise = liftIO (peekByteOff ptr i)

    skipWs :: Int -> ExceptT KESEnvelopeError IO Int
    skipWs i
      | i >= len = pure i
      | otherwise = do
          b <- peek8 i
          if b == 0x20 || b == 0x0a || b == 0x0d || b == 0x09
            then skipWs (i + 1)
            else pure i

    expectByte :: Word8 -> Int -> ExceptT KESEnvelopeError IO Int
    expectByte expected i = do
      b <- peek8 i
      if b == expected then pure (i + 1) else notAnObject

    -- A string literal starting at the given offset: the span of its contents
    -- and the offset just after the closing quote.
    stringLit :: Int -> ExceptT KESEnvelopeError IO (Span, Int)
    stringLit quoteAt = do
      contentStart <- expectByte 0x22 quoteAt -- '"'
      let go i = do
            b <- peek8 i
            if
              | b == 0x22 -> pure ((contentStart, i - contentStart), i + 1)
              | b == 0x5c -> go (i + 2) -- backslash: skip the escaped byte
              | b < 0x20 -> notAnObject -- control characters are not allowed
              | otherwise -> go (i + 1)
      go contentStart

    -- The members of the object, starting just after '{' (and whitespace).
    -- Returns the named members and the offset just after the closing '}'.
    members :: Int -> [(String, Span)] -> ExceptT KESEnvelopeError IO ([(String, Span)], Int)
    members i acc = do
      b <- peek8 i
      if b == 0x7d && null acc -- '}' of an empty object
        then pure (acc, i + 1)
        else do
          (key, afterKey) <- stringLit i
          valueAt <- skipWs afterKey >>= expectByte 0x3a >>= skipWs -- ':'
          (value, afterValue) <- stringLit valueAt
          name <- fieldName key
          when (name `elem` map fst acc) notAnObject
          let acc' = (name, value) : acc
          next <- skipWs afterValue
          b' <- peek8 next
          if
            | b' == 0x2c -> skipWs (next + 1) >>= \i' -> members i' acc' -- ','
            | b' == 0x7d -> pure (acc', next + 1) -- '}'
            | otherwise -> notAnObject

    fieldName :: Span -> ExceptT KESEnvelopeError IO String
    fieldName key = do
      matches <- liftIO $ filterM (spanEquals ptr key) ["type", "description", "cborHex"]
      case matches of
        [name] -> pure name
        _ -> notAnObject

    field :: String -> [(String, Span)] -> ExceptT KESEnvelopeError IO Span
    field name fields =
      maybe (throwError (EnvelopeMissingField name)) pure (lookup name fields)

-- | Does the span hold exactly this ASCII string?
spanEquals :: Ptr Word8 -> Span -> String -> IO Bool
spanEquals ptr (off, n) s
  | n /= length s = pure False
  | otherwise =
      and <$> zipWithM (\k c -> (== fromIntegral (ord c)) <$> peekByteOff @Word8 ptr (off + k)) [0 ..] s

-- | Does the span hold exactly these bytes?
spanEqualsBS :: Ptr Word8 -> Span -> ByteString -> IO Bool
spanEqualsBS ptr (off, n) bs
  | n /= BS.length bs = pure False
  | otherwise =
      and <$> zipWithM (\k b -> (== b) <$> peekByteOff @Word8 ptr (off + k)) [0 ..] (BS.unpack bs)
