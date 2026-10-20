{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Tests for "Cardano.Crypto.KES.EnvelopeLocked": the text-envelope reader
-- and writer over locked buffers.
module Test.Crypto.EnvelopeLocked (
  tests,
)
where

import Control.Monad (forM_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Unsafe as BSU
import Data.List (isInfixOf)
import Data.Proxy (Proxy (..))
import Data.Word (Word64, Word8)
import Foreign.Ptr (castPtr)

import Cardano.Crypto.DSIGN (Ed25519DSIGN)
import Cardano.Crypto.DirectSerialise (DirectDeserialise)
import Cardano.Crypto.Hash (Blake2b_256)
import Cardano.Crypto.KES
import Cardano.Crypto.KES.EnvelopeLocked
import Cardano.Crypto.KES.Locked (deserialiseSignKeyKESFromLockedBuf)
import Cardano.Crypto.Libsodium.Hex (HexDecodeError (..))
import Cardano.Crypto.Libsodium.Memory (
  packByteStringCStringLen,
  withMLockedForeignPtr,
 )
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)

import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

import Test.Crypto.Instances (withMLockedSeedFromPSB)
import Test.Crypto.Util (Lock, withLock)

tests :: Lock -> Spec
tests lock =
  describe "KES.EnvelopeLocked" $ do
    describe "type strings" $ do
      it "are the cardano-cli type and its period-carrying sibling" $ do
        kesEvolutionZeroTypeString "ed25519_kes_2^6" `shouldBe` "KesSigningKey_ed25519_kes_2^6"
        kesWithPeriodTypeString "ed25519_kes_2^6" `shouldBe` "KesSigningKeyWithPeriod_ed25519_kes_2^6"
    describe "fixture" $ do
      it "reads the kes-agent fixture as an evolution-zero key of 608 bytes" $ do
        r <- withLock lock $ readEnvelope fixtureAlgorithm fixtureFile
        r `shouldBe` Right (KESKeyEvolutionZero, Nothing, fixtureKeyBytes)
      it "writes the fixture key back byte for byte" $ do
        written <- withLock lock $ writeEnvelope fixtureAlgorithm Nothing fixtureKeyBytes
        written `shouldBe` fixtureFile
      it "writes the fixture key with a period in the same layout" $ do
        written <- withLock lock $ writeEnvelope fixtureAlgorithm (Just 300) fixtureKeyBytes
        written
          `shouldBe` cardanoCliLayout
            (kesWithPeriodTypeString fixtureAlgorithm)
            (Base16.encode (BS.pack [0x82, 0x19, 0x01, 0x2c, 0x59, 0x02, 0x60] <> fixtureKeyBytes))
    describe "round trips" $ do
      roundTrips @(Sum1KES Ed25519DSIGN Blake2b_256) lock "Sum1KES"
      roundTrips @(Sum5KES Ed25519DSIGN Blake2b_256) lock "Sum5KES"
      roundTrips @(CompactSum5KES Ed25519DSIGN Blake2b_256) lock "CompactSum5KES"
      prop "any period and any key length survive write then read" $
        \(period :: Word64) (bytes :: [Word8]) ->
          ioProperty . withLock lock $ do
            let key = BS.pack bytes
            written <- writeEnvelope fixtureAlgorithm (Just period) key
            r <- readEnvelope fixtureAlgorithm written
            return $ r === Right (KESKeyWithPeriod, Just period, key)
      prop "the canonical CBOR integer encoding is used for the period" $
        \(period :: Word64) ->
          ioProperty . withLock lock $ do
            written <- writeEnvelope fixtureAlgorithm (Just period) "k"
            let expectedCbor = BS.pack ([0x82] ++ canonicalUInt period ++ [0x41, 0x6b])
            return $
              written === cardanoCliLayout (kesWithPeriodTypeString fixtureAlgorithm) (Base16.encode expectedCbor)
    describe "accepted layouts" $ do
      it "reads a compact, a reordered and an upper-case-hex envelope" $ do
        let hex = Base16.encode (cborBytes fixtureKeyBytes)
            compact =
              "{\"type\":\""
                <> kesEvolutionZeroTypeString fixtureAlgorithm
                <> "\",\"description\":\"KES Signing Key\",\"cborHex\":\""
                <> hex
                <> "\"}"
            reordered =
              BS.concat
                [ "\n\t{ \"cborHex\" :\r\n \"" <> hex <> "\" ,\n"
                , "  \"description\": \"\",\n"
                , "  \"type\":\"" <> kesEvolutionZeroTypeString fixtureAlgorithm <> "\"\n\n}\n\n"
                ]
            upper = cardanoCliLayout (kesEvolutionZeroTypeString fixtureAlgorithm) (BC.map toUpperHex hex)
        forM_ [compact, reordered, upper] $ \file -> do
          r <- withLock lock $ readEnvelope fixtureAlgorithm file
          r `shouldBe` Right (KESKeyEvolutionZero, Nothing, fixtureKeyBytes)
      it "accepts every definite-length CBOR integer and byte-string form" $ do
        let key = BS.replicate 30 0xab
            forms =
              [ (BS.pack [0x82, 0x05, 0x58, 30] <> key, Just 5)
              , (BS.pack [0x82, 0x18, 0x05, 0x58, 30] <> key, Just 5)
              , (BS.pack [0x82, 0x19, 0x00, 0x05, 0x59, 0x00, 30] <> key, Just 5)
              , (BS.pack [0x82, 0x1a, 0, 0, 0, 5, 0x5a, 0, 0, 0, 30] <> key, Just 5)
              , (BS.pack [0x82, 0x1b, 0, 0, 0, 0, 0, 0, 0, 5, 0x5b, 0, 0, 0, 0, 0, 0, 0, 30] <> key, Just 5)
              ,
                ( BS.pack [0x82, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x58, 30] <> key
                , Just maxBound
                )
              ]
        forM_ forms $ \(cbor, period) -> do
          r <-
            withLock lock $
              readEnvelope fixtureAlgorithm $
                cardanoCliLayout (kesWithPeriodTypeString fixtureAlgorithm) (Base16.encode cbor)
          r `shouldBe` Right (KESKeyWithPeriod, period, key)
      it "accepts an empty byte string" $ do
        r <-
          withLock lock $
            readEnvelope fixtureAlgorithm $
              cardanoCliLayout (kesEvolutionZeroTypeString fixtureAlgorithm) "40"
        r `shouldBe` Right (KESKeyEvolutionZero, Nothing, "")
    describe "rejections" $ do
      let hex = Base16.encode (cborBytes fixtureKeyBytes)
          ty = kesEvolutionZeroTypeString fixtureAlgorithm
          secrets = [fixtureHex, BS.take 32 fixtureHex, "KES Signing Key", ty]
          rejects file expected = do
            r <- withLock lock $ readEnvelope fixtureAlgorithm file
            r `shouldBe` Left expected
            forM_ secrets $ \secret ->
              show r `shouldSatisfy` (not . (BC.unpack secret `isInfixOf`))
      it "rejects an unknown type and a wrong algorithm name" $ do
        rejects (cardanoCliLayout "KesSigningKey_bogus_kes_2^6" hex) EnvelopeUnknownType
        rejects (cardanoCliLayout "SigningKey_ed25519_kes_2^6" hex) EnvelopeUnknownType
        rejects (cardanoCliLayout "" hex) EnvelopeUnknownType
        r <- withLock lock $ readEnvelope "ed25519_kes_2^5" (cardanoCliLayout ty hex)
        r `shouldBe` Left EnvelopeUnknownType
      it "rejects a missing field" $ do
        rejects
          ("{\"description\":\"KES Signing Key\",\"cborHex\":\"" <> hex <> "\"}")
          (EnvelopeMissingField "type")
        rejects
          ("{\"type\":\"" <> ty <> "\",\"cborHex\":\"" <> hex <> "\"}")
          (EnvelopeMissingField "description")
        rejects
          ("{\"type\":\"" <> ty <> "\",\"description\":\"KES Signing Key\"}")
          (EnvelopeMissingField "cborHex")
        rejects "{}" (EnvelopeMissingField "type")
      it "rejects anything but the three-field object" $ do
        let good = cardanoCliLayout ty hex
            files =
              [ "" -- empty file
              , "[]" -- not an object
              , BS.init (BS.init good) -- closing brace missing
              , good <> "{}" -- trailing garbage
              , "{\"type\":\""
                  <> ty
                  <> "\",\"type\":\""
                  <> ty
                  <> "\",\"description\":\"\",\"cborHex\":\""
                  <> hex
                  <> "\"}" -- duplicate
              , "{\"type\":\"" <> ty <> "\",\"description\":\"\",\"cborHex\":\"" <> hex <> "\",\"extra\":\"\"}" -- unknown field
              , "{\"type\":\"" <> ty <> "\",\"description\":\"\",\"cborHex\":\"" <> hex <> "\",}" -- trailing comma
              , "{\"type\":\"" <> ty <> "\",\"description\":null,\"cborHex\":\"" <> hex <> "\"}" -- non-string value
              , "{\"type\":\"" <> ty <> "\",\"description\":\"a\nb\",\"cborHex\":\"" <> hex <> "\"}" -- control character
              ]
        forM_ files $ \file -> rejects file EnvelopeNotAnObject
      it "rejects bad hex and reports the position" $ do
        rejects (cardanoCliLayout ty (BS.init hex)) (EnvelopeBadHex (HexOddLength (BS.length hex - 1)))
        rejects
          (cardanoCliLayout ty (BS.take 100 hex <> "g" <> BS.drop 101 hex))
          (EnvelopeBadHex (HexInvalidByteAt 100))
      it "rejects CBOR that is not one byte string spanning the value (evolution zero)" $ do
        let raw = fixtureHex
            shapes =
              [ Base16.encode (BS.pack [0x59, 0x02, 0x60]) <> BS.take (BS.length raw - 2) raw -- short payload
              , "81" <> hex -- an array
              , "00" <> raw -- not a byte string
              , "82" <> "00" <> hex -- the period-carrying layout under the evolution-zero type
              , "5f" <> hex <> "ff" -- indefinite-length byte string
              , "" -- nothing at all
              , hex <> "00" -- trailing byte
              ]
        forM_ shapes $ \cborHex -> rejects (cardanoCliLayout ty cborHex) EnvelopeBadCbor
      it "rejects CBOR that is not [uint, bytes] (with period)" $ do
        let tyP = kesWithPeriodTypeString fixtureAlgorithm
            shapes =
              [ hex -- the evolution-zero layout under the period-carrying type
              , "83" <> "00" <> hex <> "00" -- arity 3
              , "81" <> hex -- arity 1
              , "82" <> "20" <> hex -- negative period
              , "82" <> "fb3ff0000000000000" <> hex -- float period
              , "82" <> "6130" <> hex -- string period
              , "82" <> "1c" <> hex -- reserved additional information
              , "82" <> "00" <> "5f" <> hex <> "ff" -- indefinite byte string
              , "9f" <> "00" <> hex <> "ff" -- indefinite array
              , "82" <> "00" <> hex <> "00" -- trailing byte
              , "82" <> "00" -- missing byte string
              , "82" <> "1900" -- truncated period
              ]
        forM_ shapes $ \cborHex -> do
          r <- withLock lock $ readEnvelope fixtureAlgorithm (cardanoCliLayout tyP cborHex)
          r `shouldBe` Left EnvelopeBadCbor

{-------------------------------------------------------------------------------
  Round trips through real keys
-------------------------------------------------------------------------------}

roundTrips ::
  forall v.
  ( UnsoundKESAlgorithm v
  , DirectDeserialise (SignKeyKES v)
  ) =>
  Lock ->
  String ->
  Spec
roundTrips lock name =
  describe name $ do
    prop "write then read gives back the key, at evolution 0 and with a period" $
      \(seedPSB :: PinnedSizedBytes (SeedSizeKES v)) (period :: Word64) ->
        ioProperty . withLock lock $ withMLockedSeedFromPSB seedPSB $ \seed -> do
          sk <- genKeyKES @v seed
          vk <- deriveVerKeyKES sk
          raw <- rawSerialiseSignKeyKES sk
          forgetSignKeyKES sk
          results <- mapM' [(Nothing, KESKeyEvolutionZero), (Just period, KESKeyWithPeriod)] $
            \(mPeriod, expectedType) -> do
              written <- writeEnvelope (algorithmNameKES (Proxy @v)) mPeriod raw
              r <- readKeyEnvelope @v (algorithmNameKES (Proxy @v)) written
              return $ case r of
                Left err -> counterexample ("read failed: " ++ show err) False
                Right (ty, p, bytes, vk') ->
                  (ty === expectedType)
                    .&&. (p === mPeriod)
                    .&&. (bytes === raw)
                    .&&. (vk' === vk)
          return (conjoin results)
  where
    mapM' xs f = mapM f xs

{-------------------------------------------------------------------------------
  Helpers
-------------------------------------------------------------------------------}

-- | Read an envelope from a (heap) 'ByteString' and copy the key bytes back
-- out (tests only), releasing the locked buffer.
readEnvelope ::
  String -> ByteString -> IO (Either KESEnvelopeError (KESEnvelopeType, Maybe Word64, ByteString))
readEnvelope name file =
  BSU.unsafeUseAsCStringLen file $ \(ptr, len) -> do
    r <- readLockedKESEnvelope name (castPtr ptr) len
    case r of
      Left err -> return (Left err)
      Right env -> do
        bytes <-
          withMLockedForeignPtr (lkeKey env) $ \key ->
            packByteStringCStringLen (key, lkeKeyLen env)
        finalizeLockedKESEnvelope env
        return (Right (lkeType env, lkePeriod env, bytes))

-- | Like 'readEnvelope', but also builds the key from the locked buffer and
-- returns its verification key.
readKeyEnvelope ::
  forall v.
  (KESAlgorithm v, DirectDeserialise (SignKeyKES v)) =>
  String ->
  ByteString ->
  IO (Either KESEnvelopeError (KESEnvelopeType, Maybe Word64, ByteString, VerKeyKES v))
readKeyEnvelope name file =
  BSU.unsafeUseAsCStringLen file $ \(ptr, len) -> do
    r <- readLockedKESEnvelope name (castPtr ptr) len
    case r of
      Left err -> return (Left err)
      Right env -> do
        bytes <-
          withMLockedForeignPtr (lkeKey env) $ \key ->
            packByteStringCStringLen (key, lkeKeyLen env)
        sk <-
          withMLockedForeignPtr (lkeKey env) $ \key ->
            deserialiseSignKeyKESFromLockedBuf @v key (lkeKeyLen env)
        finalizeLockedKESEnvelope env
        vk <- deriveVerKeyKES sk
        forgetSignKeyKES sk
        return (Right (lkeType env, lkePeriod env, bytes, vk))

-- | Write an envelope for (heap) key bytes and copy the JSON text back out
-- (tests only).
writeEnvelope :: String -> Maybe Word64 -> ByteString -> IO ByteString
writeEnvelope name mPeriod key =
  BSU.unsafeUseAsCStringLen key $ \(ptr, len) ->
    writeLockedKESEnvelope name mPeriod ptr len $ \json jsonLen ->
      packByteStringCStringLen (castPtr json, jsonLen)

-- | The layout @cardano-cli@ writes.
cardanoCliLayout :: ByteString -> ByteString -> ByteString
cardanoCliLayout ty cborHex =
  BS.concat
    [ "{\n"
    , "    \"type\": \"" <> ty <> "\",\n"
    , "    \"description\": \"KES Signing Key\",\n"
    , "    \"cborHex\": \"" <> cborHex <> "\"\n"
    , "}\n"
    ]

-- | A definite-length CBOR byte string (for payloads below 64 KiB).
cborBytes :: ByteString -> ByteString
cborBytes bs
  | n < 24 = BS.singleton (0x40 + fromIntegral n) <> bs
  | n < 256 = BS.pack [0x58, fromIntegral n] <> bs
  | otherwise = BS.pack [0x59, fromIntegral (n `div` 256), fromIntegral (n `mod` 256)] <> bs
  where
    n = BS.length bs

-- | The canonical CBOR encoding of an unsigned integer, as a list of bytes.
canonicalUInt :: Word64 -> [Word8]
canonicalUInt n
  | n < 24 = [fromIntegral n]
  | n < 0x100 = [0x18, fromIntegral n]
  | n < 0x10000 = 0x19 : be 2
  | n < 0x100000000 = 0x1a : be 4
  | otherwise = 0x1b : be 8
  where
    be w = [fromIntegral ((n `div` (256 ^ i)) `mod` 256) | i <- [w - 1, w - 2 .. 0 :: Int]]

toUpperHex :: Char -> Char
toUpperHex c
  | c >= 'a' && c <= 'f' = toEnum (fromEnum c - 32)
  | otherwise = c

{-------------------------------------------------------------------------------
  The kes-agent fixture (public test data: kes-agent/fixtures/kes.skey)
-------------------------------------------------------------------------------}

fixtureAlgorithm :: String
fixtureAlgorithm = "ed25519_kes_2^6"

fixtureFile :: ByteString
fixtureFile = cardanoCliLayout (kesEvolutionZeroTypeString fixtureAlgorithm) ("590260" <> fixtureHex)

fixtureKeyBytes :: ByteString
fixtureKeyBytes = either error id (Base16.decode fixtureHex)

-- | The 608 key bytes of the fixture, hex encoded.
fixtureHex :: ByteString
fixtureHex =
  BS.concat
    [ "5ab3db7b77d85f1a73148569454b0819ef293aaac20d04a63eb4857ab5c3505a098e346272c650e2c7e4f9929cf00bc4"
    , "39f37c4e5df5dcc35b6089acae7a4f8b465f4b5651600117b9c9063f7d45d0b6d7949db2c34cbfeeff51e0f91402fae2"
    , "b54b1c53adb0ac2a2cbcae5f7734e0133a20f5ec2004fa15eeab0eb6db6cd7a6f0a0f1675c6b9752907e3dd2217063a2"
    , "6d0ddf5993a53bee061f3cfef244397c25b02e06d720050286985db6c799be394838d8278f919c9aae2b462b4bde63af"
    , "12671a6366081ed216c70def81197e6e0880e67ed9c47f3291874e7cd4e1d4b74aa536f915fabc6c72aeb2d317da9b27"
    , "64666ad14345c2b4b6bbadc933d49de11bce1c65ae608043698b921044dcc23d8c668d21b2eb4befe5661975c1e404c3"
    , "dbe79d16616912d3051cc9cbd70dfe68dc233ed79467599646b359889883356d701cb4fb5e7901fa7f27a5125a90f37d"
    , "dfe92f8f1a8174d57904bbd92dc262d237d5d2376fe0c4c51317b45ed5ae609c40f76c7486f88bedfdb6cff5511a31bb"
    , "f9b025007a3db4af6dea85258bc29f1edf48d3518a70cdf1cf015f71f27c7cee50fd8f4bdc72356cda761368120cfdcc"
    , "64596d799076638cb808ea461d70504ea53e2b58bfcae424c1d85cb48118b8fb36b7bb4af2290734e114dda638079fca"
    , "4086e15b4e6a696e8884e1dc07c83fb3d7b414ed3cb082197a9ef4cd964385c5b189e679bbf3ba61f5def069e4bf8033"
    , "56439f662f41b32d84998b4ac80916428a70f09038a460860d4c2f1cf111a307e41319408c7d2c5dfb483eda32cbc377"
    , "9c5d8ceadf30ec3f91c2a485279ae8744e9c8fb3c574e22a73a30ffd341778c8"
    ]
