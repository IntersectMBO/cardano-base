{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Test.Crypto.Util (
  -- * CBOR
  FromCBOR (..),
  ToCBOR (..),
  prop_cbor,
  prop_cbor_size,
  prop_cbor_with,
  prop_cbor_valid,
  prop_cbor_roundtrip,
  prop_raw_serialise,
  prop_raw_deserialise,
  prop_size_serialise,
  prop_cbor_direct_vs_class,
  prop_bad_cbor_bytes,

  -- * NoThunks
  prop_no_thunks,
  prop_no_thunks_IO,
  prop_no_thunks_IO_from,
  prop_no_thunks_IO_with,

  -- * Test Seed
  TestSeed (..),
  withTestSeed,
  testSeedToChaCha,
  nullTestSeed,

  -- * Seeds
  SizedSeed,
  unSizedSeed,
  arbitrarySeedOfSize,
  arbitrarySeedBytesOfSize,

  -- * test messages for signings
  Message (..),

  -- * Test generation and shrinker helpers
  BadInputFor,
  genBadInputFor,
  shrinkBadInputFor,
  showBadInputFor,

  -- * Formatting
  hexBS,

  -- * Helpers for testing IO actions
  noExceptionsThrown,
  doesNotThrow,

  -- * Direct ser/deser helpers
  directSerialiseToBS,
  directDeserialiseFromBS,

  -- * Error handling
  eitherShowError,

  -- * Locking
  Lock,
  withLock,
  mkLock,
)
where

import Cardano.Binary (
  Decoder,
  Encoding,
  FromCBOR (fromCBOR),
  Range (Range),
  ToCBOR (toCBOR),
  decodeFull,
  decodeFullDecoder,
  encodedSizeExpr,
  hi,
  lo,
  serialize,
  szGreedy,
  szSimplify,
 )
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (SigDSIGN, SignKeyDSIGN, VerKeyDSIGN),
  sizeSigDSIGN,
  sizeSignKeyDSIGN,
  sizeVerKeyDSIGN,
 )
import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.Hash.Class (Hash, HashAlgorithm, sizeHash)
import Cardano.Crypto.Libsodium.Memory (
  allocaBytes,
  packByteStringCStringLen,
  unpackByteStringCStringLen,
 )
import Cardano.Crypto.Seed (Seed, mkSeedFromBytes)
import Cardano.Crypto.Util (SignableRepresentation (..))
import Codec.CBOR.FlatTerm (
  toFlatTerm,
  validFlatTerm,
 )
import Codec.CBOR.Write (
  toStrictByteString,
 )
import Control.Concurrent.Class.MonadMVar (
  MVar,
  newMVar,
  withMVar,
 )
import Control.Monad (guard, when)
import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow)
import Crypto.Random (
  ChaChaDRG,
  MonadPseudoRandom,
  drgNewTest,
  withDRG,
 )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Data.Kind (Type)
import Data.Proxy (Proxy (Proxy))
import Data.Word (Word64)
import Formatting.Buildable (Buildable (..), build)
import GHC.Exts (fromList, fromListN, toList)
import GHC.Stack (HasCallStack)
import GHC.TypeLits (KnownNat, Nat, natVal)
import NoThunks.Class (NoThunks, noThunks, unsafeNoThunks)
import Numeric.Natural (Natural)
import Test.QuickCheck (
  Arbitrary,
  Gen,
  Property,
  arbitrary,
  arbitraryBoundedIntegral,
  checkCoverage,
  counterexample,
  cover,
  forAllBlind,
  ioProperty,
  property,
  shrink,
  vector,
  (.&&.),
  (===),
 )
import qualified Test.QuickCheck.Gen as Gen
import Text.Show.Pretty (ppShow)

--------------------------------------------------------------------------------
-- Connecting MonadRandom to Gen
--------------------------------------------------------------------------------
newtype TestSeed
  = TestSeed
  { getTestSeed :: (Word64, Word64, Word64, Word64, Word64)
  }
  deriving (Show, Eq, Ord, FromCBOR, ToCBOR)

withTestSeed :: TestSeed -> MonadPseudoRandom ChaChaDRG a -> a
withTestSeed s = fst . withDRG (drgNewTest $ getTestSeed s)

testSeedToChaCha :: TestSeed -> ChaChaDRG
testSeedToChaCha = drgNewTest . getTestSeed

nullTestSeed :: TestSeed
nullTestSeed = TestSeed (0, 0, 0, 0, 0)

instance Arbitrary TestSeed where
  arbitrary =
    TestSeed <$> ((,,,,) <$> gen <*> gen <*> gen <*> gen <*> gen)
    where
      gen :: Gen Word64
      gen = arbitraryBoundedIntegral
  shrink = const []

--------------------------------------------------------------------------------
-- Seeds
--------------------------------------------------------------------------------

newtype SizedSeed (n :: Nat) = SizedSeed {unSizedSeed :: Seed} deriving (Show)

instance KnownNat n => Arbitrary (SizedSeed n) where
  arbitrary = SizedSeed <$> arbitrarySeedOfSize (fromIntegral $ natVal (Proxy :: Proxy n))

arbitrarySeedOfSize :: Word -> Gen Seed
arbitrarySeedOfSize sz =
  mkSeedFromBytes <$> arbitrarySeedBytesOfSize sz

arbitrarySeedBytesOfSize :: Word -> Gen ByteString
arbitrarySeedBytesOfSize sz =
  BS.pack <$> vector (fromIntegral sz)

--------------------------------------------------------------------------------
-- Messages to sign
--------------------------------------------------------------------------------

newtype Message = Message {messageBytes :: ByteString}
  deriving (Eq, Show, SignableRepresentation)

instance Arbitrary Message where
  arbitrary = Message . BS.pack <$> arbitrary
  shrink = map (Message . BS.pack) . shrink . BS.unpack . messageBytes

--------------------------------------------------------------------------------
-- Serialisation properties
--------------------------------------------------------------------------------

prop_cbor ::
  (ToCBOR a, FromCBOR a, Eq a, Show a) =>
  a -> Property
prop_cbor = prop_cbor_with toCBOR fromCBOR

prop_cbor_size :: forall a. ToCBOR a => a -> Property
prop_cbor_size a =
  counterexample (show lo ++ " ≰ " ++ show len) (lo <= len)
    .&&. counterexample (show len ++ " ≰ " ++ show hi) (len <= hi)
  where
    len, lo, hi :: Natural
    len = fromIntegral $ BS.length (toStrictByteString (toCBOR a))
    Range {lo, hi} =
      case szSimplify $ encodedSizeExpr szGreedy (Proxy :: Proxy a) of
        Right x -> x
        Left err -> error . show . build $ err

prop_cbor_with ::
  (Eq a, Show a) =>
  (a -> Encoding) ->
  (forall s. Decoder s a) ->
  a ->
  Property
prop_cbor_with encoder decoder x =
  prop_cbor_valid encoder x
    .&&. prop_cbor_roundtrip encoder decoder x

prop_cbor_valid :: (a -> Encoding) -> a -> Property
prop_cbor_valid encoder x =
  counterexample errmsg $
    validFlatTerm term
  where
    term = toFlatTerm encoding
    encoding = encoder x
    errmsg =
      "invalid flat term "
        ++ show term
        ++ " from encoding "
        ++ show encoding

-- Written like this so that an Eq DeserialiseFailure is not required.
prop_cbor_roundtrip ::
  (Eq a, Show a) =>
  (a -> Encoding) ->
  (forall s. Decoder s a) ->
  a ->
  Property
prop_cbor_roundtrip encoder decoder x =
  case decodeFullDecoder "" decoder (serialize (encoder x)) of
    Right y -> y === x
    Left err -> counterexample (show err) (property False)

prop_raw_serialise ::
  (Eq a, Show a) =>
  (a -> ByteString) ->
  (ByteString -> Maybe a) ->
  a ->
  Property
prop_raw_serialise serialise deserialise x =
  case deserialise (serialise x) of
    Just y -> y === x
    Nothing -> property False

prop_raw_deserialise ::
  forall (a :: Type).
  Show a =>
  (ByteString -> Maybe a) ->
  BadInputFor a ->
  Property
prop_raw_deserialise deserialise (BadInputFor forbiddenLen bs) =
  checkCoverage
    . cover 50.0 (BS.length bs > forbiddenLen) "too long"
    . cover 50.0 (BS.length bs < forbiddenLen) "too short"
    $ case deserialise bs of
      Nothing -> property True
      Just x -> counterexample (ppShow x) False

prop_bad_cbor_bytes ::
  forall (a :: Type).
  (Show a, FromCBOR a) =>
  BadInputFor a ->
  Property
prop_bad_cbor_bytes (BadInputFor forbiddenLen bs) =
  checkCoverage
    . cover 50.0 (BS.length bs > forbiddenLen) "too long"
    . cover 50.0 (BS.length bs < forbiddenLen) "too short"
    $ case decodeFull (serialize bs) of
      Left _ -> property True
      Right (x :: a) -> counterexample ("FromCBOR: \n" <> ppShow x) False

-- | The crypto algorithm classes have direct encoding functions, and the key
-- types are also typically a member of the 'ToCBOR' class. Where a 'ToCBOR'
-- instance is provided then these should match.
prop_cbor_direct_vs_class ::
  ToCBOR a =>
  (a -> Encoding) ->
  a ->
  Property
prop_cbor_direct_vs_class encoder x =
  toFlatTerm (encoder x) === toFlatTerm (toCBOR x)

prop_size_serialise :: (a -> ByteString) -> Word -> a -> Property
prop_size_serialise serialise size x =
  BS.length (serialise x) === fromIntegral size

--------------------------------------------------------------------------------
-- NoThunks
--------------------------------------------------------------------------------

-- | When forcing the given value to WHNF, it may no longer contain thunks.
prop_no_thunks :: NoThunks a => a -> Property
prop_no_thunks !a = case unsafeNoThunks a of
  Nothing -> property True
  Just msg -> counterexample (show msg) (property False)

prop_no_thunks_IO :: NoThunks a => IO a -> IO Property
prop_no_thunks_IO a =
  a >>= noThunks [] >>= \case
    Nothing -> return $ property True
    Just msg -> return $! counterexample (show msg) $! property False

prop_no_thunks_IO_from :: NoThunks a => (b -> IO a) -> b -> Property
prop_no_thunks_IO_from mkX y = ioProperty $ do
  prop_no_thunks_IO (mkX y)

prop_no_thunks_IO_with :: NoThunks a => Gen (IO a) -> Property
prop_no_thunks_IO_with mkX =
  forAllBlind mkX (ioProperty . prop_no_thunks_IO)

--------------------------------------------------------------------------------
-- Helpers for property testing
--------------------------------------------------------------------------------

-- Essentially a ByteString carrying around the length it's not allowed to be.
-- This is annoying, but so's QuickCheck sometimes.
data BadInputFor (a :: Type) = BadInputFor
  { _badInputExpectedLength :: Int
  , _badInputBytes :: ByteString
  }
  deriving (Eq)

instance Show (BadInputFor a) where
  show = showBadInputFor

instance HashAlgorithm h => Arbitrary (BadInputFor (Hash h a)) where
  arbitrary = genBadInputFor (fromIntegral (sizeHash (Proxy :: Proxy h)))
  shrink = shrinkBadInputFor

instance DSIGNAlgorithm v => Arbitrary (BadInputFor (VerKeyDSIGN v)) where
  arbitrary = genBadInputFor (fromIntegral (sizeVerKeyDSIGN (Proxy :: Proxy v)))
  shrink = shrinkBadInputFor

instance DSIGNAlgorithm v => Arbitrary (BadInputFor (SignKeyDSIGN v)) where
  arbitrary = genBadInputFor (fromIntegral (sizeSignKeyDSIGN (Proxy :: Proxy v)))
  shrink = shrinkBadInputFor

instance DSIGNAlgorithm v => Arbitrary (BadInputFor (SigDSIGN v)) where
  arbitrary = genBadInputFor (fromIntegral (sizeSigDSIGN (Proxy :: Proxy v)))
  shrink = shrinkBadInputFor

-- Coercion around a phantom parameter here is dangerous, as there's an implicit
-- relation between it and the forbidden length. We ensure this is impossible.
type role BadInputFor nominal

-- Needed instead of an Arbitrary instance, as there's no (good) way of knowing
-- what our forbidden (i.e. correct) length is.
genBadInputFor ::
  forall (a :: Type).
  Int ->
  Gen (BadInputFor a)
genBadInputFor forbiddenLen =
  BadInputFor forbiddenLen <$> Gen.oneof [tooLow, tooHigh]
  where
    tooLow :: Gen ByteString
    tooLow = do
      len <- Gen.chooseInt (0, forbiddenLen - 1)
      fromListN len <$> Gen.vectorOf len arbitrary
    tooHigh :: Gen ByteString
    tooHigh = do
      len <- Gen.chooseInt (forbiddenLen + 1, forbiddenLen * 2)
      fromListN len <$> Gen.vectorOf len arbitrary

-- This ensures we don't \'shrink out of case\': we shrink too-longs to
-- (smaller) too-longs, and too-shorts to (smaller) too-shorts.
shrinkBadInputFor ::
  forall (a :: Type).
  BadInputFor a ->
  [BadInputFor a]
shrinkBadInputFor (BadInputFor len bs) =
  BadInputFor len <$> do
    bs' <- fromList <$> shrink (toList bs)
    when (BS.length bs > len) (guard (BS.length bs' > len))
    pure bs'

-- This shows only the ByteString, in hex.
showBadInputFor ::
  forall (a :: Type).
  BadInputFor a ->
  String
showBadInputFor (BadInputFor len bs) =
  "BadInputFor [Expected length: " <> show len <> ", Bytes: " <> hexBS bs <> "]"

hexBS :: ByteString -> String
hexBS bs =
  "0x" <> BS8.unpack (Base16.encode bs) <> " (length " <> show (BS.length bs) <> ")"

-- | Return a property that always succeeds in some monad (typically 'IO').
-- This is useful to express that we are only interested in whether the side
-- effects of the preceding actions caused any exceptions or not - if they
-- did, then the test will fail because of it, but if they did not, then
-- 'noExceptionsThrown' will be reached, and the test will succeed.
noExceptionsThrown :: Applicative m => m Property
noExceptionsThrown = pure (property True)

-- | Chain monadic action with 'noExceptionsThrown' to express that we only
-- want to make sure that the action does not throw any exceptions, but we are
-- not interested in its result.
doesNotThrow :: Applicative m => m a -> m Property
doesNotThrow = (*> noExceptionsThrown)

newtype Lock = Lock (MVar IO ())

withLock :: Lock -> IO a -> IO a
withLock (Lock v) = withMVar v . const

mkLock :: IO Lock
mkLock = Lock <$> newMVar ()

eitherShowError :: (HasCallStack, Show e) => Either e a -> IO a
eitherShowError (Left e) = error (show e)
eitherShowError (Right a) = return a

--------------------------------------------------------------------------------
-- Helpers for direct ser/deser
--------------------------------------------------------------------------------

directSerialiseToBS ::
  forall m a.
  DirectSerialise a =>
  MonadST m =>
  MonadThrow m =>
  Int ->
  a ->
  m ByteString
directSerialiseToBS dstsize val = do
  allocaBytes dstsize $ \dst -> do
    directSerialiseBufChecked dst dstsize val
    packByteStringCStringLen (dst, fromIntegral dstsize)

directDeserialiseFromBS ::
  forall m a.
  DirectDeserialise a =>
  MonadST m =>
  MonadThrow m =>
  ByteString ->
  m a
directDeserialiseFromBS bs = do
  unpackByteStringCStringLen bs $ \(src, srcsize) -> do
    directDeserialiseBufChecked src srcsize
