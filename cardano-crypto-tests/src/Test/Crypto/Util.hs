{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DataKinds #-}

module Test.Crypto.Util
  ( -- * CBOR
    FromCBOR (..)
  , ToCBOR (..)
  , prop_cbor
  , prop_cbor_size
  , prop_cbor_with
  , prop_cbor_valid
  , prop_cbor_roundtrip
  , prop_raw_serialise
  , prop_raw_deserialise
  , prop_size_serialise
  , prop_cbor_direct_vs_class

    -- * NoThunks
  , prop_no_thunks

    -- * Test Seed
  , TestSeed (..)
  , withTestSeed
  , testSeedToChaCha
  , nullTestSeed

    -- * Seeds
  , SizedSeed
  , unSizedSeed
  , arbitrarySeedOfSize

   -- * test messages for signings
  , Message(..)

    -- * Test generation and shrinker helpers
  , BadInputFor
  , genBadInputFor
  , shrinkBadInputFor
  , showBadInputFor
  )
where

import Numeric (showHex)
import GHC.Exts (fromListN, fromList, toList)
import Text.Show.Pretty (ppShow)
import Data.Kind (Type)
import Cardano.Binary (
  FromCBOR (fromCBOR),
  ToCBOR (toCBOR),
  Encoding,
  Decoder,
  Range (Range),
  decodeFullDecoder,
  serializeEncoding,
  szGreedy,
  szSimplify,
  lo,
  hi,
  encodedSizeExpr
  )
import Codec.CBOR.FlatTerm  (
  validFlatTerm,
  toFlatTerm
  )
import Codec.CBOR.Write (
  toStrictByteString
  )
import Cardano.Crypto.Seed (Seed, mkSeedFromBytes)
import Cardano.Crypto.Util (SignableRepresentation(..))
import Crypto.Random
  ( ChaChaDRG
  , MonadPseudoRandom
  , drgNewTest
  , withDRG
  )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (Proxy))
import Data.Word (Word64)
import NoThunks.Class (NoThunks, unsafeNoThunks)
import Numeric.Natural (Natural)
import Test.QuickCheck
  ( (.&&.)
  , (===)
  , Arbitrary
  , Gen
  , Property
  , arbitrary
  , arbitraryBoundedIntegral
  , counterexample
  , property
  , shrink
  , vector
  , checkCoverage
  , cover
  )
import Formatting.Buildable (build)
import qualified Test.QuickCheck.Gen as Gen
import Control.Monad (guard, when)
import GHC.TypeLits (Nat, KnownNat, natVal)

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

newtype SizedSeed (n :: Nat) = SizedSeed { unSizedSeed :: Seed } deriving Show

instance (KnownNat n) => Arbitrary (SizedSeed n) where
    arbitrary = SizedSeed <$> arbitrarySeedOfSize (fromIntegral $ natVal (Proxy :: Proxy n))

arbitrarySeedOfSize :: Word -> Gen Seed
arbitrarySeedOfSize sz = mkSeedFromBytes . BS.pack <$> vector (fromIntegral sz)

--------------------------------------------------------------------------------
-- Messages to sign
--------------------------------------------------------------------------------

newtype Message = Message { messageBytes :: ByteString }
  deriving (Eq, Show, SignableRepresentation)

instance Arbitrary Message where
  arbitrary = Message . BS.pack <$> arbitrary
  shrink    = map (Message . BS.pack) . shrink . BS.unpack . messageBytes

--------------------------------------------------------------------------------
-- Serialisation properties
--------------------------------------------------------------------------------

prop_cbor :: (ToCBOR a, FromCBOR a, Eq a, Show a)
          => a -> Property
prop_cbor = prop_cbor_with toCBOR fromCBOR

prop_cbor_size :: forall a. ToCBOR a => a -> Property
prop_cbor_size a = counterexample (show lo ++ " ≰ " ++ show len) (lo <= len)
              .&&. counterexample (show len ++ " ≰ " ++ show hi) (len <= hi)
  where
    len, lo, hi :: Natural
    len = fromIntegral $ BS.length (toStrictByteString (toCBOR a))
    Range {lo, hi} =
      case szSimplify $ encodedSizeExpr szGreedy (Proxy :: Proxy a) of
        Right x -> x
        Left err -> error . show . build $ err

prop_cbor_with :: (Eq a, Show a)
               => (a -> Encoding)
               -> (forall s. Decoder s a)
               -> a -> Property
prop_cbor_with encoder decoder x =
      prop_cbor_valid     encoder         x
 .&&. prop_cbor_roundtrip encoder decoder x

prop_cbor_valid :: (a -> Encoding) -> a -> Property
prop_cbor_valid encoder x =
    counterexample errmsg $
      validFlatTerm term
  where
    term     = toFlatTerm encoding
    encoding = encoder x
    errmsg   = "invalid flat term " ++ show term
            ++ " from encoding " ++ show encoding

-- Written like this so that an Eq DeserialiseFailure is not required.
prop_cbor_roundtrip :: (Eq a, Show a)
                    => (a -> Encoding)
                    -> (forall s. Decoder s a)
                    -> a -> Property
prop_cbor_roundtrip encoder decoder x =
    case decodeFullDecoder "" decoder (serializeEncoding (encoder x)) of
      Right y  -> y === x
      Left err -> counterexample (show err) (property False)

prop_raw_serialise :: (Eq a, Show a)
                   => (a -> ByteString)
                   -> (ByteString -> Maybe a)
                   -> a -> Property
prop_raw_serialise serialise deserialise x =
    case deserialise (serialise x) of
      Just y  -> y === x
      Nothing -> property False

prop_raw_deserialise ::
  forall (a :: Type) .
  (Show a) =>
  (ByteString -> Maybe a) ->
  BadInputFor a ->
  Property
prop_raw_deserialise deserialise (BadInputFor (forbiddenLen, bs)) =
  checkCoverage .
  cover 50.0 (BS.length bs > forbiddenLen) "too long" .
  cover 50.0 (BS.length bs < forbiddenLen) "too short" $
  case deserialise bs of
    Nothing -> property True
    Just x -> counterexample (ppShow x) False

-- | The crypto algorithm classes have direct encoding functions, and the key
-- types are also typically a member of the 'ToCBOR' class. Where a 'ToCBOR'
-- instance is provided then these should match.
--
prop_cbor_direct_vs_class :: ToCBOR a
                          => (a -> Encoding)
                          -> a -> Property
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
    Nothing  -> property True
    Just msg -> counterexample (show msg) (property False)

--------------------------------------------------------------------------------
-- Helpers for property testing
--------------------------------------------------------------------------------

-- Essentially a ByteString carrying around the length it's not allowed to be.
-- This is annoying, but so's QuickCheck sometimes.
newtype BadInputFor (a :: Type) = BadInputFor (Int, ByteString)
  deriving (Eq, Show)

-- Coercion around a phantom parameter here is dangerous, as there's an implicit
-- relation between it and the forbidden length. We ensure this is impossible.
type role BadInputFor nominal

-- Needed instead of an Arbitrary instance, as there's no (good) way of knowing
-- what our forbidden (i.e. correct) length is.
genBadInputFor ::
  forall (a :: Type) .
  Int ->
  Gen (BadInputFor a)
genBadInputFor forbiddenLen =
  BadInputFor . (,) forbiddenLen <$> Gen.oneof [tooLow, tooHigh]
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
  forall (a :: Type) .
  BadInputFor a ->
  [BadInputFor a]
shrinkBadInputFor (BadInputFor (len, bs)) = BadInputFor . (len,) <$> do
  bs' <- fromList <$> shrink (toList bs)
  when (BS.length bs > len) (guard (BS.length bs' > len))
  pure bs'

-- This shows only the ByteString, in hex.
showBadInputFor ::
  forall (a :: Type) .
  BadInputFor a ->
  String
showBadInputFor (BadInputFor (_, bs)) =
  "0x" <> BS.foldr showHex "" bs <> " (length " <> show (BS.length bs) <> ")"
