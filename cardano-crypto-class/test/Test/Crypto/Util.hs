{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
  , prop_size_serialise
  , prop_cbor_direct_vs_class

    -- * NoUnexpectedThunks
  , prop_no_unexpected_thunks

    -- * Test Seed
  , TestSeed (..)
  , withTestSeed
  , testSeedToChaCha
  , nullTestSeed

    -- * Seeds
  , arbitrarySeedOfSize
  )
where


import Cardano.Binary (FromCBOR (..), ToCBOR (..),
                       Encoding, Decoder, Range (..),
                       decodeFullDecoder, serializeEncoding, szGreedy, szSimplify)
import Cardano.Prelude (NoUnexpectedThunks, unsafeNoUnexpectedThunks)
import Codec.CBOR.FlatTerm
import Codec.CBOR.Write
import Cardano.Crypto.Seed (Seed, mkSeedFromBytes)
import Crypto.Random
  ( ChaChaDRG
  , MonadPseudoRandom
  , drgNewTest
  , withDRG
  )
import Data.ByteString as BS (ByteString, pack, length)
import Data.Proxy (Proxy (..))
import Data.Word (Word64)
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
  )

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

arbitrarySeedOfSize :: Word -> Gen Seed
arbitrarySeedOfSize sz =
  (mkSeedFromBytes . BS.pack) <$> vector (fromIntegral sz)

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
    Right (Range {lo, hi}) = szSimplify $ encodedSizeExpr szGreedy (Proxy :: Proxy a)


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
-- NoUnexpectedThunks
--------------------------------------------------------------------------------

-- | When forcing the given value to WHNF, it may no longer contain thunks.
prop_no_unexpected_thunks :: NoUnexpectedThunks a => a -> Property
prop_no_unexpected_thunks !a = case unsafeNoUnexpectedThunks a of
    Nothing  -> property True
    Just msg -> counterexample msg (property False)
