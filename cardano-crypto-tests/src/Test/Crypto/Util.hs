{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}

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
  , prop_raw_serialise_IO_from
  , prop_raw_serialise_only
  , prop_size_serialise
  , prop_size_serialise_IO
  , prop_cbor_direct_vs_class

    -- * NoThunks
  , prop_no_thunks

    -- * Test Seed
  , TestSeed (..)
  , withTestSeed
  , testSeedToChaCha
  , nullTestSeed

    -- * Seeds
  , arbitrarySeedOfSize

   -- * test messages for signings
  , Message(..)
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..),
                       Encoding, Decoder, Range (..),
                       decodeFullDecoder, serializeEncoding, szGreedy, szSimplify)
import Codec.CBOR.FlatTerm
import Codec.CBOR.Write
import Cardano.Crypto.Seed (Seed, mkSeedFromBytes)
import Cardano.Crypto.Util (SignableRepresentation(..))
import Crypto.Random
  ( ChaChaDRG
  , MonadPseudoRandom
  , drgNewTest
  , withDRG
  )
import Data.ByteString as BS (ByteString, pack, unpack, length)
import Data.Proxy (Proxy (..))
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
  , ioProperty
  )
import Formatting.Buildable (Buildable (..))

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

prop_raw_serialise_IO_from :: forall a b. (Eq a, Show a)
                   => (a -> IO ByteString)
                   -> (ByteString -> IO (Maybe a))
                   -> (b -> IO a)
                   -> b
                   -> Property
prop_raw_serialise_IO_from serialise deserialise mkX seed = do
  ioProperty $ do
    x <- mkX seed
    serialise x >>= deserialise >>= \case
      Just y  -> return (y === x)
      Nothing -> return (property False)

prop_raw_serialise_only :: (a -> ByteString)
                        -> a -> Bool
prop_raw_serialise_only serialise x =
    let y = serialise x
    in y `seq` True

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

prop_size_serialise_IO :: (a -> IO ByteString) -> Word -> a -> Property
prop_size_serialise_IO serialise size x = ioProperty $ do
    actual <- BS.length <$> serialise x
    return $ actual === fromIntegral size

--------------------------------------------------------------------------------
-- NoThunks
--------------------------------------------------------------------------------

-- | When forcing the given value to WHNF, it may no longer contain thunks.
prop_no_thunks :: NoThunks a => a -> Property
prop_no_thunks !a = case unsafeNoThunks a of
    Nothing  -> property True
    Just msg -> counterexample (show msg) (property False)
