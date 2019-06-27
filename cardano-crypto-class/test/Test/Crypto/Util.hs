{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Test.Crypto.Util
  ( -- * CBOR
    FromCBOR (..)
  , ToCBOR (..)
  , prop_cbor
  , prop_cbor_valid
  , prop_cbor_roundtrip
  , -- * Seed
    Seed (..)
  , withSeed
  , seedToChaCha
  , nullSeed
  , -- * Natural Numbers
    genNat
  , genNatBetween
  , shrinkNat
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..), decodeFull, serialize)
import Codec.CBOR.FlatTerm
import Crypto.Random
  ( ChaChaDRG
  , MonadPseudoRandom
  , drgNewTest
  , withDRG
  )
import Data.Word (Word64)
import Numeric.Natural (Natural)
import Test.QuickCheck
  ( (.&&.)
  , (===)
  , Gen
  , NonNegative (..)
  , Property
  , arbitrary
  , choose
  , counterexample
  , property
  , shrink
  )

--------------------------------------------------------------------------------
-- Connecting MonadRandom to Gen
--------------------------------------------------------------------------------
newtype Seed
  = Seed
      { getSeed :: (Word64, Word64, Word64, Word64, Word64)
      }
  deriving (Show, Eq, Ord, FromCBOR, ToCBOR)

withSeed :: Seed -> MonadPseudoRandom ChaChaDRG a -> a
withSeed s = fst . withDRG (drgNewTest $ getSeed s)

seedToChaCha :: Seed -> ChaChaDRG
seedToChaCha = drgNewTest . getSeed

nullSeed :: Seed
nullSeed = Seed (0, 0, 0, 0, 0)

-- Class properties
--
prop_cbor :: (ToCBOR a, FromCBOR a, Eq a, Show a) => a -> Property
prop_cbor x =
  prop_cbor_valid x .&&.
    prop_cbor_roundtrip x

prop_cbor_valid :: ToCBOR a => a -> Property
prop_cbor_valid a =
  let e = toCBOR a
      f = toFlatTerm e
      s = "invalid flat term " ++ show f ++ " from encoding " ++ show e
  in counterexample s $ validFlatTerm f

-- Written like this so that an Eq DeserialiseFailure is not required.
prop_cbor_roundtrip :: (ToCBOR a, FromCBOR a, Eq a, Show a) => a -> Property
prop_cbor_roundtrip x = case decodeFull (serialize x) of
  Right y -> y === x
  Left decoderError -> counterexample (show decoderError) (property False)

--------------------------------------------------------------------------------
-- Natural numbers
--------------------------------------------------------------------------------
genNatBetween :: Natural -> Natural -> Gen Natural
genNatBetween from to = do
  i <- choose (toInteger from, toInteger to)
  return $ fromIntegral i

genNat :: Gen Natural
genNat = do
  NonNegative i <- arbitrary :: Gen (NonNegative Integer)
  return $ fromIntegral i

shrinkNat :: Natural -> [Natural]
shrinkNat = map fromIntegral . shrink . toInteger
