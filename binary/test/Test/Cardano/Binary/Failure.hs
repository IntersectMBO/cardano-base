{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Test.Cardano.Binary.Failure
  (tests)
  where

import Cardano.Binary hiding (Range)
import Cardano.Prelude
import qualified Codec.CBOR.Read as CR
 
import Hedgehog 
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Hedgehog.Internal.Property (failWith)

tests :: IO Bool
tests = checkParallel $$(discover)

----------------------------------------------------------------------
-------------------------   Generators   -----------------------------

genInvalidNonEmptyCBOR :: Gen Encoding -- NonEmpty Bool
genInvalidNonEmptyCBOR  = toCBOR <$> pure ([] ::[Bool])

genInvalidEitherCBOR :: Gen Encoding -- Either Bool Bool
genInvalidEitherCBOR = do
  b <- Gen.bool
  pure (encodeListLen 2 <> encodeWord 3 <> toCBOR b)

----------------------------------------------------------------------
-------------------------   Properties   -----------------------------

prop_shouldFailNonEmpty :: Property
prop_shouldFailNonEmpty = property $ do
  ne <- forAll genInvalidNonEmptyCBOR
  assertIsLeft (decode ne :: Either DecoderError (NonEmpty Bool))

prop_shouldFailEither :: Property
prop_shouldFailEither = property $ do
  e <- forAll genInvalidEitherCBOR
  assertIsLeft (decode e :: Either DecoderError (Either Bool Bool))

prop_shouldFailMaybe :: Property
prop_shouldFailMaybe = property $ do
  e <- forAll genInvalidEitherCBOR
  assertIsLeft (decode e :: Either DecoderError (Maybe Bool))

prop_shouldFailSetTag :: Property
prop_shouldFailSetTag = property $ do
  set <- forAll genInvalidEitherCBOR
  let wrongTag = encodeTag 266
  assertIsLeft (decode (wrongTag <> set) :: Either DecoderError (Set Int))

prop_shouldFailSet :: Property
prop_shouldFailSet = property $ do
  ls <- forAll $ Gen.list (Range.constant 0 20) (Gen.int Range.constantBounded)
  let set = encodeTag 258
          <> encodeListLen (fromIntegral $ length ls + 2) 
          <> (mconcat $ toCBOR <$> (4: 3:ls))
  assertIsLeft (decode set :: Either DecoderError (Set Int))

---------------------------------------------------------------------
------------------------------- helpers -----------------------------

assertIsLeft :: (HasCallStack, MonadTest m) => Either DecoderError b -> m ()
assertIsLeft (Right _) = withFrozenCallStack $ failWith Nothing "This should have Left : failed"
assertIsLeft (Left !x) = case x of
  DecoderErrorDeserialiseFailure _ (CR.DeserialiseFailure _ str) | length str > 0 -> success
  DecoderErrorCanonicityViolation _  -> success
  DecoderErrorCustom _  _            -> success 
  DecoderErrorEmptyList _            -> success
  DecoderErrorLeftover _ _           -> success
  DecoderErrorSizeMismatch _ _ _     -> success
  DecoderErrorUnknownTag _ i | i > 0 -> success
  _                                  -> success

decode :: FromCBOR a => Encoding -> Either DecoderError a
decode enc = 
 let encoded = serializeEncoding enc
 in decodeFull encoded

