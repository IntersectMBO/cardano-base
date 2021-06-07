{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.DSIGN
  ( tests
  )
where

import Data.Proxy (Proxy (..))

import Cardano.Crypto.DSIGN
import Cardano.Crypto.Util (SignableRepresentation(..))

import Test.Crypto.Util hiding (label)
import Test.Crypto.Instances ()
import Test.QuickCheck ((=/=), (===), (==>), Arbitrary(..), Gen, Property)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.DSIGN"
    [ testDSIGNAlgorithm (Proxy :: Proxy MockDSIGN) "MockDSIGN"
    , testDSIGNAlgorithm (Proxy :: Proxy Ed25519DSIGN) "Ed25519DSIGN"
    , testDSIGNAlgorithm (Proxy :: Proxy Ed448DSIGN) "Ed448DSIGN"
    ]

testDSIGNAlgorithm
  :: forall proxy v. ( DSIGNAlgorithm v
                     , ToCBOR (VerKeyDSIGN v)
                     , FromCBOR (VerKeyDSIGN v)
                     , ToCBOR (SignKeyDSIGN v)
                     , FromCBOR (SignKeyDSIGN v)
                     , Eq (SignKeyDSIGN v)   -- no Eq for signing keys normally
                     , ToCBOR (SigDSIGN v)
                     , FromCBOR (SigDSIGN v)
                     , Signable v ~ SignableRepresentation
                     , ContextDSIGN v ~ ()
                     )
  => proxy v
  -> String
  -> TestTree
testDSIGNAlgorithm _ n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise @(VerKeyDSIGN v)
                                                      rawSerialiseVerKeyDSIGN
                                                      rawDeserialiseVerKeyDSIGN
        , testProperty "SignKey" $ prop_raw_serialise @(SignKeyDSIGN v)
                                                      rawSerialiseSignKeyDSIGN
                                                      rawDeserialiseSignKeyDSIGN
        , testProperty "Sig"     $ prop_raw_serialise @(SigDSIGN v)
                                                      rawSerialiseSigDSIGN
                                                      rawDeserialiseSigDSIGN
        ]

      , testGroup "size"
        [ testProperty "VerKey"  $ prop_size_serialise @(VerKeyDSIGN v)
                                                       rawSerialiseVerKeyDSIGN
                                                       (sizeVerKeyDSIGN (Proxy @ v))
        , testProperty "SignKey" $ prop_size_serialise @(SignKeyDSIGN v)
                                                       rawSerialiseSignKeyDSIGN
                                                       (sizeSignKeyDSIGN (Proxy @ v))
        , testProperty "Sig"     $ prop_size_serialise @(SigDSIGN v)
                                                       rawSerialiseSigDSIGN
                                                       (sizeSigDSIGN (Proxy @ v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey"  $ prop_cbor_with @(VerKeyDSIGN v)
                                                  encodeVerKeyDSIGN
                                                  decodeVerKeyDSIGN
        , testProperty "SignKey" $ prop_cbor_with @(SignKeyDSIGN v)
                                                  encodeSignKeyDSIGN
                                                  decodeSignKeyDSIGN
        , testProperty "Sig"     $ prop_cbor_with @(SigDSIGN v)
                                                  encodeSigDSIGN
                                                  decodeSigDSIGN
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $ prop_cbor @(VerKeyDSIGN v)
        , testProperty "SignKey" $ prop_cbor @(SignKeyDSIGN v)
        , testProperty "Sig"     $ prop_cbor @(SigDSIGN v)
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $ prop_cbor_size @(VerKeyDSIGN v)
        , testProperty "SignKey" $ prop_cbor_size @(SignKeyDSIGN v)
        , testProperty "Sig"     $ prop_cbor_size @(SigDSIGN v)
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey"  $ prop_cbor_direct_vs_class @(VerKeyDSIGN v)
                                                             encodeVerKeyDSIGN
        , testProperty "SignKey" $ prop_cbor_direct_vs_class @(SignKeyDSIGN v)
                                                             encodeSignKeyDSIGN
        , testProperty "Sig"     $ prop_cbor_direct_vs_class @(SigDSIGN v)
                                                             encodeSigDSIGN
        ]
      ]

    , testGroup "verify"
      [ testProperty "verify positive" $ prop_dsign_verify_pos @v
      , testProperty "verify newgative (wrong key)" $ prop_dsign_verify_neg_key @v
      , testProperty "verify newgative (wrong message)" $ prop_dsign_verify_neg_msg @v
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyDSIGN v)
      , testProperty "SignKey" $ prop_no_thunks @(SignKeyDSIGN v)
      , testProperty "Sig"     $ prop_no_thunks @(SigDSIGN v)
      ]
    ]

-- | If we sign a message @a@ with the signing key, then we can verify the
-- signature using the corresponding verification key.
--
prop_dsign_verify_pos
  :: forall v. (DSIGNAlgorithm v, ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_pos a sk =
  let sig = signDSIGN () a sk
      vk = deriveVerKeyDSIGN sk
  in verifyDSIGN () vk a sig === Right ()

-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature (and message @a@) using a verification key corresponding to a
-- different signing key, then the verification fails.
--
prop_dsign_verify_neg_key
  :: forall v. (DSIGNAlgorithm v, Eq (SignKeyDSIGN v),
                ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyDSIGN v
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_neg_key a sk sk' =
  sk /= sk' ==>
    let sig = signDSIGN () a sk
        vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN () vk' a sig =/= Right ()


-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature with a message other than @a@, then the verification fails.
--
prop_dsign_verify_neg_msg
  :: forall v. (DSIGNAlgorithm v,
                ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> Message
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_neg_msg a a' sk =
  a /= a' ==>
    let sig = signDSIGN () a sk
        vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk a' sig =/= Right ()

--
-- Arbitrary instances
--

instance DSIGNAlgorithm v => Arbitrary (VerKeyDSIGN v) where
  arbitrary = deriveVerKeyDSIGN <$> arbitrary
  shrink = const []

instance DSIGNAlgorithm v => Arbitrary (SignKeyDSIGN v) where
  arbitrary = genKeyDSIGN <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeDSIGN (Proxy :: Proxy v)
  shrink = const []

instance (DSIGNAlgorithm v,
          ContextDSIGN v ~ (), Signable v ~ SignableRepresentation)
      => Arbitrary (SigDSIGN v) where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    return $ signDSIGN () a sk
  shrink = const []
