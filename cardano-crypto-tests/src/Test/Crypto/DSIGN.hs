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
import Data.Word (Word8)

import Cardano.Crypto.DSIGN
import Cardano.Crypto.Util (SignableRepresentation(..))
import Cardano.Crypto.Seed
import Cardano.Crypto.PinnedSizedBytes

import GHC.Stack (HasCallStack)
import Test.Crypto.Util hiding (label)
import Test.Crypto.Instances ()
import Test.QuickCheck ((=/=), (===), (==>), Arbitrary(..), Gen, Property, label)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import qualified Data.ByteString as BS
import qualified Cardano.Crypto.Libsodium as NaCl

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.DSIGN"
    [ testDSIGNAlgorithm (Proxy :: Proxy MockDSIGN) "MockDSIGN"
    , testDSIGNAlgorithm (Proxy :: Proxy Ed25519DSIGN) "Ed25519DSIGN"
    , testDSIGNAlgorithm (Proxy :: Proxy Ed448DSIGN) "Ed448DSIGN"

    , testSodiumDSIGNAlgorithm (Proxy :: Proxy Ed25519DSIGN) "Ed25519DSIGN"
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

    , testGroup "NoUnexpectedThunks"
      [ testProperty "VerKey"  $ prop_no_unexpected_thunks @(VerKeyDSIGN v)
      , testProperty "SignKey" $ prop_no_unexpected_thunks @(SignKeyDSIGN v)
      , testProperty "Sig"     $ prop_no_unexpected_thunks @(SigDSIGN v)
      ]
    ]

testSodiumDSIGNAlgorithm
  :: forall v. ( NaCl.SodiumDSIGNAlgorithm v, Signable v ~ SignableRepresentation)
  => Proxy v
  -> String
  -> TestTree
testSodiumDSIGNAlgorithm pv n =
  testGroup n
    [ testProperty "genKey agree" $ prop_sodium_genKey pv
    , testProperty "deriveVerKey agree" $ prop_sodium_deriveVerKey pv
    , testProperty "sign agree" $ prop_sodium_sign pv
    , testProperty "verify agree" $ prop_sodium_verify pv
    , testProperty "verify agree (random sig)" $ prop_sodium_verify_neg pv
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
-- Libsodium
--

prop_sodium_genKey
    :: forall v. NaCl.SodiumDSIGNAlgorithm v
    => Proxy v
    -> NaCl.MLockedSizedBytes (SeedSizeDSIGN v)
    -> Property
prop_sodium_genKey p seed = actual === expected
  where
    actual = NaCl.mlsbToByteString $ NaCl.naclGenKeyDSIGN p seed
    expected = rawSerialiseSignKeyDSIGN (genKeyDSIGN (mkSeedFromBytes (NaCl.mlsbToByteString seed)) :: SignKeyDSIGN v)

fromJustCS :: HasCallStack => Maybe a -> a
fromJustCS (Just x) = x
fromJustCS Nothing  = error "fromJustCS"

prop_sodium_deriveVerKey
    :: forall v. NaCl.SodiumDSIGNAlgorithm v
    => Proxy v
    -> NaCl.SodiumSignKeyDSIGN v
    -> Property
prop_sodium_deriveVerKey p sk = actual === expected
  where
    actual = psbToByteString $ NaCl.naclDeriveVerKeyDSIGN p sk
    sk' = fromJustCS $ rawDeserialiseSignKeyDSIGN $ NaCl.mlsbToByteString sk :: SignKeyDSIGN v
    expected = rawSerialiseVerKeyDSIGN $ deriveVerKeyDSIGN sk'

prop_sodium_sign
    :: forall v. (NaCl.SodiumDSIGNAlgorithm v, Signable v ~ SignableRepresentation, ContextDSIGN v ~ ())
    => Proxy v
    -> NaCl.SodiumSignKeyDSIGN v
    -> [Word8]
    -> Property
prop_sodium_sign p sk bytes = actual === expected
  where
    msg = BS.pack bytes
    actual = psbToByteString $ NaCl.naclSignDSIGN p msg sk
    sk' = fromJustCS $ rawDeserialiseSignKeyDSIGN $ NaCl.mlsbToByteString sk :: SignKeyDSIGN v
    expected = rawSerialiseSigDSIGN $ signDSIGN () msg sk'

prop_sodium_verify
    :: forall v. (NaCl.SodiumDSIGNAlgorithm v, Signable v ~ SignableRepresentation, ContextDSIGN v ~ ())
    => Proxy v
    -> NaCl.SodiumSignKeyDSIGN v
    -> [Word8]
    -> Property
prop_sodium_verify p sk bytes =
    label (con expected) $ actual === expected
  where
    msg = BS.pack bytes
    vk = NaCl.naclDeriveVerKeyDSIGN p sk
    sig = NaCl.naclSignDSIGN p msg sk

    actual = NaCl.naclVerifyDSIGN p vk msg sig

    sk' = fromJustCS $ rawDeserialiseSignKeyDSIGN $ NaCl.mlsbToByteString sk :: SignKeyDSIGN v
    sig' = fromJustCS $ rawDeserialiseSigDSIGN $ psbToByteString sig :: SigDSIGN v
    vk' = deriveVerKeyDSIGN sk'

    expected = verifyDSIGN () vk' msg sig'

    con :: Either a b -> String
    con (Left _) = "Left"
    con (Right _) = "Right"

prop_sodium_verify_neg
    :: forall v. (NaCl.SodiumDSIGNAlgorithm v, Signable v ~ SignableRepresentation, ContextDSIGN v ~ ())
    => Proxy v
    -> NaCl.SodiumSignKeyDSIGN v
    -> [Word8]
    -> NaCl.SodiumSigDSIGN v
    -> Property
prop_sodium_verify_neg p sk bytes sig =
    label (con expected) $ actual === expected
  where
    msg = BS.pack bytes
    vk = NaCl.naclDeriveVerKeyDSIGN p sk

    actual = NaCl.naclVerifyDSIGN p vk msg sig

    sk' = fromJustCS $ rawDeserialiseSignKeyDSIGN $ NaCl.mlsbToByteString sk :: SignKeyDSIGN v
    sig' = fromJustCS $ rawDeserialiseSigDSIGN $ psbToByteString sig :: SigDSIGN v
    vk' = deriveVerKeyDSIGN sk'

    expected = verifyDSIGN () vk' msg sig'

    con :: Either a b -> String
    con (Left _) = "Left"
    con (Right _) = "Right"

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
