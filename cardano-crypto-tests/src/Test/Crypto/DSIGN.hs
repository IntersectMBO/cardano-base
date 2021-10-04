{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
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
import Control.Monad
import Control.Exception (evaluate)

import Cardano.Crypto.DSIGN
import Cardano.Crypto.Util (SignableRepresentation(..))
import Cardano.Crypto.Seed (mkSeedFromBytes)

import GHC.Stack (HasCallStack)

import Test.Crypto.Util hiding (label)
import Test.Crypto.Instances ()

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}
import Test.QuickCheck ((=/=), (===), (==>), Arbitrary(..), Gen, Property, label, ioProperty)
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
    , testDSIGNMAlgorithm (Proxy :: Proxy Ed25519DSIGNM) (Proxy :: Proxy Ed25519DSIGN) "Ed25519DSIGNM"
    ]

testDSIGNMAlgorithm
  :: forall proxy v w. ( DSIGNMAlgorithm IO v
                       , DSIGNAlgorithm w
                       , ToCBOR (VerKeyDSIGNM v)
                       , FromCBOR (VerKeyDSIGNM v)
                       -- , ToCBOR (SignKeyDSIGNM v)
                       -- , FromCBOR (SignKeyDSIGNM v)
                       , Eq (SignKeyDSIGNM v)   -- no Eq for signing keys normally
                       , ToCBOR (SigDSIGNM v)
                       , FromCBOR (SigDSIGNM v)
                       , SignableM v ~ SignableRepresentation
                       , Signable w ~ SignableRepresentation
                       , ContextDSIGNM v ~ ()
                       , ContextDSIGN w ~ ()
                       )
  => proxy v
  -> proxy w
  -> String
  -> TestTree
testDSIGNMAlgorithm _ _ n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise_IO_from @(VerKeyDSIGNM v)
                                                      (return . rawSerialiseVerKeyDSIGNM)
                                                      (return . rawDeserialiseVerKeyDSIGNM)
                                                      (genKeyDSIGNM >=> deriveVerKeyDSIGNM)
        -- , testProperty "SignKey" $ prop_raw_serialise_IO_from @(SignKeyDSIGNM v)
        --                                               rawSerialiseSignKeyDSIGNM
        --                                               rawDeserialiseSignKeyDSIGNM
        --                                               genKeyDSIGNM
        -- , testProperty "Sig"     $ prop_raw_serialise_IO_from @(SigDSIGNM v)
        --                                               (return . rawSerialiseSigDSIGNM)
        --                                               (return . rawDeserialiseSigDSIGNM)
        --                                               return
        ]

      -- , testGroup "size"
      --   [ testProperty "VerKey"  $ prop_size_serialise @(VerKeyDSIGNM v)
      --                                                  rawSerialiseVerKeyDSIGNM
      --                                                  (sizeVerKeyDSIGNM (Proxy @ v))
      --   , testProperty "SignKey" $ prop_size_serialise_IO @(SignKeyDSIGNM v)
      --                                                  rawSerialiseSignKeyDSIGNM
      --                                                  (sizeSignKeyDSIGNM (Proxy @ v))
      --   , testProperty "Sig"     $ prop_size_serialise @(SigDSIGNM v)
      --                                                  rawSerialiseSigDSIGNM
      --                                                  (sizeSigDSIGNM (Proxy @ v))
      --   ]

      -- , testGroup "direct CBOR"
      --   [ testProperty "VerKey"  $ prop_cbor_with @(VerKeyDSIGNM v)
      --                                             encodeVerKeyDSIGNM
      --                                             decodeVerKeyDSIGNM
      --   -- , testProperty "SignKey" $ prop_cbor_with @(SignKeyDSIGNM v)
      --   --                                           encodeSignKeyDSIGNM
      --   --                                           decodeSignKeyDSIGNM
      --   , testProperty "Sig"     $ prop_cbor_with @(SigDSIGNM v)
      --                                             encodeSigDSIGNM
      --                                             decodeSigDSIGNM
      --   ]

      -- , testGroup "To/FromCBOR class"
      --   [ testProperty "VerKey"  $ prop_cbor @(VerKeyDSIGNM v)
      --   , testProperty "SignKey" $ prop_cbor @(SignKeyDSIGNM v)
      --   , testProperty "Sig"     $ prop_cbor @(SigDSIGNM v)
      --   ]

      -- , testGroup "ToCBOR size"
      --   [ testProperty "VerKey"  $ prop_cbor_size @(VerKeyDSIGNM v)
      --   , testProperty "SignKey" $ prop_cbor_size @(SignKeyDSIGNM v)
      --   , testProperty "Sig"     $ prop_cbor_size @(SigDSIGNM v)
      --   ]

      -- , testGroup "direct matches class"
      --   [ testProperty "VerKey"  $ prop_cbor_direct_vs_class @(VerKeyDSIGNM v)
      --                                                        encodeVerKeyDSIGNM
      --   -- , testProperty "SignKey" $ prop_cbor_direct_vs_class @(SignKeyDSIGNM v)
      --   --                                                      encodeSignKeyDSIGNM
      --   , testProperty "Sig"     $ prop_cbor_direct_vs_class @(SigDSIGNM v)
      --                                                        encodeSigDSIGNM
      --   ]
        , testGroup "Seed/SK"
          [ testProperty "Seed round-trip" $ prop_dsignm_seed_roundtrip (Proxy @v)
          ]
      ]

    -- , testGroup "verify"
    --   [ testProperty "verify positive" $ prop_dsignm_verify_pos @v
    --   , testProperty "verify negative (wrong key)" $ prop_dsign_verify_neg_key @v
    --   , testProperty "verify negative (wrong message)" $ prop_dsign_verify_neg_msg @v
    --   ]

    -- , testGroup "NoThunks"
    --   [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyDSIGNM v)
    --   , testProperty "SignKey" $ prop_no_thunks @(SignKeyDSIGNM v)
    --   , testProperty "Sig"     $ prop_no_thunks @(SigDSIGNM v)
    --   ]
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
      , testProperty "verify negative (wrong key)" $ prop_dsign_verify_neg_key @v
      , testProperty "verify negative (wrong message)" $ prop_dsign_verify_neg_msg @v
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyDSIGN v)
      , testProperty "SignKey" $ prop_no_thunks @(SignKeyDSIGN v)
      , testProperty "Sig"     $ prop_no_thunks @(SigDSIGN v)
      ]
    ]

prop_dsignm_seed_roundtrip
  :: forall v. (DSIGNMAlgorithm IO v)
  => Proxy v
  -> MLockedSeed (SeedSizeDSIGNM v)
  -> Property
prop_dsignm_seed_roundtrip p seed = ioProperty $ do
  sk <- genKeyDSIGNM seed
  seed' <- getSeedDSIGNM p sk
  bs <- evaluate $! BS.copy (NaCl.mlsbToByteString seed)
  bs' <- evaluate $! BS.copy (NaCl.mlsbToByteString seed')
  forgetSignKeyDSIGNM sk
  -- NaCl.mlsbFinalize seed
  NaCl.mlsbFinalize seed'
  return (bs === bs')

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
    :: forall v w.
       ( DSIGNMAlgorithm IO v
       , DSIGNAlgorithm w
       )
    => Proxy v
    -> Proxy w
    -> MLockedSeed (SeedSizeDSIGNM v)
    -> Property
prop_sodium_genKey p q seed = ioProperty $ do
    sk <- genKeyDSIGNM seed :: IO (SignKeyDSIGNM v)
    let sk' = genKeyDSIGN (mkSeedFromBytes $ NaCl.mlsbToByteString seed) :: SignKeyDSIGN w
    actual <- rawSerialiseSignKeyDSIGNM sk
    let expected = rawSerialiseSignKeyDSIGN sk'
    return (actual === expected)

fromJustCS :: HasCallStack => Maybe a -> a
fromJustCS (Just x) = x
fromJustCS Nothing  = error "fromJustCS"

-- | Given the monadic and pure flavors of the same DSIGN algorithm, show that
-- they derive the same verkey
prop_sodium_deriveVerKey
    :: forall v w
     . (DSIGNMAlgorithm IO v, DSIGNAlgorithm w)
    => Proxy v
    -> Proxy w
    -> SignKeyDSIGNM v
    -> Property
prop_sodium_deriveVerKey p q sk = ioProperty $ do
  Just sk' <- (rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk) :: IO (Maybe (SignKeyDSIGN w))
  actual <- rawSerialiseVerKeyDSIGNM <$> deriveVerKeyDSIGNM sk
  let expected = rawSerialiseVerKeyDSIGN $ deriveVerKeyDSIGN sk'
  return (actual === expected)

prop_sodium_sign
    :: forall v w.
       ( DSIGNMAlgorithm IO v
       , DSIGNAlgorithm w
       , SignableM v ~ SignableRepresentation
       , Signable w ~ SignableRepresentation
       , ContextDSIGNM v ~ ()
       , ContextDSIGN w ~ ()
       )
    => Proxy v
    -> Proxy w
    -> SignKeyDSIGNM v
    -> [Word8]
    -> Property
prop_sodium_sign p q sk bytes = ioProperty $ do
  Just sk' <- rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk
  actual <- rawSerialiseSigDSIGNM <$> (signDSIGNM () msg sk :: IO (SigDSIGNM v))
  let expected = rawSerialiseSigDSIGN $ (signDSIGN () msg sk' :: SigDSIGN w)
  return (actual === expected)
  where
    msg = BS.pack bytes

prop_sodium_verify
    :: forall v w.
       ( DSIGNMAlgorithm IO v
       , DSIGNAlgorithm w
       , SignableM v ~ SignableRepresentation
       , Signable w ~ SignableRepresentation
       , ContextDSIGNM v ~ ()
       , ContextDSIGN w ~ ()
       )
    => Proxy v
    -> Proxy w
    -> SignKeyDSIGNM v
    -> [Word8]
    -> Property
prop_sodium_verify p q sk bytes = ioProperty $ do
    Just sk' <- rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk
    vk <- deriveVerKeyDSIGNM sk
    let vk' = deriveVerKeyDSIGN sk'
    sig <- signDSIGNM () msg sk
    let sig' = signDSIGN () msg sk' :: SigDSIGN w

    let actual = verifyDSIGNM () vk msg sig
    let expected = verifyDSIGN () vk' msg sig'
    return $ label (con expected) $ actual === expected
  where
    msg = BS.pack bytes
    con :: Either a b -> String
    con (Left _) = "Left"
    con (Right _) = "Right"

prop_sodium_verify_neg
    :: forall v w.
       ( DSIGNMAlgorithm IO v
       , DSIGNAlgorithm w
       , SignableM v ~ SignableRepresentation
       , Signable w ~ SignableRepresentation
       , ContextDSIGNM v ~ ()
       , ContextDSIGN w ~ ()
       )
    => Proxy v
    -> Proxy w
    -> SignKeyDSIGNM v
    -> [Word8]
    -> SigDSIGNM v
    -> Property
prop_sodium_verify_neg p q sk bytes sig = ioProperty $ do
    Just sk' <- rawDeserialiseSignKeyDSIGN <$> rawSerialiseSignKeyDSIGNM sk
    vk <- deriveVerKeyDSIGNM sk
    let vk' = deriveVerKeyDSIGN sk'
    let Just sig' = rawDeserialiseSigDSIGN $ rawSerialiseSigDSIGNM sig :: Maybe (SigDSIGN w)
    let actual = verifyDSIGNM () vk msg sig
    let expected = verifyDSIGN () vk' msg sig'
    return $ label (con expected) $ actual === expected
  where
    msg = BS.pack bytes
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
