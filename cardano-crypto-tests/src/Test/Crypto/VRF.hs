{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.VRF
  ( tests
  )
where

import Cardano.Crypto.VRF
import Cardano.Crypto.VRF.Praos
import Cardano.Crypto.VRF.Praos09
import Cardano.Crypto.Util

import qualified Data.ByteString as BS
import Data.Word (Word8, Word64)
import Data.Proxy (Proxy (..))

import Test.Crypto.Util
import Test.QuickCheck
         ((==>), (===), Arbitrary(..), Gen, Property,  NonNegative(..),
          counterexample)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

{- HLINT IGNORE "Use <$>" -}

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.VRF"
    [ testVRFAlgorithm (Proxy :: Proxy MockVRF) "MockVRF"
    , testVRFAlgorithm (Proxy :: Proxy SimpleVRF) "SimpleVRF"
    , testVRFAlgorithm (Proxy :: Proxy PraosVRF) "PraosVRF"
    , testVRFAlgorithm (Proxy :: Proxy Praos09VRF) "Praos09VRF"

    , testGroup "OutputVRF"
      [ testProperty "bytesToNatural" prop_bytesToNatural
      , testProperty "naturalToBytes" prop_naturalToBytes
      ]
    ]

testVRFAlgorithm
  :: forall proxy v. ( VRFAlgorithm v
                     , ToCBOR (VerKeyVRF v)
                     , FromCBOR (VerKeyVRF v)
                     , ToCBOR (SignKeyVRF v)
                     , FromCBOR (SignKeyVRF v)
                     , ToCBOR (CertVRF v)
                     , FromCBOR (CertVRF v)
                     , Eq (SignKeyVRF v)     -- no Eq for signing keys normally
                     , ContextVRF v ~ ()
                     , Signable v ~ SignableRepresentation
                     )
  => proxy v
  -> String
  -> TestTree
testVRFAlgorithm _ n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise @(VerKeyVRF v)
                                                      rawSerialiseVerKeyVRF
                                                      rawDeserialiseVerKeyVRF
        , testProperty "SignKey" $ prop_raw_serialise @(SignKeyVRF v)
                                                      rawSerialiseSignKeyVRF
                                                      rawDeserialiseSignKeyVRF
        , testProperty "Cert"    $ prop_raw_serialise @(CertVRF v)
                                                      rawSerialiseCertVRF
                                                      rawDeserialiseCertVRF
        ]

      , testGroup "size"
        [ testProperty "VerKey"  $ prop_size_serialise @(VerKeyVRF v)
                                                       rawSerialiseVerKeyVRF
                                                       (sizeVerKeyVRF (Proxy @ v))
        , testProperty "SignKey" $ prop_size_serialise @(SignKeyVRF v)
                                                       rawSerialiseSignKeyVRF
                                                       (sizeSignKeyVRF (Proxy @ v))
        , testProperty "Cert"    $ prop_size_serialise @(CertVRF v)
                                                       rawSerialiseCertVRF
                                                       (sizeCertVRF (Proxy @ v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey"  $ prop_cbor_with @(VerKeyVRF v)
                                                  encodeVerKeyVRF
                                                  decodeVerKeyVRF
        , testProperty "SignKey" $ prop_cbor_with @(SignKeyVRF v)
                                                  encodeSignKeyVRF
                                                  decodeSignKeyVRF
        , testProperty "Cert"    $ prop_cbor_with @(CertVRF v)
                                                  encodeCertVRF
                                                  decodeCertVRF
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $ prop_cbor @(VerKeyVRF v)
        , testProperty "SignKey" $ prop_cbor @(SignKeyVRF v)
        , testProperty "Cert"    $ prop_cbor @(CertVRF v)
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $ prop_cbor_size @(VerKeyVRF v)
        , testProperty "SignKey" $ prop_cbor_size @(SignKeyVRF v)
        , testProperty "Sig"     $ prop_cbor_size @(CertVRF v)
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey"  $ prop_cbor_direct_vs_class @(VerKeyVRF v)
                                                             encodeVerKeyVRF
        , testProperty "SignKey" $ prop_cbor_direct_vs_class @(SignKeyVRF v)
                                                             encodeSignKeyVRF
        , testProperty "Cert"    $ prop_cbor_direct_vs_class @(CertVRF v)
                                                             encodeCertVRF
        ]
      ]

    , testGroup "verify"
      [ -- NOTE: we no longer test against maxVRF, because the maximum numeric
        -- value isn't actually what we're interested in, as long as all
        -- keys/hashes have the correct sizes, which 'prop_size_serialise'
        -- tests already.
        testProperty "verify positive" $ prop_vrf_verify_pos @v
      , testProperty "verify negative" $ prop_vrf_verify_neg @v
      ]

    , testGroup "output"
      [ testProperty "sizeOutputVRF"   $ prop_vrf_output_size    @v
      , testProperty "mkTestOutputVRF" $ prop_vrf_output_natural @v
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyVRF v)
      , testProperty "SignKey" $ prop_no_thunks @(SignKeyVRF v)
      , testProperty "Cert"    $ prop_no_thunks @(CertVRF v)
      ]
    ]

prop_vrf_verify_pos
  :: forall v. (VRFAlgorithm v,
                ContextVRF v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyVRF v
  -> Bool
prop_vrf_verify_pos a sk =
  let (y, c) = evalVRF () a sk
      vk = deriveVerKeyVRF sk
  in verifyVRF () vk a (y, c)

prop_vrf_verify_neg
  :: forall v. (VRFAlgorithm v, Eq (SignKeyVRF v),
                ContextVRF v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyVRF v
  -> SignKeyVRF v
  -> Property
prop_vrf_verify_neg a sk sk' =
  sk /=
    sk' ==>
    let (y, c) = evalVRF () a sk'
        vk = deriveVerKeyVRF sk
    in not $ verifyVRF () vk a (y, c)


prop_vrf_output_size
  :: forall v. (VRFAlgorithm v,
                ContextVRF v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyVRF v
  -> Property
prop_vrf_output_size a sk =
  let (out, _c) = evalVRF () a sk
   in     BS.length (getOutputVRFBytes out)
      === fromIntegral (sizeOutputVRF (Proxy :: Proxy v))

prop_vrf_output_natural
  :: forall v. (VRFAlgorithm v,
                ContextVRF v ~ (), Signable v ~ SignableRepresentation)
  => Message
  -> SignKeyVRF v
  -> Property
prop_vrf_output_natural a sk =
  let (out, _c) = evalVRF () a sk
      n         = getOutputVRFNatural out
   in counterexample (show n) $
      mkTestOutputVRF n === out

--
-- Natural <-> bytes conversion
--

prop_bytesToNatural :: [Word8] -> Bool
prop_bytesToNatural ws =
    naturalToBytes (BS.length bs) (bytesToNatural bs) == bs
  where
    bs = BS.pack ws

prop_naturalToBytes :: NonNegative Int -> Word64 -> Property
prop_naturalToBytes (NonNegative sz) n =
    sz >= 8 ==>
      bytesToNatural (naturalToBytes sz (fromIntegral n)) == fromIntegral n


--
-- Arbitrary instances
--

instance VRFAlgorithm v => Arbitrary (VerKeyVRF v) where
  arbitrary = deriveVerKeyVRF <$> arbitrary
  shrink = const []

instance VRFAlgorithm v => Arbitrary (SignKeyVRF v) where
  arbitrary = genKeyVRF <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeVRF (Proxy :: Proxy v)
  shrink = const []

instance (VRFAlgorithm v,
          ContextVRF v ~ (), Signable v ~ SignableRepresentation)
      => Arbitrary (CertVRF v) where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    return $ snd $ evalVRF () a sk
  shrink = const []
