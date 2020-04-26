{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
module Test.Crypto.VRF
  ( tests
  )
where

import Cardano.Binary (FromCBOR, ToCBOR (..))
import Cardano.Crypto.VRF
import Data.Proxy (Proxy (..))
import Test.Crypto.Orphans.Arbitrary ()
import Test.Crypto.Util (TestSeed, prop_cbor, withTestSeed)
import Test.QuickCheck ((==>), Property, counterexample)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.VRF"
    [ testVRFAlgorithm (Proxy :: Proxy MockVRF) "MockVRF"
    , testVRFAlgorithm (Proxy :: Proxy SimpleVRF) "SimpleVRF"
    ]

testVRFAlgorithm
  :: forall proxy v. ( VRFAlgorithm v
                     , ToCBOR (VerKeyVRF v)
                     , FromCBOR (VerKeyVRF v)
                     , ToCBOR (SignKeyVRF v)
                     , FromCBOR (SignKeyVRF v)
                     , Eq (SignKeyVRF v)     -- no Eq for signing keys normally
                     , Signable v Int
                     , ContextVRF v ~ ()
                     )
  => proxy v
  -> String
  -> TestTree
testVRFAlgorithm _ n =
  testGroup
    n
    [ testProperty "serialise VerKey" $ prop_cbor @(VerKeyVRF v)
    , testProperty "serialise SignKey" $ prop_cbor @(SignKeyVRF v)
    , testProperty "serialise Cert" $ prop_cbor @(CertVRF v)
    , testProperty "max" $ prop_vrf_max @Int @v
    , testProperty "verify positive" $ prop_vrf_verify_pos @Int @v
    , testProperty "verify negative" $ prop_vrf_verify_neg @Int @v
    ]

prop_vrf_max
  :: forall a v. (Signable v a, VRFAlgorithm v, ContextVRF v ~ ())
  => TestSeed
  -> a
  -> SignKeyVRF v
  -> Property
prop_vrf_max seed a sk =
  let (y, _) = withTestSeed seed $ evalVRF () a sk
      m = maxVRF (Proxy :: Proxy v)
  in counterexample ("expected " ++ show y ++ " <= " ++ show m) $ y <= m

prop_vrf_verify_pos
  :: forall a v. (Signable v a, VRFAlgorithm v, ContextVRF v ~ ())
  => TestSeed
  -> a
  -> SignKeyVRF v
  -> Bool
prop_vrf_verify_pos seed a sk =
  let (y, c) = withTestSeed seed $ evalVRF () a sk
      vk = deriveVerKeyVRF sk
  in verifyVRF () vk a (y, c)

prop_vrf_verify_neg
  :: forall a v. (Signable v a, VRFAlgorithm v, Eq (SignKeyVRF v), ContextVRF v ~ ())
  => TestSeed
  -> a
  -> SignKeyVRF v
  -> SignKeyVRF v
  -> Property
prop_vrf_verify_neg seed a sk sk' =
  sk /=
    sk' ==>
    let (y, c) = withTestSeed seed $ evalVRF () a sk'
        vk = deriveVerKeyVRF sk
    in not $ verifyVRF () vk a (y, c)
