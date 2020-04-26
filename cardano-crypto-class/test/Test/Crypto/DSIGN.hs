{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
module Test.Crypto.DSIGN
  ( tests
  )
where

import Cardano.Binary (FromCBOR, ToCBOR (..))
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm (..)
  , Ed25519DSIGN
  , Ed448DSIGN
  , MockDSIGN
  )
import Data.Proxy (Proxy (..))
import Test.Crypto.Orphans.Arbitrary ()
import Test.Crypto.Util (Seed, prop_cbor, withSeed)
import Test.QuickCheck ((=/=), (===), (==>), Property)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

-- import           Ouroboros.Consensus.Util.Orphans ()
-- import           Ouroboros.Consensus.Util.Random (Seed, withSeed)

-- import           Ouroboros.Network.Testing.Serialise (Serialise(..), prop_cbor)
-- import           Test.Util.Orphans.Arbitrary ()

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
                     , Signable v Int
                     , ContextDSIGN v ~ ()
                     )
  => proxy v
  -> String
  -> TestTree
testDSIGNAlgorithm _ n =
  testGroup n
    [ testProperty "serialise VerKey" $ prop_cbor @(VerKeyDSIGN v)
    , testProperty "serialise SignKey" $ prop_cbor @(SignKeyDSIGN v)
    , testProperty "serialise Sig" $ prop_cbor @(SigDSIGN v)
    , testProperty "verify positive" $ prop_dsign_verify_pos @Int @v
    , testProperty "verify newgative (wrong key)" $ prop_dsign_verify_neg_key @Int @v
    , testProperty "verify newgative (wrong message)" $ prop_dsign_verify_neg_msg @Int @v
    ]

prop_dsign_verify_pos
  :: forall a v. (DSIGNAlgorithm v, Signable v a, ContextDSIGN v ~ ())
  => Seed
  -> a
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_pos seed a sk =
  let sig = withSeed seed $ signDSIGN () a sk
      vk = deriveVerKeyDSIGN sk
  in verifyDSIGN () vk a sig === Right ()

prop_dsign_verify_neg_key
  :: forall a v. (DSIGNAlgorithm v, Eq (SignKeyDSIGN v), Signable v a, ContextDSIGN v ~ ())
  => Seed
  -> a
  -> SignKeyDSIGN v
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_neg_key seed a sk sk' =
  sk /= sk' ==>
    let sig = withSeed seed $ signDSIGN () a sk'
        vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk a sig =/= Right ()

prop_dsign_verify_neg_msg
  :: forall a v. (Eq a, DSIGNAlgorithm v, Signable v a, ContextDSIGN v ~ ())
  => Seed
  -> a
  -> a
  -> SignKeyDSIGN v
  -> Property
prop_dsign_verify_neg_msg seed a a' sk =
  a /= a' ==>
    let sig = withSeed seed $ signDSIGN () a sk
        vk = deriveVerKeyDSIGN sk
    in verifyDSIGN () vk a' sig =/= Right ()
