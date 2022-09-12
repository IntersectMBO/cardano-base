{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.KES
  ( tests
  )
where

import Data.Proxy (Proxy(..))
import Data.List (unfoldr)

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.Util (SignableRepresentation(..))

import Test.QuickCheck
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckMaxSize(..))

import Test.Crypto.Util hiding (label)
import Test.Crypto.Instances ()

{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.KES"
  [ testKESAlgorithm (Proxy :: Proxy (MockKES 7))               "MockKES"
  , testKESAlgorithm (Proxy :: Proxy (SimpleKES Ed448DSIGN 7))  "SimpleKES"
  , testKESAlgorithm (Proxy :: Proxy (SingleKES Ed25519DSIGN))  "SingleKES"
  , testKESAlgorithm (Proxy :: Proxy (Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
  , testKESAlgorithm (Proxy :: Proxy (Sum2KES Ed25519DSIGN Blake2b_256)) "Sum2KES"
  , testKESAlgorithm (Proxy :: Proxy (Sum5KES Ed25519DSIGN Blake2b_256)) "Sum5KES"
  , testKESAlgorithm (Proxy :: Proxy (CompactSingleKES Ed25519DSIGN))  "CompactSingleKES"
  , testKESAlgorithm (Proxy :: Proxy (CompactSum1KES Ed25519DSIGN Blake2b_256)) "CompactSum1KES"
  , testKESAlgorithm (Proxy :: Proxy (CompactSum2KES Ed25519DSIGN Blake2b_256)) "CompactSum2KES"
  , testKESAlgorithm (Proxy :: Proxy (CompactSum5KES Ed25519DSIGN Blake2b_256)) "CompactSum5KES"
  ]

-- We normally ensure that we avoid naively comparing signing keys by not
-- providing instances, but for tests it is fine, so we provide the orphan
-- instances here.
deriving instance Eq (SignKeyDSIGN d) => Eq (SignKeyKES (SimpleKES d t))

deriving instance Eq (SignKeyDSIGN d)
               => Eq (SignKeyKES (SingleKES d))
deriving instance (KESAlgorithm d, Eq (SignKeyKES d))
               => Eq (SignKeyKES (SumKES h d))
deriving instance Eq (SignKeyDSIGN d)
               => Eq (SignKeyKES (CompactSingleKES d))
deriving instance (KESAlgorithm d, Eq (SignKeyKES d))
               => Eq (SignKeyKES (CompactSumKES h d))

testKESAlgorithm
  :: forall v proxy.
     ( KESAlgorithm v
     , ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , ToCBOR (SignKeyKES v)
     , FromCBOR (SignKeyKES v)
     , Eq (SignKeyKES v)   -- no Eq for signing keys normally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , Signable v ~ SignableRepresentation
     , ContextKES v ~ ()
     )
  => proxy v
  -> String
  -> TestTree
testKESAlgorithm _p n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise @(VerKeyKES v)
                                                      rawSerialiseVerKeyKES
                                                      rawDeserialiseVerKeyKES
        , testProperty "SignKey" $ prop_raw_serialise @(SignKeyKES v)
                                                      rawSerialiseSignKeyKES
                                                      rawDeserialiseSignKeyKES
        , testProperty "Sig"     $ prop_raw_serialise @(SigKES v)
                                                      rawSerialiseSigKES
                                                      rawDeserialiseSigKES
        ]

      , testGroup "size"
        [ testProperty "VerKey"  $ prop_size_serialise @(VerKeyKES v)
                                                       rawSerialiseVerKeyKES
                                                       (sizeVerKeyKES (Proxy @v))
        , testProperty "SignKey" $ prop_size_serialise @(SignKeyKES v)
                                                       rawSerialiseSignKeyKES
                                                       (sizeSignKeyKES (Proxy @v))
        , testProperty "Sig"     $ prop_size_serialise @(SigKES v)
                                                       rawSerialiseSigKES
                                                       (sizeSigKES (Proxy @v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey"  $ prop_cbor_with @(VerKeyKES v)
                                                  encodeVerKeyKES
                                                  decodeVerKeyKES
        , testProperty "SignKey" $ prop_cbor_with @(SignKeyKES v)
                                                  encodeSignKeyKES
                                                  decodeSignKeyKES
        , testProperty "Sig"     $ prop_cbor_with @(SigKES v)
                                                  encodeSigKES
                                                  decodeSigKES
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $ prop_cbor @(VerKeyKES v)
        , testProperty "SignKey" $ prop_cbor @(SignKeyKES v)
        , testProperty "Sig"     $ prop_cbor @(SigKES v)
        ]
      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $ prop_cbor_size @(VerKeyKES v)
        , testProperty "SignKey" $ prop_cbor_size @(SignKeyKES v)
        , testProperty "Sig"     $ prop_cbor_size @(SigKES v)
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey"  $ prop_cbor_direct_vs_class @(VerKeyKES v)
                                                             encodeVerKeyKES
        , testProperty "SignKey" $ prop_cbor_direct_vs_class @(SignKeyKES v)
                                                             encodeSignKeyKES
        , testProperty "Sig"     $ prop_cbor_direct_vs_class @(SigKES v)
                                                             encodeSigKES
        ]
      ]

    , testProperty "total periods" $ prop_totalPeriodsKES @v
    , testProperty "same VerKey "  $ prop_deriveVerKeyKES @v

    , testGroup "verify"
      [ testProperty "positive"           $ prop_verifyKES_positive         @v
      , testProperty "negative (key)"     $ prop_verifyKES_negative_key     @v
      , testProperty "negative (message)" $ prop_verifyKES_negative_message @v
      , adjustOption (\(QuickCheckMaxSize sz) -> QuickCheckMaxSize (min sz 50)) $
        testProperty "negative (period)"  $ prop_verifyKES_negative_period  @v
      ]

    , testGroup "serialisation of all KES evolutions"
      [ testProperty "VerKey"  $ prop_serialise_VerKeyKES  @v
      , testProperty "SignKey" $ prop_serialise_SignKeyKES @v
      , testProperty "Sig"     $ prop_serialise_SigKES     @v
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyKES v)
      , testProperty "SignKey" $ prop_no_thunks @(SignKeyKES v)
      , testProperty "Sig"     $ prop_no_thunks @(SigKES v)
      ]
    ]


-- | If we start with a signing key, we can evolve it a number of times so that
-- the total number of signing keys (including the initial one) equals the
-- total number of periods for this algorithm.
--
prop_totalPeriodsKES
  :: forall v. (KESAlgorithm v, ContextKES v ~ ())
  => SignKeyKES v -> Property
prop_totalPeriodsKES sk_0 =
    totalPeriods > 0 ==>
    counterexample (show totalPeriods) $
    counterexample (show sks) $
      length sks === totalPeriods
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))

    sks :: [SignKeyKES v]
    sks = allUpdatesKES sk_0


-- | If we start with a signing key, and all its evolutions, the verification
-- keys we derive from each one are the same.
--
prop_deriveVerKeyKES
  :: forall v. (KESAlgorithm v, ContextKES v ~ ())
  => SignKeyKES v -> Property
prop_deriveVerKeyKES sk_0 =
    counterexample (show vks) $
      conjoin [ vk === vk_0 | vk <- vks ]
  where
    sks :: [SignKeyKES v]
    sks = allUpdatesKES sk_0

    vk_0 = deriveVerKeyKES sk_0

    vks :: [VerKeyKES v]
    vks = map deriveVerKeyKES sks


-- | If we take an initial signing key, a sequence of messages to sign, and
-- sign each one with an updated key, we can verify each one for the
-- corresponding period.
--
prop_verifyKES_positive
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ (), Signable v ~ SignableRepresentation)
  => SignKeyKES v -> [Message] -> Property
prop_verifyKES_positive sk_0 xs =
    cover 1 (length xs >= totalPeriods) "covers total periods" $
    conjoin [ counterexample ("period " ++ show t) $
              verifyKES () vk t x sig === Right ()
            | let vk = deriveVerKeyKES sk_0
            , (t, x, sk) <- zip3 [0..] xs (allUpdatesKES sk_0)
            , let sig = signKES () t x sk
            ]
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using a verification key
-- corresponding to a different signing key, then the verification fails.
--
prop_verifyKES_negative_key
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ (),
      Signable v ~ SignableRepresentation, Eq (SignKeyKES v))
  => SignKeyKES v -> SignKeyKES v -> Message -> Property
prop_verifyKES_negative_key sk_0 sk'_0 x =
    sk_0 /= sk'_0 ==>
    conjoin [ counterexample ("period " ++ show t) $
              verifyKES () vk' t x sig =/= Right ()
            | let sks = allUpdatesKES sk_0
                  vk' = deriveVerKeyKES sk'_0
            , (t, sk) <- zip [0..] sks
            , let sig = signKES () t x sk
            ]

-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature with a message other than @a@, then the
-- verification fails.
--
prop_verifyKES_negative_message
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ (), Signable v ~ SignableRepresentation)
  => SignKeyKES v -> Message -> Message -> Property
prop_verifyKES_negative_message sk_0 x x' =
    x /= x' ==>
    conjoin [ counterexample ("period " ++ show t) $
              verifyKES () vk t x' sig =/= Right ()
            | let sks = allUpdatesKES sk_0
                  vk  = deriveVerKeyKES sk_0
            , (t, sk) <- zip [0..] sks
            , let sig = signKES () t x sk
            ]

-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using the right verification
-- key but at a different period than the key used for signing, then the
-- verification fails.
--
prop_verifyKES_negative_period
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ (), Signable v ~ SignableRepresentation)
  => SignKeyKES v -> Message -> Property
prop_verifyKES_negative_period sk_0 x =
    conjoin [ counterexample ("periods " ++ show (t, t')) $
              verifyKES () vk t' x sig =/= Right ()
            | let sks = allUpdatesKES sk_0
                  vk  = deriveVerKeyKES sk_0
            , (t, sk) <- zip [0..] sks
            , let sig = signKES () t x sk
            , (t', _) <- zip [0..] sks
            , t /= t'
            ]


-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'VerKeyKES' on /all/ the KES key evolutions.
--
prop_serialise_VerKeyKES
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ ())
  => SignKeyKES v -> Property
prop_serialise_VerKeyKES sk_0 =
    conjoin
      [ counterexample ("period " ++ show (t :: Int)) $
        counterexample ("vkey " ++ show vk) $
           prop_raw_serialise rawSerialiseVerKeyKES
                              rawDeserialiseVerKeyKES vk
       .&. prop_cbor_with encodeVerKeyKES
                          decodeVerKeyKES vk
       .&. prop_size_serialise rawSerialiseVerKeyKES
                               (sizeVerKeyKES (Proxy @v)) vk
      | (t, vk) <- zip [0..] (map deriveVerKeyKES (allUpdatesKES sk_0)) ]


-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'SignKeyKES' on /all/ the KES key evolutions.
--
prop_serialise_SignKeyKES
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ (), Eq (SignKeyKES v))
  => SignKeyKES v -> Property
prop_serialise_SignKeyKES sk_0 =
    conjoin
      [ counterexample ("period " ++ show (t :: Int)) $
        counterexample ("skey " ++ show sk) $
           prop_raw_serialise rawSerialiseSignKeyKES
                              rawDeserialiseSignKeyKES sk
       .&. prop_cbor_with encodeSignKeyKES
                          decodeSignKeyKES sk
       .&. prop_size_serialise rawSerialiseSignKeyKES
                               (sizeSignKeyKES (Proxy @v)) sk
      | (t, sk) <- zip [0..] (allUpdatesKES sk_0) ]


-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'SigKES' on /all/ the KES key evolutions.
--
prop_serialise_SigKES
  :: forall v.
     (KESAlgorithm v, ContextKES v ~ (), Signable v ~ SignableRepresentation)
  => SignKeyKES v -> Message -> Property
prop_serialise_SigKES sk_0 x =
    conjoin
      [ counterexample ("period " ++ show t) $
        counterexample ("vkey "   ++ show sk) $
        counterexample ("sig "    ++ show sig) $
           prop_raw_serialise rawSerialiseSigKES
                              rawDeserialiseSigKES sig
       .&. prop_cbor_with encodeSigKES
                          decodeSigKES sig
       .&. prop_size_serialise rawSerialiseSigKES
                               (sizeSigKES (Proxy @v)) sig
      | (t, sk) <- zip [0..] (allUpdatesKES sk_0)
      , let sig = signKES () t x sk
      ]


--
-- KES test utils
--

allUpdatesKES :: forall v. (KESAlgorithm v, ContextKES v ~ ())
              => SignKeyKES v -> [SignKeyKES v]
allUpdatesKES sk_0 =
    sk_0 : unfoldr update (sk_0, 0)
  where
    update :: (SignKeyKES v, Period)
           -> Maybe (SignKeyKES v, (SignKeyKES v, Period))
    update (sk, t) =
      case updateKES () sk t of
        Nothing  -> Nothing
        Just sk' -> Just (sk', (sk', t+1))


--
-- Arbitrary instances
--

instance KESAlgorithm v => Arbitrary (VerKeyKES v) where
  arbitrary = deriveVerKeyKES <$> arbitrary
  shrink = const []

instance KESAlgorithm v => Arbitrary (SignKeyKES v) where
  arbitrary = genKeyKES <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeKES (Proxy :: Proxy v)
  shrink = const []

instance (KESAlgorithm v, ContextKES v ~ (), Signable v ~ SignableRepresentation)
      => Arbitrary (SigKES v) where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    let sig = signKES () 0 a sk
    return sig
  shrink = const []
