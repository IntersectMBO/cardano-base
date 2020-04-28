{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE DeriveAnyClass       #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE UndecidableInstances #-}

module Test.Crypto.KES
  ( tests
  )
where

import Data.Proxy (Proxy(..))
import Numeric.Natural (Natural)
import Test.QuickCheck
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import Cardano.Binary (FromCBOR, ToCBOR(..))
import Cardano.Crypto.DSIGN
import Cardano.Crypto.KES
import Cardano.Crypto.Seed
import qualified Cardano.Crypto.KES as KES

import Test.Crypto.Util


--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.KES"
  [ testKESAlgorithm (Proxy :: Proxy (MockKES 42))              "MockKES"
  , testKESAlgorithm (Proxy :: Proxy (SimpleKES Ed448DSIGN 42)) "SimpleKES (with Ed448)"
  ]

-- We normally ensure that we avoid naively comparing signing keys by not
-- providing instances, but for tests it is fine, so we provide the orphan
-- instance here.
deriving instance (DSIGNAlgorithm d, Eq (SignKeyDSIGN d))
               => Eq (SignKeyKES (SimpleKES d t))

testKESAlgorithm
  :: ( KESAlgorithm v
     , ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , ToCBOR (SignKeyKES v)
     , FromCBOR (SignKeyKES v)
     , Eq (SignKeyKES v)   -- no Eq for signing keys normally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , KES.Signable v ~ ToCBOR
     , ContextKES v ~ ()
     )
  => proxy v
  -> String
  -> TestTree
testKESAlgorithm p n =
  testGroup n
    [ testProperty "serialise VerKey"                $ prop_KES_serialise_VerKey p
    , testProperty "serialise SignKey"               $ prop_KES_serialise_SignKey p
    , testProperty "serialise Sig"                   $ prop_KES_serialise_Sig p
    , testProperty "verify positive"                 $ prop_KES_verify_pos p
    , testProperty "verify negative (wrong key)"     $ prop_KES_verify_neg_key p
    , testProperty "verify negative (wrong message)" $ prop_KES_verify_neg_msg p
    , testProperty "verify negative (wrong time)"    $ prop_KES_verify_neg_time p
    ]

prop_KES_serialise_VerKey
  :: (KESAlgorithm v, FromCBOR (VerKeyKES v), ToCBOR (VerKeyKES v))
  => proxy v
  -> SK v
  -> Property
prop_KES_serialise_VerKey _ (SK sk _) =
  prop_cbor (deriveVerKeyKES sk)

prop_KES_serialise_SignKey
  :: ( KESAlgorithm v
     , FromCBOR (SignKeyKES v)
     , ToCBOR (SignKeyKES v)
     , Eq (SignKeyKES v)
     )
  => proxy v
  -> SK v
  -> Property
prop_KES_serialise_SignKey _ (SK sk _) = prop_cbor sk

prop_KES_serialise_Sig
  :: ( KESAlgorithm v
     , KES.Signable v ~ ToCBOR
     , ContextKES v ~ ()
     , FromCBOR (SigKES v)
     , ToCBOR (SigKES v)
     )
  => proxy v
  -> SK_Times v [Int]
  -> Property
prop_KES_serialise_Sig _ d = case trySign d of
  Left  e  -> counterexample e False
  Right xs -> conjoin [ prop_cbor sig | (_, _, sig) <- xs ]

prop_KES_verify_pos
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> SK_Times v [Int]
  -> Property
prop_KES_verify_pos _ d =
  let vk = getFirstVerKey d
  in
    case trySign d of
      Left e -> counterexample e False
      Right xs ->
        conjoin [ verifyKES () vk j a sig === Right () | (j, a, sig) <- xs ]

prop_KES_verify_neg_key
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> SK_Times v Int
  -> Property
prop_KES_verify_neg_key _ d =
  case trySign d of
    Left  e  -> counterexample e False
    Right xs -> conjoin
      [ verifyKES () (getSecondVerKey d) j a sig =/= Right ()
      | (j, a, sig) <- xs
      ]

prop_KES_verify_neg_msg
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> SK_Times v Float
  -> Float
  -> Property
prop_KES_verify_neg_msg _ d a =
  let vk = getFirstVerKey d
  in
    case trySign d of
      Left  e  -> counterexample e False
      Right xs -> conjoin
        [ a /= a' ==> verifyKES () vk j a sig =/= Right ()
        | (j, a', sig) <- xs
        ]

prop_KES_verify_neg_time
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> SK_Times v Float
  -> Integer
  -> Property
prop_KES_verify_neg_time _ d i =
  let
    vk   = getFirstVerKey d
    t    = fromIntegral $ abs i
  in case trySign d of
    Left  e  -> counterexample e False
    Right xs -> conjoin
      [ t /= j ==> verifyKES () vk t a sig =/= Right ()
      | (j, a, sig) <- xs
      ]

getFirstVerKey :: KESAlgorithm v => SK_Times v a -> VerKeyKES v
getFirstVerKey (SK_Times sk _ _) = deriveVerKeyKES sk

getSecondVerKey :: SK_Times v a -> VerKeyKES v
getSecondVerKey (SK_Times _ vk _) = vk

trySign
  :: forall v a
   . ( KESAlgorithm v
     , KES.Signable v ~ ToCBOR
     , ContextKES v ~ ()
     , ToCBOR a
     , Show a
     )
  => SK_Times v a
  -> Either String [(Natural, a, SigKES v)]
trySign (SK_Times sk _ ts) =
    go sk ts
  where
    go :: SignKeyKES v
       -> [(Natural, a)]
       -> Either String [(Natural, a, SigKES v)]
    go _   [] = Right []
    go sk' l@((j, a) : xs)
      | currentPeriodKES () sk' < j =
        case updateKES () sk' j of
          Nothing   -> Left $ "trySign: error evolution of " ++ show sk
                           ++ " to KES period " ++ show j
          Just sk'' -> go sk'' l

      | otherwise =
        case signKES () j a sk' of
          Nothing   -> Left $ "trySign: error signing" ++ show a
                           ++ " at " ++ show j
                           ++ " with " ++ show sk
          Just sig  ->
            case updateKES () sk' (1 + currentPeriodKES () sk') of
              Nothing    -> Right [(j, a, sig)]
              Just sk'' ->
                case go sk'' xs of
                  Right ys -> Right ((j, a, sig) : ys)
                  e@Left{} -> e



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

instance (KES.Signable v Int, KESAlgorithm v, ContextKES v ~ ())
      => Arbitrary (SigKES v) where
  arbitrary = do
    a <- arbitrary :: Gen Int
    sk <- arbitrary
    let Just sig = signKES () 0 a sk
    return sig
  shrink = const []



data SK v = SK (SignKeyKES v) (VerKeyKES v)

deriving instance KESAlgorithm v => Show (SK v)

instance KESAlgorithm v => Arbitrary (SK v) where

    arbitrary = do
        (sk, _sk', _vk, vk') <- genKeys
          -- For the simple/mock key types, it's possible to generate the same
          -- key twice, since they're low entropy. So we filter those out.
          `suchThat` (\(_sk, _sk', vk, vk') -> vk /= vk')

        return (SK sk vk')
      where
        genKeys = do
          let seedSize = seedSizeKES (Proxy :: Proxy v)
          seed <- arbitrarySeedOfSize (seedSize * 2)
          let Just (kseed, kseed') = splitSeed (fromIntegral seedSize) seed
              sk  = genKeyKES kseed
              sk' = genKeyKES kseed'
              vk  = deriveVerKeyKES sk
              vk' = deriveVerKeyKES sk'
          return (sk, sk', vk, vk')

    shrink _ = []

data SK_Times v a =
     SK_Times (SignKeyKES v) (VerKeyKES v) [(Natural, a)]

deriving instance (KESAlgorithm v, Show a) => Show (SK_Times v a)

instance (KESAlgorithm v, Arbitrary a) => Arbitrary (SK_Times v a) where

    arbitrary = do
        SK sk vk <- arbitrary
        ts <- genTimes 0
        return (SK_Times sk vk ts)
      where
        genTimes :: Natural -> Gen [(Natural, a)]
        genTimes j
          | j >= duration = return []
          | otherwise = do
            k  <- genNatBetween j (duration - 1)
            a  <- arbitrary
            ns <- genTimes (k + 1)
            return ((k, a) : ns)
          where
            duration = totalPeriodsKES (Proxy :: Proxy v)

    shrink _ = []

