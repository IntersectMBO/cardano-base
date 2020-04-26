{-# LANGUAGE DeriveAnyClass       #-}
{-# LANGUAGE DeriveGeneric        #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.KES
  ( tests
  )
where

import Crypto.Random (MonadRandom)
import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)
import Numeric.Natural (Natural)
import Test.QuickCheck
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import Cardano.Binary (FromCBOR, ToCBOR(..), encodeListLen)
import Cardano.Crypto.DSIGN
import Cardano.Crypto.KES
import qualified Cardano.Crypto.KES as KES

import Test.Crypto.Orphans.Arbitrary ()
import Test.Crypto.Util
  ( TestSeed(..)
  , genNat
  , genNatBetween
  , prop_cbor
  , shrinkNat
  , withTestSeed
  )

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.KES"
  [ testKESAlgorithm (Proxy :: Proxy MockKES)                "MockKES"
  , testKESAlgorithm (Proxy :: Proxy (SimpleKES Ed448DSIGN)) "SimpleKES (with Ed448)"
  ]

-- We normally ensure that we avoid naively comparing signing keys by not
-- providing instances, but for tests it is fine, so we provide the orphan
-- instance here.
deriving instance (DSIGNAlgorithm d, Eq (SignKeyDSIGN d))
               => Eq (SignKeyKES (SimpleKES d))

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
  -> Duration_TestSeed_SK v
  -> Property
prop_KES_serialise_VerKey _ (Duration_TestSeed_SK _ _ sk _) =
  prop_cbor (deriveVerKeyKES sk)

prop_KES_serialise_SignKey
  :: ( KESAlgorithm v
     , FromCBOR (SignKeyKES v)
     , ToCBOR (SignKeyKES v)
     , Eq (SignKeyKES v)
     )
  => proxy v
  -> Duration_TestSeed_SK v
  -> Property
prop_KES_serialise_SignKey _ (Duration_TestSeed_SK _ _ sk _) = prop_cbor sk

prop_KES_serialise_Sig
  :: ( KESAlgorithm v
     , KES.Signable v ~ ToCBOR
     , ContextKES v ~ ()
     , FromCBOR (SigKES v)
     , ToCBOR (SigKES v)
     )
  => proxy v
  -> Duration_TestSeed_SK_Times v [Int]
  -> TestSeed
  -> Property
prop_KES_serialise_Sig _ d seed = case withTestSeed seed $ trySign d of
  Left  e  -> counterexample e False
  Right xs -> conjoin [ prop_cbor sig | (_, _, sig) <- xs ]

prop_KES_verify_pos
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> Duration_TestSeed_SK_Times v [Int]
  -> TestSeed
  -> Property
prop_KES_verify_pos _ d seed =
  let vk = getFirstVerKey d
  in
    case withTestSeed seed $ trySign d of
      Left e -> counterexample e False
      Right xs ->
        conjoin [ verifyKES () vk j a sig === Right () | (j, a, sig) <- xs ]

prop_KES_verify_neg_key
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> Duration_TestSeed_SK_Times v Int
  -> TestSeed
  -> Property
prop_KES_verify_neg_key _ d seed =
  getDuration d > 0 ==> case withTestSeed seed $ trySign d of
    Left  e  -> counterexample e False
    Right xs -> conjoin
      [ verifyKES () (getSecondVerKey d) j a sig =/= Right ()
      | (j, a, sig) <- xs
      ]

prop_KES_verify_neg_msg
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> Duration_TestSeed_SK_Times v Float
  -> Float
  -> TestSeed
  -> Property
prop_KES_verify_neg_msg _ d a seed =
  let vk = getFirstVerKey d
  in
    case withTestSeed seed $ trySign d of
      Left  e  -> counterexample e False
      Right xs -> conjoin
        [ a /= a' ==> verifyKES () vk j a sig =/= Right ()
        | (j, a', sig) <- xs
        ]

prop_KES_verify_neg_time
  :: (KESAlgorithm v, KES.Signable v ~ ToCBOR, ContextKES v ~ ())
  => proxy v
  -> Duration_TestSeed_SK_Times v Float
  -> Integer
  -> Property
prop_KES_verify_neg_time _ d i =
  let
    seed = TestSeed (1, 0, 2, 0, 1)
    vk   = getFirstVerKey d
    t    = fromIntegral $ abs i
  in case withTestSeed seed $ trySign d of
    Left  e  -> counterexample e False
    Right xs -> conjoin
      [ t /= j ==> verifyKES () vk t a sig =/= Right ()
      | (j, a, sig) <- xs
      ]

getDuration :: Duration_TestSeed_SK_Times v a -> Natural
getDuration d = case d of
  (Duration_TestSeed_SK_Times duration _ _ _ _) -> duration

getFirstVerKey :: KESAlgorithm v => Duration_TestSeed_SK_Times v a -> VerKeyKES v
getFirstVerKey d = case d of
  (Duration_TestSeed_SK_Times _ _ sk _ _) -> deriveVerKeyKES sk

getSecondVerKey :: Duration_TestSeed_SK_Times v a -> VerKeyKES v
getSecondVerKey d = case d of
  (Duration_TestSeed_SK_Times _ _ _ vk _) -> vk

trySign
  :: forall m v a
   . ( MonadRandom m
     , KESAlgorithm v
     , KES.Signable v ~ ToCBOR
     , ContextKES v ~ ()
     , ToCBOR a
     , Show a
     )
  => Duration_TestSeed_SK_Times v a
  -> m (Either String [(Natural, a, SigKES v)])
trySign (Duration_TestSeed_SK_Times _ _ sk _ ts) = go sk ts
 where
  go
    :: SignKeyKES v
    -> [(Natural, a)]
    -> m (Either String [(Natural, a, SigKES v)])
  go _   [] = return $ Right []
  go sk' l@((j, a) : xs) = do
    if currentPeriodKES () sk' < j
      then do
      sk'' <- updateKES () sk' j
      case sk'' of
        Nothing -> return $
          Left ("trySign: error evolution of " ++
          show sk ++
          " to KES period " ++ show j)
        Just sk''' -> go sk''' l
      else do
      m <- signKES () j a sk'
      case m of
        Nothing ->
          return
          $  Left
          $  "trySign: error signing "
          ++ show a
          ++ " at "
          ++ show j
          ++ " with "
          ++ show sk
        Just sig -> do
          sk'' <- updateKES () sk' (1 + currentPeriodKES () sk')
          case sk'' of
            Nothing -> pure $ Right [(j, a, sig)]
            Just sk''' -> do
              e <- go sk''' xs
              return $ case e of
                Right ys -> Right ((j, a, sig) : ys)
                Left  _  -> e

data Duration_TestSeed_SK v = Duration_TestSeed_SK Natural TestSeed (SignKeyKES v) (VerKeyKES v)
    deriving Generic

deriving instance KESAlgorithm v => Show (Duration_TestSeed_SK v)
deriving instance (KESAlgorithm v, Eq (SignKeyKES v)) => Eq (Duration_TestSeed_SK v)

instance
  (KESAlgorithm v, ToCBOR (SignKeyKES v), ToCBOR (VerKeyKES v))
  => ToCBOR (Duration_TestSeed_SK v)
 where
  toCBOR (Duration_TestSeed_SK n s sk vk) =
    encodeListLen 4
      <> toCBOR n
      <> toCBOR s
      <> toCBOR sk
      <> toCBOR vk

instance KESAlgorithm v => Arbitrary (Duration_TestSeed_SK v) where

    arbitrary = do
        duration <- genNat
        seed <- arbitrary
        return $ duration_TestSeed_SK duration seed

    shrink (Duration_TestSeed_SK duration seed _ _) =
        [duration_TestSeed_SK d seed | d <- shrinkNat duration]

data Duration_TestSeed_SK_Times v a =
    Duration_TestSeed_SK_Times Natural TestSeed (SignKeyKES v) (VerKeyKES v) [(Natural, a)]
    deriving Generic

instance (KESAlgorithm v, Arbitrary a) => Arbitrary (Duration_TestSeed_SK_Times v a) where

    arbitrary = arbitrary >>= gen_Duration_TestSeed_SK_Times

    shrink (Duration_TestSeed_SK_Times d s sk vk ts) = do
        Duration_TestSeed_SK d' s' sk' vk' <- shrink $ Duration_TestSeed_SK d s sk vk
        let ts' = filter ((< d') . fst) ts
        return $ Duration_TestSeed_SK_Times d' s' sk' vk' ts'

deriving instance (KESAlgorithm v, Show a) => Show (Duration_TestSeed_SK_Times v a)
deriving instance (KESAlgorithm v, Eq (SignKeyKES v), Eq a) => Eq (Duration_TestSeed_SK_Times v a)

instance
  (KESAlgorithm v, ToCBOR a, ToCBOR (SignKeyKES v), ToCBOR (VerKeyKES v))
  => ToCBOR (Duration_TestSeed_SK_Times v a)
 where
  toCBOR (Duration_TestSeed_SK_Times d s sk vk ts) =
    encodeListLen 5
      <> toCBOR d
      <> toCBOR s
      <> toCBOR sk
      <> toCBOR vk
      <> toCBOR ts

duration_TestSeed_SK :: KESAlgorithm v => Natural -> TestSeed -> Duration_TestSeed_SK v
duration_TestSeed_SK duration seed =
  let (sk, vk) = withTestSeed seed go in Duration_TestSeed_SK duration seed sk vk
 where
  go = do
    sk  <- genKeyKES duration
    sk' <- genKeyKES duration
    let vk = deriveVerKeyKES sk'
    if duration > 0 && deriveVerKeyKES sk == vk then go else return (sk, vk)

gen_Duration_TestSeed_SK_Times
  :: Arbitrary a => Duration_TestSeed_SK v -> Gen (Duration_TestSeed_SK_Times v a)
gen_Duration_TestSeed_SK_Times (Duration_TestSeed_SK duration seed sk vk) = do
  ts <- genTimes 0
  return $ Duration_TestSeed_SK_Times duration seed sk vk ts
 where
  genTimes :: Arbitrary a => Natural -> Gen [(Natural, a)]
  genTimes j
    | j >= duration = return []
    | otherwise = do
      k  <- genNatBetween j (duration - 1)
      a  <- arbitrary
      ns <- genTimes $ k + 1
      return ((k, a) : ns)
