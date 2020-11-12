{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

module Test.Crypto.KES.NoSalt where

import Cardano.Crypto.DSIGN
import Cardano.Crypto.Hash (Hash, HashAlgorithm, SizeHash, hashToBytes, hashWith)
import Cardano.Crypto.KES (totalPeriodsKES, KESAlgorithm (seedSizeKES), Period, SeedSizeKES, SingleKES, SumKES)
import Cardano.Crypto.Libsodium (SodiumDSIGNAlgorithm, SodiumHashAlgorithm)
import Cardano.Crypto.Seed (expandSeed, getSeedBytes)
import Cardano.Crypto.Util (SignableRepresentation)
import Cardano.Prelude (NFData)
import Control.Exception (assert)
import Data.ByteString (ByteString)
import Data.Proxy
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import Test.Crypto.Util (arbitrarySeedOfSize)
import Test.QuickCheck

class
  ( KESAlgorithm v,
    Show (SignKeyKES v),
    Show (VerKeyKES v)
  ) =>
  NoSalt v
  where
  data SignKeyKES v
  data VerKeyKES v
  data SigKES v

  signKES ::
    SignableRepresentation a =>
    -- | The /current/ period for the key
    Period ->
    a ->
    SignKeyKES v ->
    SigKES v

  verifyKES ::
    (SignableRepresentation a) =>
    VerKeyKES v ->
    -- | The /current/ period for the key
    Period ->
    a ->
    SigKES v ->
    Either String ()

  genKeyKES :: Seed -> SignKeyKES v
  deriveVerKeyKES :: SignKeyKES v -> VerKeyKES v

  rawSerialiseVerKeyKES :: VerKeyKES v -> ByteString
  rawSerialiseSignKeyKES :: SignKeyKES v -> ByteString
  rawSerialiseSigKES :: SigKES v -> ByteString

instance
  ( Typeable d,
    SodiumDSIGNAlgorithm d
  ) =>
  NoSalt (SingleKES d)
  where
  newtype VerKeyKES (SingleKES d) = VerKeySingleKES (VerKeyDSIGN d)
    deriving (Generic)

  newtype SignKeyKES (SingleKES d) = SignKeySingleKES (SignKeyDSIGN d)
    deriving (Generic)

  newtype SigKES (SingleKES d) = SigSingleKES (SigDSIGN d)
    deriving (Generic)

  genKeyKES seed = SignKeySingleKES (genKeyDSIGN seed)
  deriveVerKeyKES (SignKeySingleKES sk) =
    VerKeySingleKES (deriveVerKeyDSIGN sk)

  signKES t a (SignKeySingleKES sk) =
    assert (t == 0) $
      SigSingleKES (signDSIGN () a sk)

  verifyKES (VerKeySingleKES vk) t a (SigSingleKES sig) =
    assert (t == 0) $
      verifyDSIGN () vk a sig

  rawSerialiseVerKeyKES (VerKeySingleKES vk) = rawSerialiseVerKeyDSIGN vk
  rawSerialiseSignKeyKES (SignKeySingleKES sk) = rawSerialiseSignKeyDSIGN sk
  rawSerialiseSigKES (SigSingleKES sig) = rawSerialiseSigDSIGN sig

instance
  ( Typeable d,
    SodiumHashAlgorithm h,
    NoSalt d,
    SizeHash h ~ SeedSizeKES d -- can be relaxed
  ) =>
  NoSalt (SumKES h d)
  where
  newtype VerKeyKES (SumKES h d)
    = VerKeySumKES (Hash h (VerKeyKES d, VerKeyKES d))
    deriving (Generic)
    deriving newtype (NFData)

  data SignKeyKES (SumKES h d)
    = SignKeySumKES
        !(SignKeyKES d)
        !Seed
        !(VerKeyKES d)
        !(VerKeyKES d)
    deriving (Generic)

  data SigKES (SumKES h d)
    = SigSumKES
        !(SigKES d)
        !(VerKeyKES d)
        !(VerKeyKES d)
    deriving (Generic)

  genKeyKES r = SignKeySumKES sk_0 r1 vk_0 vk_1
    where
      (r0, r1) = expandSeed (Proxy :: Proxy h) r

      sk_0 = genKeyKES r0
      vk_0 = deriveVerKeyKES sk_0

      sk_1 = genKeyKES r1
      vk_1 = deriveVerKeyKES sk_1
  deriveVerKeyKES (SignKeySumKES _ _ vk_0 vk_1) =
    VerKeySumKES (hashPairOfVKeys (vk_0, vk_1))

  signKES t a (SignKeySumKES sk _r_1 vk_0 vk_1) =
      SigSumKES sigma vk_0 vk_1
    where
      sigma | t < _T    = signKES  t       a sk
            | otherwise = signKES (t - _T) a sk

      _T = totalPeriodsKES (Proxy :: Proxy d)

  verifyKES (VerKeySumKES vk) t a (SigSumKES sigma vk_0 vk_1)
    | hashPairOfVKeys (vk_0, vk_1) /= vk
                = Left "Reject"
    | t < _T    = verifyKES vk_0  t       a sigma
    | otherwise = verifyKES vk_1 (t - _T) a sigma
    where
      _T = totalPeriodsKES (Proxy :: Proxy d)

  rawSerialiseVerKeyKES (VerKeySumKES vk) = hashToBytes vk

  rawSerialiseSignKeyKES (SignKeySumKES sk r_1 vk_0 vk_1) =
    mconcat
      [ rawSerialiseSignKeyKES sk,
        getSeedBytes r_1,
        rawSerialiseVerKeyKES vk_0,
        rawSerialiseVerKeyKES vk_1
      ]

  rawSerialiseSigKES (SigSumKES sigma vk_0 vk_1) =
    mconcat
      [ rawSerialiseSigKES sigma,
        rawSerialiseVerKeyKES vk_0,
        rawSerialiseVerKeyKES vk_1
      ]

hashPairOfVKeys ::
  (HashAlgorithm h, NoSalt d) =>
  (VerKeyKES d, VerKeyKES d) ->
  Hash h (VerKeyKES d, VerKeyKES d)
hashPairOfVKeys =
  hashWith $ \(a, b) ->
    rawSerialiseVerKeyKES a <> rawSerialiseVerKeyKES b

instance NoSalt v => Arbitrary (VerKeyKES v) where
  arbitrary = deriveVerKeyKES <$> arbitrary
  shrink = const []

instance NoSalt v => Arbitrary (SignKeyKES v) where
  arbitrary = genKeyKES <$> arbitrarySeedOfSize seedSize
    where
      seedSize = seedSizeKES (Proxy :: Proxy v)
  shrink = const []

deriving instance DSIGNAlgorithm d => Show (SignKeyKES (SingleKES d))

deriving instance DSIGNAlgorithm d => Show (VerKeyKES (SingleKES d))

deriving instance NoSalt d => Show (SignKeyKES (SumKES h d))

deriving instance NoSalt d => Show (VerKeyKES (SumKES h d))
