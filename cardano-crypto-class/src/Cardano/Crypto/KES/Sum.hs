{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoStarIsType #-}

-- | A key evolving signatures implementation.
--
-- It is a naive recursive implementation of the sum composition from
-- section 3.1 of the \"MMM\" paper:
--
-- /Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures/
-- By Tal Malkin, Daniele Micciancio and Sara Miner
-- <https://eprint.iacr.org/2001/034>
--
-- Specfically we do the binary sum composition directly as in the paper, and
-- then use that in a nested\/recursive fashion to construct a 7-level deep
-- binary tree version.
--
-- This relies on "Cardano.Crypto.KES.Single" for the base case.
--
-- NOTE - some functions in this module have been deliberately marked NOINLINE;
-- this is necessary to avoid an edge case in GHC that causes the simplifier to
-- go haywire, leading to a @Simplifier ticks exhausted@ error and very long
-- compilation times. Worse yet, this error will only appear when compiling
-- code that depends on this module, not when compiling the module itself.
module Cardano.Crypto.KES.Sum (
    SumKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)

    -- * Type aliases for powers of binary sums
  , Sum0KES
  , Sum1KES
  , Sum2KES
  , Sum3KES
  , Sum4KES
  , Sum5KES
  , Sum6KES
  , Sum7KES
  ) where

import           Data.Proxy (Proxy(..))
import           GHC.Generics (Generic)
import qualified Data.ByteString as BS
import           Control.Monad (guard, (<$!>))
import           NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

import           Cardano.Binary (FromCBOR (..), ToCBOR (..))

import           Cardano.Crypto.Hash.Class
import           Cardano.Crypto.KES.Class
import           Cardano.Crypto.KES.Single (SingleKES)
import           Cardano.Crypto.Util
import           Cardano.Crypto.MLockedSeed
import           Cardano.Crypto.MonadMLock
import           Control.Monad.Class.MonadST (MonadST (..))
import           Control.Monad.Class.MonadThrow (MonadThrow)
import           Control.Monad.Trans.Maybe (MaybeT (..), runMaybeT)
import           Control.DeepSeq (NFData (..))
import           GHC.TypeLits (KnownNat, type (+), type (*))


-- | A 2^0 period KES
type Sum0KES d   = SingleKES d

-- | A 2^1 period KES
type Sum1KES d h = SumKES h (Sum0KES d)

-- | A 2^2 period KES
type Sum2KES d h = SumKES h (Sum1KES d h)

-- | A 2^3 period KES
type Sum3KES d h = SumKES h (Sum2KES d h)

-- | A 2^4 period KES
type Sum4KES d h = SumKES h (Sum3KES d h)

-- | A 2^5 period KES
type Sum5KES d h = SumKES h (Sum4KES d h)

-- | A 2^6 period KES
type Sum6KES d h = SumKES h (Sum5KES d h)

-- | A 2^7 period KES
type Sum7KES d h = SumKES h (Sum6KES d h)


-- | A composition of two KES schemes to give a KES scheme with the sum of
-- the time periods.
--
-- While we could do this with two independent KES schemes (i.e. two types)
-- we only need it for two instances of the same scheme, and we save
-- substantially on the size of the type and runtime dictionaries if we do it
-- this way, especially when we start applying it recursively.
--
data SumKES h d

instance (NFData (SigKES d), NFData (VerKeyKES d)) =>
  NFData (SigKES (SumKES h d)) where

instance (NFData (SignKeyKES d), NFData (VerKeyKES d)) =>
  NFData (SignKeyKES (SumKES h d)) where
    rnf (SignKeySumKES sk r vk1 vk2) =
      rnf (sk, r, vk1, vk2)

instance ( KESAlgorithm d
         , SodiumHashAlgorithm h -- needed for secure forgetting
         , SizeHash h ~ SeedSizeKES d -- can be relaxed
         , KnownNat ((SizeSignKeyKES d + SeedSizeKES d) + (2 * SizeVerKeyKES d))
         , KnownNat (SizeSigKES d + (SizeVerKeyKES d * 2))
         )
      => KESAlgorithm (SumKES h d) where

    type SeedSizeKES (SumKES h d) = SeedSizeKES d

    --
    -- Key and signature types
    --

    -- | From Section 3,1:
    --
    -- The verification key @vk@ for the sum scheme is the hash of the
    -- verification keys @vk_0, vk_1@ of the two constituent schemes.
    --
    newtype VerKeyKES (SumKES h d) =
              VerKeySumKES (Hash h (VerKeyKES d, VerKeyKES d))
        deriving Generic
        deriving newtype NFData

    -- | From Figure 3: @(sigma, vk_0, vk_1)@
    --
    data SigKES (SumKES h d) =
           SigSumKES !(SigKES d)
                     !(VerKeyKES d)
                     !(VerKeyKES d)
        deriving Generic


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES _ = mungeName (algorithmNameKES (Proxy :: Proxy d))

    -- The verification key in this scheme is actually a hash already
    -- however the type of hashVerKeyKES says the caller gets to choose
    -- the hash, not the implementation. So that's why we have to hash
    -- the hash here. We could alternatively provide a "key identifier"
    -- function and let the implementation choose what that is.
    hashVerKeyKES (VerKeySumKES vk) = castHash (hashWith hashToBytes vk)


    --
    -- Core algorithm operations
    --

    type Signable   (SumKES h d) = Signable   d
    type ContextKES (SumKES h d) = ContextKES d

    verifyKES ctxt (VerKeySumKES vk) t a (SigSumKES sigma vk_0 vk_1)
      | hashPairOfVKeys (vk_0, vk_1) /= vk
                  = Left "Reject"
      | t < _T    = verifyKES ctxt vk_0  t       a sigma
      | otherwise = verifyKES ctxt vk_1 (t - _T) a sigma
      where
        _T = totalPeriodsKES (Proxy :: Proxy d)

    totalPeriodsKES  _ = 2 * totalPeriodsKES (Proxy :: Proxy d)

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES (SumKES h d) = SizeHash h
    type SizeSignKeyKES (SumKES h d) = SizeSignKeyKES d
                                       + SeedSizeKES d
                                       + 2 * SizeVerKeyKES d
    type SizeSigKES (SumKES h d) = SizeSigKES d
                                   + SizeVerKeyKES d * 2

    rawSerialiseVerKeyKES  (VerKeySumKES  vk) = hashToBytes vk

    rawSerialiseSigKES (SigSumKES sigma vk_0 vk_1) =
      mconcat
        [ rawSerialiseSigKES sigma
        , rawSerialiseVerKeyKES vk_0
        , rawSerialiseVerKeyKES vk_1
        ]

    rawDeserialiseVerKeyKES = fmap VerKeySumKES  . hashFromBytes

    rawDeserialiseSigKES b = do
        guard (BS.length b == fromIntegral size_total)
        sigma <- rawDeserialiseSigKES    b_sig
        vk_0  <- rawDeserialiseVerKeyKES b_vk0
        vk_1  <- rawDeserialiseVerKeyKES b_vk1
        return (SigSumKES sigma vk_0 vk_1)
      where
        b_sig = slice off_sig size_sig b
        b_vk0 = slice off_vk0 size_vk  b
        b_vk1 = slice off_vk1 size_vk  b

        size_sig   = sizeSigKES    (Proxy :: Proxy d)
        size_vk    = sizeVerKeyKES (Proxy :: Proxy d)
        size_total = sizeSigKES    (Proxy :: Proxy (SumKES h d))

        off_sig    = 0 :: Word
        off_vk0    = size_sig
        off_vk1    = off_vk0 + size_vk

instance ( KESSignAlgorithm m d
         , SodiumHashAlgorithm h -- needed for secure forgetting
         , SizeHash h ~ SeedSizeKES d -- can be relaxed
         , MonadST m
         , MonadThrow m
         , KnownNat ((SizeSignKeyKES d + SeedSizeKES d) + (2 * SizeVerKeyKES d))
         , KnownNat (SizeSigKES d + (SizeVerKeyKES d * 2))
         )
      => KESSignAlgorithm m (SumKES h d) where
    -- | From Figure 3: @(sk_0, r_1, vk_0, vk_1)@
    --
    data SignKeyKES (SumKES h d) =
           SignKeySumKES !(SignKeyKES d)
                         !(MLockedSeed (SeedSizeKES d))
                         !(VerKeyKES d)
                         !(VerKeyKES d)


    deriveVerKeyKES (SignKeySumKES _ _ vk_0 vk_1) =
        return $! VerKeySumKES (hashPairOfVKeys (vk_0, vk_1))

    signKES ctxt t a (SignKeySumKES sk _r_1 vk_0 vk_1) = do
        sigma <- getSigma
        return $! SigSumKES sigma vk_0 vk_1
      where
        getSigma
          | t < _T    = signKES ctxt  t       a sk
          | otherwise = signKES ctxt (t - _T) a sk

        _T = totalPeriodsKES (Proxy :: Proxy d)

    {-# NOINLINE updateKES #-}
    updateKES ctx (SignKeySumKES sk r_1 vk_0 vk_1) t
      | t+1 <  _T = runMaybeT $!
                      do
                        sk' <- MaybeT $! updateKES ctx sk t
                        r_1' <- MaybeT $! Just <$!> mlockedSeedCopy r_1
                        return $! SignKeySumKES sk' r_1' vk_0 vk_1
      | t+1 == _T = do
                        sk' <- genKeyKES r_1
                        r_1' <- mlockedSeedNewZero
                        return $! Just $! SignKeySumKES sk' r_1' vk_0 vk_1
      | otherwise = runMaybeT $
                      do
                        sk' <- MaybeT $! updateKES ctx sk (t - _T)
                        r_1' <- MaybeT $! Just <$!> mlockedSeedCopy r_1
                        return $! SignKeySumKES sk' r_1' vk_0 vk_1
      where
        _T = totalPeriodsKES (Proxy :: Proxy d)

    --
    -- Key generation
    --

    {-# NOINLINE genKeyKES #-}
    genKeyKES r = do
      (r0raw, r1raw) <- expandHash (Proxy :: Proxy h) (mlockedSeedMLSB r)
      let r0 = MLockedSeed r0raw
          r1 = MLockedSeed r1raw
      sk_0 <- genKeyKES r0
      vk_0 <- deriveVerKeyKES sk_0
      sk_1 <- genKeyKES r1
      vk_1 <- deriveVerKeyKES sk_1
      forgetSignKeyKES sk_1
      mlockedSeedFinalize r0
      return $! SignKeySumKES sk_0 r1 vk_0 vk_1

    --
    -- forgetting
    --
    forgetSignKeyKES (SignKeySumKES sk_0 r1 _ _) = do
      forgetSignKeyKES sk_0
      mlockedSeedFinalize r1

instance ( KESSignAlgorithm m (SumKES h d)
         , UnsoundKESSignAlgorithm m d
         , MonadST m
         ) => UnsoundKESSignAlgorithm m (SumKES h d) where
    --
    -- Raw serialise/deserialise - dangerous, do not use in production code.
    --

    {-# NOINLINE rawSerialiseSignKeyKES #-}
    rawSerialiseSignKeyKES (SignKeySumKES sk r_1 vk_0 vk_1) = do
      ssk <- rawSerialiseSignKeyKES sk
      sr1 <- mlsbToByteString . mlockedSeedMLSB $ r_1
      return $ mconcat
                  [ ssk
                  , sr1
                  , rawSerialiseVerKeyKES vk_0
                  , rawSerialiseVerKeyKES vk_1
                  ]

    {-# NOINLINE rawDeserialiseSignKeyKES #-}
    rawDeserialiseSignKeyKES b = runMaybeT $ do
        guard (BS.length b == fromIntegral size_total)
        sk   <- MaybeT $ rawDeserialiseSignKeyKES b_sk
        r <- MaybeT $ mlsbFromByteStringCheck b_r
        vk_0 <- MaybeT . return $ rawDeserialiseVerKeyKES  b_vk0
        vk_1 <- MaybeT . return $ rawDeserialiseVerKeyKES  b_vk1
        return (SignKeySumKES sk (MLockedSeed r) vk_0 vk_1)
      where
        b_sk  = slice off_sk  size_sk b
        b_r   = slice off_r   size_r  b
        b_vk0 = slice off_vk0 size_vk b
        b_vk1 = slice off_vk1 size_vk b

        size_sk    = sizeSignKeyKES (Proxy :: Proxy d)
        size_r     = seedSizeKES    (Proxy :: Proxy d)
        size_vk    = sizeVerKeyKES  (Proxy :: Proxy d)
        size_total = sizeSignKeyKES (Proxy :: Proxy (SumKES h d))

        off_sk     = 0 :: Word
        off_r      = size_sk
        off_vk0    = off_r + size_r
        off_vk1    = off_vk0 + size_vk


--
-- VerKey instances
--

deriving instance HashAlgorithm h => Show (VerKeyKES (SumKES h d))
deriving instance Eq   (VerKeyKES (SumKES h d))

instance (KESAlgorithm (SumKES h d), SodiumHashAlgorithm h, SizeHash h ~ SeedSizeKES d)
      => ToCBOR (VerKeyKES (SumKES h d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance (KESAlgorithm (SumKES h d), SodiumHashAlgorithm h, SizeHash h ~ SeedSizeKES d)
      => FromCBOR (VerKeyKES (SumKES h d)) where
  fromCBOR = decodeVerKeyKES

instance (KESAlgorithm d) => NoThunks (VerKeyKES  (SumKES h d))

--
-- SignKey instances
--

-- These instances would violate mlocking protections, bleeding secret keys
-- onto the GHC heap.
--
-- instance (KESAlgorithm d, HashAlgorithm h, SizeHash h ~ SeedSizeKES d)
--       => ToCBOR (SignKeyKES (SumKES h d)) where
--   toCBOR = encodeSignKeyKES
--   encodedSizeExpr _size = encodedSignKeyKESSizeExpr
--
-- instance (KESAlgorithm d, HashAlgorithm h, SizeHash h ~ SeedSizeKES d)
--       => FromCBOR (SignKeyKES (SumKES h d)) where
--   fromCBOR = decodeSignKeyKES

deriving via OnlyCheckWhnfNamed "SignKeyKES (SumKES h d)" (SignKeyKES (SumKES h d))
  instance NoThunks (SignKeyKES (SumKES h d))

--
-- Sig instances
--

deriving instance (KESAlgorithm d, KESAlgorithm (SumKES h d)) => Show (SigKES (SumKES h d))
deriving instance (KESAlgorithm d, KESAlgorithm (SumKES h d)) => Eq (SigKES (SumKES h d))

instance KESAlgorithm d => NoThunks (SigKES (SumKES h d))

instance (KESAlgorithm (SumKES h d), SodiumHashAlgorithm h, SizeHash h ~ SeedSizeKES d)
      => ToCBOR (SigKES (SumKES h d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance (KESAlgorithm (SumKES h d), SodiumHashAlgorithm h, SizeHash h ~ SeedSizeKES d)
      => FromCBOR (SigKES (SumKES h d)) where
  fromCBOR = decodeSigKES
