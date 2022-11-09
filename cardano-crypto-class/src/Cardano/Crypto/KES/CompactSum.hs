{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
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
-- This relies on "Cardano.Crypto.KES.CompactSingle" for the base case.
--
-- Compared to the implementation in 'Cardano.Crypto.KES.Sum', this flavor
-- stores only one VerKey in the branch node.
--
-- Consider the following Merkle tree:
--
-- @
--       (A)
--      /   \
--   (B)     (C)
--   / \     / \
-- (D) (E) (F) (G)
--      ^
--  0   1   2   3
-- @
--
-- The caret points at leaf node E, indicating that the current period is 1.
-- The signatures for leaf nodes D through G all contain their respective
-- DSIGN keys; the signature for branch node B however only holds the signature
-- for node E, and the VerKey for node D. It can reconstruct its own VerKey
-- from these two. The signature for branch node A (the root node), then, only
-- contains the VerKey for node C, and the signature for node B. In other
-- words, the number of individual hashes to be stored equals the depth of the
-- Merkle tree. Compare that to the older, naive 'SumKES', where each branch
-- node stores two VerKeys: here, the number of keys to store is the depth of
-- the tree times two.
--
-- Note that when we verify such a signature, we need to also compare the
-- ultimate VerKey at the root against the one passed in externally, because
-- all VerKeys until that point have been derived from the (user-supplied, so
-- untrusted) signature. But we only need to do this once, at the tree root,
-- so we split up the verification into two parts: verifying a signature
-- against its embedded VerKey, and comparing that VerKey against the
-- externally supplied target key.
module Cardano.Crypto.KES.CompactSum (
    CompactSumKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)

    -- * Type aliases for powers of binary sums
  , CompactSum0KES
  , CompactSum1KES
  , CompactSum2KES
  , CompactSum3KES
  , CompactSum4KES
  , CompactSum5KES
  , CompactSum6KES
  , CompactSum7KES
  ) where

import           Data.Proxy (Proxy(..))
import           GHC.Generics (Generic)
import           GHC.TypeLits (KnownNat, type (+), type (*))
import qualified Data.ByteString as BS
import           Control.Monad (guard)
import           Control.Monad.Trans (lift)
import           Control.Monad.Trans.Maybe (MaybeT (..), runMaybeT)
import           Control.DeepSeq (NFData)
import           NoThunks.Class (NoThunks)

import           Cardano.Binary (FromCBOR (..), ToCBOR (..))

import           Cardano.Crypto.Hash.Class
import           Cardano.Crypto.KES.Class
import           Cardano.Crypto.KES.CompactSingle (CompactSingleKES)
import qualified Cardano.Crypto.MonadSodium as NaCl

import           Cardano.Crypto.Util

-- | A 2^0 period KES
type CompactSum0KES d   = CompactSingleKES d

-- | A 2^1 period KES
type CompactSum1KES d h = CompactSumKES h (CompactSum0KES d)

-- | A 2^2 period KES
type CompactSum2KES d h = CompactSumKES h (CompactSum1KES d h)

-- | A 2^3 period KES
type CompactSum3KES d h = CompactSumKES h (CompactSum2KES d h)

-- | A 2^4 period KES
type CompactSum4KES d h = CompactSumKES h (CompactSum3KES d h)

-- | A 2^5 period KES
type CompactSum5KES d h = CompactSumKES h (CompactSum4KES d h)

-- | A 2^6 period KES
type CompactSum6KES d h = CompactSumKES h (CompactSum5KES d h)

-- | A 2^7 period KES
type CompactSum7KES d h = CompactSumKES h (CompactSum6KES d h)


-- | A composition of two KES schemes to give a KES scheme with the sum of
-- the time periods.
--
-- While we could do this with two independent KES schemes (i.e. two types)
-- we only need it for two instances of the same scheme, and we save
-- substantially on the size of the type and runtime dictionaries if we do it
-- this way, especially when we start applying it recursively.
--
data CompactSumKES h d

instance (NFData (SigKES d), NFData (VerKeyKES d)) =>
  NFData (SigKES (CompactSumKES h d)) where

instance (NFData (SignKeyKES d), NFData (VerKeyKES d)) =>
  NFData (SignKeyKES (CompactSumKES h d)) where

instance ( OptimizedKESAlgorithm d
         , NaCl.SodiumHashAlgorithm h
         , SizeHash h ~ SeedSizeKES d -- can be relaxed
         , NoThunks (VerKeyKES (CompactSumKES h d))
         , KnownNat (SizeVerKeyKES (CompactSumKES h d))
         , KnownNat (SizeSignKeyKES (CompactSumKES h d))
         , KnownNat (SizeSigKES (CompactSumKES h d))
         )
      => KESAlgorithm (CompactSumKES h d) where

    type SeedSizeKES (CompactSumKES h d) = SeedSizeKES d

    --
    -- Key and signature types
    --

    -- | From Section 3,1:
    --
    -- The verification key @vk@ for the sum scheme is the hash of the
    -- verification keys @vk_0, vk_1@ of the two constituent schemes.
    --
    newtype VerKeyKES (CompactSumKES h d) =
              VerKeyCompactSumKES (Hash h (VerKeyKES d, VerKeyKES d))
        deriving Generic
        deriving newtype NFData

    -- | From Figure 3: @(sk_0, r_1, vk_0, vk_1)@
    --
    data SignKeyKES (CompactSumKES h d) =
           SignKeyCompactSumKES !(SignKeyKES d)
                         !(NaCl.SafePinned (NaCl.MLockedSizedBytes (SeedSizeKES d)))
                         !(VerKeyKES d)
                         !(VerKeyKES d)
        deriving Generic

    -- | Figure 3 gives: @(sigma, vk_0, vk_1)@ - however, we store only the
    -- \"off-side\" VK in the branch, and calculate the \"on-side\" one from
    -- the leaf VK (stored in the leaf node, see 'CompactSingleKES') and the
    -- \"off-side\" VK's along the Merkle path.
    --
    data SigKES (CompactSumKES h d) =
           SigCompactSumKES !(SigKES d) -- includes VerKeys for the Merkle subpath
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
    hashVerKeyKES (VerKeyCompactSumKES vk) = castHash (hashWith hashToBytes vk)


    --
    -- Core algorithm operations
    --

    type Signable   (CompactSumKES h d) = Signable   d
    type ContextKES (CompactSumKES h d) = ContextKES d

    verifyKES = verifyOptimizedKES

    totalPeriodsKES  _ = 2 * totalPeriodsKES (Proxy :: Proxy d)


    --
    -- Key generation
    --

    seedSizeKES _ = seedSizeKES (Proxy :: Proxy d)

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES  _ = SizeHash       h
    type SizeSignKeyKES _ = SizeSignKeyKES d
                          + SeedSizeKES    d
                          + SizeVerKeyKES  d * 2
    type SizeSigKES     _ = SizeSigKES     d
                          + SizeVerKeyKES  d

    rawSerialiseVerKeyKES  (VerKeyCompactSumKES  vk) = hashToBytes vk

    rawSerialiseSigKES (SigCompactSumKES sigma vk_other) =
      mconcat
        [ rawSerialiseSigKES sigma
        , rawSerialiseVerKeyKES vk_other
        ]

    rawDeserialiseVerKeyKES = fmap VerKeyCompactSumKES  . hashFromBytes

    rawDeserialiseSigKES b = do
        guard (BS.length b == fromIntegral size_total)
        sigma <- rawDeserialiseSigKES    b_sig
        vk  <- rawDeserialiseVerKeyKES b_vk
        return (SigCompactSumKES sigma vk)
      where
        b_sig = slice off_sig size_sig b
        b_vk  = slice off_vk  size_vk  b

        size_sig   = sizeSigKES    (Proxy :: Proxy d)
        size_vk    = sizeVerKeyKES (Proxy :: Proxy d)
        size_total = sizeSigKES    (Proxy :: Proxy (CompactSumKES h d))

        off_sig    = 0 :: Word
        off_vk     = size_sig

instance ( OptimizedKESAlgorithm d
         , KESSignAlgorithm m d
         , NaCl.SodiumHashAlgorithm h -- needed for secure forgetting
         , SizeHash h ~ SeedSizeKES d -- can be relaxed
         , NaCl.MonadSodium m
         , NoThunks (VerKeyKES (CompactSumKES h d))
         , KnownNat (SizeVerKeyKES (CompactSumKES h d))
         , KnownNat (SizeSignKeyKES (CompactSumKES h d))
         , KnownNat (SizeSigKES (CompactSumKES h d))
         )
      => KESSignAlgorithm m (CompactSumKES h d) where

    deriveVerKeyKES (SignKeyCompactSumKES _ _ vk_0 vk_1) =
        return $ VerKeyCompactSumKES (hashPairOfVKeys (vk_0, vk_1))

    signKES ctxt t a (SignKeyCompactSumKES sk _r_1 vk_0 vk_1) = do
        sigma <- getSigma
        return $ SigCompactSumKES sigma vk_other
      where
        (getSigma, vk_other)
          | t < _T    = (signKES ctxt  t       a sk, vk_1)
          | otherwise = (signKES ctxt (t - _T) a sk, vk_0)

        _T = totalPeriodsKES (Proxy :: Proxy d)

    updateKES ctx (SignKeyCompactSumKES sk r_1 vk_0 vk_1) t
      | t+1 <  _T = runMaybeT $
                      do
                        sk' <- MaybeT $ updateKES ctx sk t
                        r_1' <- lift $ NaCl.mapSafePinned NaCl.mlsbCopy r_1
                        return $ SignKeyCompactSumKES sk' r_1' vk_0 vk_1

      | t+1 == _T = do
                        sk' <- NaCl.interactSafePinned r_1 genKeyKES
                        zero <- NaCl.makeSafePinned =<< NaCl.mlsbNew
                        return . Just $ SignKeyCompactSumKES sk' zero vk_0 vk_1
      | otherwise = runMaybeT $
                      do
                        sk' <- MaybeT $ updateKES ctx sk (t - _T)
                        r_1' <- lift $ NaCl.mapSafePinned NaCl.mlsbCopy r_1
                        return $ SignKeyCompactSumKES sk' r_1' vk_0 vk_1
      where
        _T = totalPeriodsKES (Proxy :: Proxy d)

    --
    -- Key generation
    --

    genKeyKES r = do
      (rr0, rr1) <- NaCl.expandHash (Proxy :: Proxy h) r
      r0 <- NaCl.makeSafePinned rr0
      r1 <- NaCl.makeSafePinned rr1
      sk_0 <- NaCl.interactSafePinned r0 genKeyKES
      vk_0 <- deriveVerKeyKES sk_0
      sk_1 <- NaCl.interactSafePinned r1 genKeyKES
      vk_1 <- deriveVerKeyKES @m @d sk_1
      forgetSignKeyKES sk_1
      NaCl.releaseSafePinned r0
      return $ SignKeyCompactSumKES sk_0 r1 vk_0 vk_1

    --
    -- forgetting
    --
    forgetSignKeyKES (SignKeyCompactSumKES sk_0 r1 _ _) = do
        forgetSignKeyKES sk_0
        NaCl.releaseSafePinned r1

    --
    -- raw serialise/deserialise
    --

    rawSerialiseSignKeyKES (SignKeyCompactSumKES sk r_1 vk_0 vk_1) = do
      ssk <- rawSerialiseSignKeyKES sk
      rr1 <- NaCl.interactSafePinned r_1 return
      return $ mconcat
                  [ ssk
                  , NaCl.mlsbToByteString rr1
                  , rawSerialiseVerKeyKES vk_0
                  , rawSerialiseVerKeyKES vk_1
                  ]

    rawDeserialiseSignKeyKES b = runMaybeT $ do
        guard (BS.length b == fromIntegral size_total)
        sk   <- MaybeT $ rawDeserialiseSignKeyKES b_sk
        rr <- MaybeT $ NaCl.mlsbFromByteStringCheck b_r
        r <- MaybeT . fmap Just $ NaCl.makeSafePinned rr
        vk_0 <- MaybeT . return $ rawDeserialiseVerKeyKES  b_vk0
        vk_1 <- MaybeT . return $ rawDeserialiseVerKeyKES  b_vk1
        return (SignKeyCompactSumKES sk r vk_0 vk_1)
      where
        b_sk  = slice off_sk  size_sk b
        b_r   = slice off_r   size_r  b
        b_vk0 = slice off_vk0 size_vk b
        b_vk1 = slice off_vk1 size_vk b

        size_sk    = sizeSignKeyKES (Proxy :: Proxy d)
        size_r     = seedSizeKES    (Proxy :: Proxy d)
        size_vk    = sizeVerKeyKES  (Proxy :: Proxy d)
        size_total = sizeSignKeyKES (Proxy :: Proxy (CompactSumKES h d))

        off_sk     = 0 :: Word
        off_r      = size_sk
        off_vk0    = off_r + size_r
        off_vk1    = off_vk0 + size_vk



instance (KESAlgorithm (CompactSumKES h d), OptimizedKESAlgorithm d, HashAlgorithm h) =>
         OptimizedKESAlgorithm (CompactSumKES h d) where

    verifySigKES ctxt t a (SigCompactSumKES sigma _) =
      verifySigKES ctxt t' a sigma
      where
        _T = totalPeriodsKES (Proxy :: Proxy d)
        t' | t < _T = t
           | otherwise = t - _T

    verKeyFromSigKES ctxt t (SigCompactSumKES sigma vk_other) =
      VerKeyCompactSumKES $ hashPairOfVKeys (vk_0, vk_1)
      where
        _T = totalPeriodsKES (Proxy :: Proxy d)
        t' | t < _T = t
           | otherwise = t - _T
        (vk_0, vk_1) | t < _T = (verKeyFromSigKES ctxt t' sigma, vk_other)
                     | otherwise = (vk_other, verKeyFromSigKES ctxt t' sigma)

--
-- VerKey instances
--

deriving instance HashAlgorithm h => Show (VerKeyKES (CompactSumKES h d))
deriving instance Eq   (VerKeyKES (CompactSumKES h d))

instance (KESAlgorithm d) => NoThunks (SignKeyKES (CompactSumKES h d))

instance (KESAlgorithm d) => NoThunks (VerKeyKES (CompactSumKES h d))

instance ( OptimizedKESAlgorithm d
         , NaCl.SodiumHashAlgorithm h
         , SizeHash h ~ SeedSizeKES d
         , NoThunks (VerKeyKES (CompactSumKES h d))
         , KnownNat (SizeVerKeyKES (CompactSumKES h d))
         , KnownNat (SizeSignKeyKES (CompactSumKES h d))
         , KnownNat (SizeSigKES (CompactSumKES h d))
         )
      => ToCBOR (VerKeyKES (CompactSumKES h d)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance ( OptimizedKESAlgorithm d
         , NaCl.SodiumHashAlgorithm h
         , SizeHash h ~ SeedSizeKES d
         , NoThunks (VerKeyKES (CompactSumKES h d))
         , KnownNat (SizeVerKeyKES (CompactSumKES h d))
         , KnownNat (SizeSignKeyKES (CompactSumKES h d))
         , KnownNat (SizeSigKES (CompactSumKES h d))
         )
      => FromCBOR (VerKeyKES (CompactSumKES h d)) where
  fromCBOR = decodeVerKeyKES

--
-- SignKey instances
--

-- These instances would violate mlocking protections, bleeding secret keys
-- onto the GHC heap.
--
-- deriving instance KESAlgorithm d => Show (SignKeyKES (CompactSumKES h d))
--
-- instance (OptimizedKESAlgorithm d) => NoThunks (VerKeyKES  (CompactSumKES h d))
--
-- instance (OptimizedKESAlgorithm d, HashAlgorithm h, SizeHash h ~ SeedSizeKES d)
--       => ToCBOR (SignKeyKES (CompactSumKES h d)) where
--   toCBOR = encodeSignKeyKES
--   encodedSizeExpr _size = encodedSignKeyKESSizeExpr
--
-- instance (OptimizedKESAlgorithm d, HashAlgorithm h, SizeHash h ~ SeedSizeKES d)
--       => FromCBOR (SignKeyKES (CompactSumKES h d)) where
--   fromCBOR = decodeSignKeyKES

--
-- Sig instances
--

deriving instance KESAlgorithm d => Show (SigKES (CompactSumKES h d))
deriving instance KESAlgorithm d => Eq   (SigKES (CompactSumKES h d))

instance KESAlgorithm d => NoThunks (SigKES (CompactSumKES h d))

instance ( OptimizedKESAlgorithm d
         , NaCl.SodiumHashAlgorithm h
         , SizeHash h ~ SeedSizeKES d
         , NoThunks (VerKeyKES (CompactSumKES h d))
         , KnownNat (SizeVerKeyKES (CompactSumKES h d))
         , KnownNat (SizeSignKeyKES (CompactSumKES h d))
         , KnownNat (SizeSigKES (CompactSumKES h d))
         )
      => ToCBOR (SigKES (CompactSumKES h d)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance ( OptimizedKESAlgorithm d
         , NaCl.SodiumHashAlgorithm h
         , SizeHash h ~ SeedSizeKES d
         , NoThunks (VerKeyKES (CompactSumKES h d))
         , KnownNat (SizeVerKeyKES (CompactSumKES h d))
         , KnownNat (SizeSignKeyKES (CompactSumKES h d))
         , KnownNat (SizeSigKES (CompactSumKES h d))
         )
      => FromCBOR (SigKES (CompactSumKES h d)) where
  fromCBOR = decodeSigKES
