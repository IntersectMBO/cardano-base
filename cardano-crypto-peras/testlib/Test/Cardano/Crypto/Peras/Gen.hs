{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Crypto.Peras.Gen (
  genPerasSigningKey,
  perasSigningKeyFromSeedByte,
  genPerasSignature,
  genPerasVRFOutput,
  genPerasRoundNo,
  genPerasSeatIndex,
  genPerasBlockRef,
  genPerasBoostedBlock,
  genPerasCertVoters,
  genPerasCert,
  genPerasVoteEligibilityProof,
  genPerasVote,
  generateWith,
) where

import Cardano.Crypto.DSIGN (SigDSIGN, genKeyDSIGN, seedSizeDSIGN, signDSIGN)
import Cardano.Crypto.Peras (
  PerasBlockRef (..),
  PerasBoostedBlock (..),
  PerasDSIGN,
  PerasRoundNo (..),
  PerasSeatIndex (..),
  PerasSignature (..),
  PerasSigningKey,
  PerasVRFOutput (..),
  perasBlockHashSize,
 )
import Cardano.Crypto.Peras.Cert (
  PerasCert (..),
  PerasCertVoters,
  perasCertVotersFromSeats,
 )
import Cardano.Crypto.Peras.Vote (
  PerasVote (..),
  PerasVoteEligibilityProof (..),
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Slotting.Slot (SlotNo (..), WithOrigin (..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as SBS
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes)
import Data.Proxy (Proxy (..))
import Data.Word (Word16, Word8)
import Test.Cardano.Base.Bytes (genByteString)
import Test.Crypto.Util (arbitrarySeedOfSize)
import Test.QuickCheck (Gen, arbitrary, choose, frequency, sized)
import Test.QuickCheck.Gen (unGen)
import Test.QuickCheck.Random (mkQCGen)

genPerasSigningKey :: Gen PerasSigningKey
genPerasSigningKey = do
  seed <- arbitrarySeedOfSize (seedSizeDSIGN (Proxy @PerasDSIGN))
  pure $ genKeyDSIGN seed

perasSigningKeyFromSeedByte :: Word8 -> PerasSigningKey
perasSigningKeyFromSeedByte b =
  genKeyDSIGN $
    mkSeedFromBytes $
      BS.replicate (fromIntegral (seedSizeDSIGN (Proxy @PerasDSIGN))) b

genRawSignature :: Gen (SigDSIGN PerasDSIGN)
genRawSignature = do
  sk <- genPerasSigningKey
  msgLen <- choose (0, 256)
  msg <- genByteString msgLen
  pure $ signDSIGN () msg sk

genPerasSignature :: Gen PerasSignature
genPerasSignature = PerasSignature <$> genRawSignature

genPerasVRFOutput :: Gen PerasVRFOutput
genPerasVRFOutput = PerasVRFOutput <$> genRawSignature

genPerasRoundNo :: Gen PerasRoundNo
genPerasRoundNo = PerasRoundNo <$> arbitrary

genPerasSeatIndex :: Gen PerasSeatIndex
genPerasSeatIndex = PerasSeatIndex <$> arbitrary

genPerasBlockRef :: Gen PerasBlockRef
genPerasBlockRef =
  PerasBlockRef
    <$> (SlotNo <$> arbitrary)
    <*> (SBS.toShort <$> genByteString perasBlockHashSize)

genPerasBoostedBlock :: Gen PerasBoostedBlock
genPerasBoostedBlock =
  PerasBoostedBlock
    <$> frequency
      [ (1, pure Origin)
      , (9, At <$> genPerasBlockRef)
      ]

genPerasCertVoters :: Bool -> Gen PerasCertVoters
genPerasCertVoters allowNonPersistent = do
  numVoters <- sized $ \size -> (+ 1) <$> choose @Word16 (0, fromIntegral (min size 400) * 4)
  numPersistent <-
    if allowNonPersistent
      then choose (0, numVoters)
      else pure numVoters
  let persistent = [(PerasSeatIndex i, Nothing) | i <- take (fromIntegral numPersistent) [0 ..]]
  nonPersistent <-
    mapM
      (\i -> (,) (PerasSeatIndex i) . Just <$> genPerasVRFOutput)
      (take (fromIntegral (numVoters - numPersistent)) [numPersistent ..])
  kept <- dropSome False (persistent <> nonPersistent)
  either error pure $ perasCertVotersFromSeats (NonEmpty.fromList kept)
  where
    dropSome _ [] = pure []
    dropSome canDrop (x : xs) = do
      keep <- frequency [(75, pure True), (if canDrop then 25 else 0, pure False)]
      rest <- dropSome (canDrop || keep) xs
      pure $ catMaybes [if keep then Just x else Nothing] <> rest

genPerasCert :: Bool -> Gen PerasCert
genPerasCert allowNonPersistent =
  PerasCert
    <$> genPerasRoundNo
    <*> genPerasBoostedBlock
    <*> genPerasCertVoters allowNonPersistent
    <*> genPerasSignature

genPerasVoteEligibilityProof :: Gen PerasVoteEligibilityProof
genPerasVoteEligibilityProof =
  frequency
    [ (1, pure PersistentPerasVoteEligibilityProof)
    , (1, NonPersistentPerasVoteEligibilityProof <$> genPerasVRFOutput)
    ]

genPerasVote :: Gen PerasVote
genPerasVote =
  PerasVote
    <$> genPerasRoundNo
    <*> genPerasBoostedBlock
    <*> genPerasSeatIndex
    <*> genPerasVoteEligibilityProof
    <*> genPerasSignature

generateWith :: Integral i => Gen a -> i -> a
generateWith gen seed = unGen gen (mkQCGen (fromIntegral seed)) 30
