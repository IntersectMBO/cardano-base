{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}

-- | QuickCheck generators for 'Cardano.Crypto.Leios' types, intended for
-- downstream test suites (e.g. @cardano-ledger@).
module Test.Cardano.Crypto.Leios.Gen (
  genLeiosSigningKey,
  genLeiosSignature,
  genCommittee,
  TestCommittee (..),
  genTestSeats,
  mkCommitteeFromTestSeats,
  TestSeatType (..),
  genLeiosCert,
  generateWith,
) where

import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (deriveVerKeyDSIGN),
  createPossessionProofDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,
  signDSIGN,
 )
import Cardano.Crypto.Leios (
  LeiosCert,
  LeiosCommittee,
  LeiosDSIGN,
  LeiosSeatId (..),
  LeiosSignature,
  LeiosSigningKey,
  Weight,
  aggregateLeiosCert,
  mkLeiosCommittee,
 )
import qualified Data.Map.Strict as Map
import Data.Maybe.Strict (StrictMaybe (..))
import Data.Proxy (Proxy (Proxy))
import Data.Ratio ((%))
import qualified Data.Vector.Strict as V
import Data.Word (Word16)
import Test.Cardano.Base.Bytes (genByteString)
import Test.Crypto.Util (arbitrarySeedOfSize)
import Test.QuickCheck (Arbitrary (..), Gen, choose, chooseInt, elements, shuffle, sized, vectorOf)
import Test.QuickCheck.Gen (unGen)
import Test.QuickCheck.Random (mkQCGen)

-- | Generate a 'LeiosSigningKey' from a uniformly random seed of the
-- algorithm's expected size.
genLeiosSigningKey :: Gen LeiosSigningKey
genLeiosSigningKey = do
  seed <- arbitrarySeedOfSize (seedSizeDSIGN (Proxy @LeiosDSIGN))
  pure $ genKeyDSIGN seed

-- | Generate a real BLS 'LeiosSignature' by signing a random message with a
-- freshly-generated signing key. Suitable as a byte-generator source for
-- CDDL specs that need on-wire bytes which round-trip through
-- 'Cardano.Crypto.DSIGN.rawDeserialiseSigDSIGN' — uniformly random 48-byte
-- strings do /not/ decode to valid BLS G1 points and will crash there.
genLeiosSignature :: Gen LeiosSignature
genLeiosSignature = do
  sk <- genLeiosSigningKey
  msgLen <- choose (0, 256)
  msg <- genByteString msgLen
  pure $ signDSIGN () msg sk

-- | Generate an all-keyed committee together with its signing keys, at an
-- interesting size: driven by the QuickCheck size parameter but capped at 16 —
-- covering the single-voter (1), single-byte-bitfield (≤ 8) and two-byte
-- boundary (9..16) cases — and always ≥ 1.
genCommittee :: Gen TestCommittee
genCommittee = sized $ \size -> do
  n <- chooseInt (1, max 1 (min size 16))
  let (allKeys, committee) = mkCommitteeFromTestSeats (replicate n (WithKey, 1 / fromIntegral n))
  pure TestCommittee {committee, allKeys}

-- | A committee with all the signing keys, useful for testing.
data TestCommittee = TestCommittee
  { committee :: LeiosCommittee
  , allKeys :: [LeiosSigningKey]
  }
  deriving (Show)

-- | Generate input for 'mkLeiosCommittee' via 'mkCommitteeFromTestSeats': a non-empty
-- run of seats, each a type and a weight, with sizes chosen to cover the
-- bitfield byte boundaries (n = 1, ≤ 8, 9..16).
genTestSeats :: Gen [(TestSeatType, Weight)]
genTestSeats = chooseInt (1, 16) >>= \n -> vectorOf n genSeat
  where
    genSeat = (,) <$> arbitrary <*> (fromIntegral <$> chooseInt (0, 100))

-- | Build the committee that 'mkLeiosCommittee' produces from a generated seat
-- list, returning the per-seat signing keys alongside it so callers can sign
-- without re-deriving keys. Keys are derived per position: a 'NoKey' seat
-- registers no key, and a 'BadPoP' seat pairs its key with an unrelated key's
-- proof of possession, which cannot verify.
mkCommitteeFromTestSeats :: [(TestSeatType, Weight)] -> ([LeiosSigningKey], LeiosCommittee)
mkCommitteeFromTestSeats testSeats =
  (keys, mkLeiosCommittee (V.fromList (zipWith seatInput keys testSeats)))
  where
    keys = [genLeiosSigningKey `generateWith` i | i <- [0 .. length testSeats - 1]]

    seatInput sk (kind, w) = (keyPoP, w)
      where
        vk = deriveVerKeyDSIGN sk

        keyPoP = case kind of
          NoKey -> SNothing
          WithKey -> SJust (vk, createPossessionProofDSIGN sk)
          BadPoP -> SJust (vk, createPossessionProofDSIGN unrelatedSk)

        unrelatedSk = genLeiosSigningKey `generateWith` (length testSeats + 1)

-- | How a generated committee seat carries (or fails to carry) a key.
data TestSeatType
  = WithKey
  | NoKey
  | BadPoP
  deriving (Show, Eq, Enum, Bounded)

instance Arbitrary TestSeatType where
  arbitrary = elements [minBound .. maxBound]
  shrink = const []

-- | Generate a real, canonical 'LeiosCert' by building a fresh committee
-- and aggregating a non-empty subset of its members' signatures over a
-- random message. The cert is structurally valid (bitfield length matches
-- the committee, aggregate signature is well-formed) but the committee is
-- not returned — suitable for CBOR / AST-shape tests, not for
-- protocol-acceptance tests in downstream packages.
--
-- Coverage of bitfield byte-length boundaries (CBOR uint widths > 256
-- bytes) is not exercised here; that belongs in this package's own test
-- suite, not in the shared testlib.
genLeiosCert :: Gen LeiosCert
genLeiosCert = do
  n <- elements [1, 8, 9, 16, 17, 24]
  sks <- vectorOf n genLeiosSigningKey
  let committee =
        mkLeiosCommittee . V.fromList $
          [ (SJust (vk, pop), 1 % toInteger n)
          | sk <- sks
          , let vk = deriveVerKeyDSIGN sk
                pop = createPossessionProofDSIGN sk
          ]
  k <- chooseInt (1, n)
  signerIxs <- take k <$> shuffle [0 .. n - 1]
  msgLen <- choose (0, 64)
  msg <- genByteString msgLen
  let sigs =
        Map.fromList
          [ (LeiosSeatId (fromIntegral @Int @Word16 i), signDSIGN () msg (sks !! i))
          | i <- signerIxs
          ]
  case aggregateLeiosCert committee sigs of
    Right cert -> pure cert
    Left e -> error ("genLeiosCert: aggregation failed: " <> show e)

-- | Deterministically evaluate a QuickCheck 'Gen' at a fixed seed. Useful for
-- pinning a single value (e.g. for golden tests) without going through
-- 'Test.QuickCheck.generate' in 'IO'.
generateWith :: Integral i => Gen a -> i -> a
generateWith gen seed = unGen gen (mkQCGen (fromIntegral seed)) 30
