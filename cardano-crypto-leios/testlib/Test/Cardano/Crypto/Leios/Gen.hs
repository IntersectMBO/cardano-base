{-# LANGUAGE TypeApplications #-}

-- | QuickCheck generators for 'Cardano.Crypto.Leios' types, intended for
-- downstream test suites (e.g. @cardano-ledger@) that want a real
-- structurally-valid 'LeiosCert' without depending on the BLS plumbing.
--
-- These generators produce values whose CBOR encoding round-trips, but they
-- do not attempt to satisfy 'verifyLeiosCert' against any particular
-- committee or message — the @signers@ bitfield is uncorrelated with the
-- aggregated signature. That makes them suitable for serialisation and
-- AST-shape tests, not for protocol-level acceptance tests.
module Test.Cardano.Crypto.Leios.Gen (
  genLeiosCert,
  genLeiosSignature,
  genLeiosSigningKey,
  generateWith,
) where

import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (deriveVerKeyDSIGN),
  genKeyDSIGN,
  seedSizeDSIGN,
  signDSIGN,
 )
import Cardano.Crypto.Leios (
  Committee (..),
  LeiosCert,
  LeiosDSIGN,
  LeiosSignature,
  LeiosSigningKey,
  LeiosVoter (..),
  VoterId (..),
  aggregateLeiosCert,
  leiosSignContext,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Data.Map.Strict as Map
import Data.Proxy (Proxy (Proxy))
import Data.Ratio ((%))
import qualified Data.Vector.Strict as V
import Data.Word (Word16, Word64)
import Test.Cardano.Base.Bytes (genByteString)
import Test.QuickCheck (Gen, choose, chooseInt, elements, shuffle, vectorOf)
import Test.QuickCheck.Gen (unGen)
import Test.QuickCheck.Random (mkQCGen)

-- | Generate a 'LeiosSigningKey' from a uniformly random seed of the
-- algorithm's expected size.
genLeiosSigningKey :: Gen LeiosSigningKey
genLeiosSigningKey = do
  let seedLen = fromIntegral @Word @Int (seedSizeDSIGN (Proxy @LeiosDSIGN))
  seedBytes <- genByteString seedLen
  pure $ genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes seedBytes)

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
  pure $ signDSIGN leiosSignContext msg sk

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
        Committee . V.fromList $
          [LeiosVoter (1 % toInteger n) (deriveVerKeyDSIGN sk) | sk <- sks]
  k <- chooseInt (1, n)
  signerIxs <- take k <$> shuffle [0 .. n - 1]
  msgLen <- choose (0, 64)
  msg <- genByteString msgLen
  let sigs =
        Map.fromList
          [ (VoterId (fromIntegral @Int @Word16 i), signDSIGN leiosSignContext msg (sks !! i))
          | i <- signerIxs
          ]
  case aggregateLeiosCert committee sigs of
    Right cert -> pure cert
    Left e -> error ("genLeiosCert: aggregation failed: " <> show e)

-- | Deterministically evaluate a QuickCheck 'Gen' at a fixed seed. Useful for
-- pinning a single value (e.g. for golden tests) without going through
-- 'Test.QuickCheck.generate' in 'IO'.
generateWith :: Gen a -> Word64 -> a
generateWith gen seed = unGen gen (mkQCGen (fromIntegral @Word64 @Int seed)) 30
