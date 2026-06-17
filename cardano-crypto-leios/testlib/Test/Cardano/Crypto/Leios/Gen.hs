{-# LANGUAGE TypeApplications #-}

-- | Hedgehog generators for 'Cardano.Crypto.Leios' types, intended for
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

import Cardano.Crypto.DSIGN (genKeyDSIGN, seedSizeDSIGN, signDSIGN)
import Cardano.Crypto.Leios (
  LeiosCert (..),
  LeiosDSIGN,
  LeiosSignature,
  LeiosSigningKey,
  bitFieldFromBytes,
  leiosSignContext,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Data.Proxy (Proxy (Proxy))
import Data.Word (Word64)
import Hedgehog (Gen, Size (..))
import qualified Hedgehog.Gen as Gen
import Hedgehog.Internal.Gen (evalGen)
import qualified Hedgehog.Internal.Seed as Seed
import Hedgehog.Internal.Tree (treeValue)
import qualified Hedgehog.Range as Range

-- | Generate a 'LeiosSigningKey' from a uniformly random seed of the
-- algorithm's expected size.
genLeiosSigningKey :: Gen LeiosSigningKey
genLeiosSigningKey = do
  let seedLen = fromIntegral (seedSizeDSIGN (Proxy @LeiosDSIGN))
  seedBytes <- Gen.bytes (Range.singleton seedLen)
  pure $ genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes seedBytes)

-- | Generate a real BLS 'LeiosSignature' by signing a random message with a
-- freshly-generated signing key. Suitable as a byte-generator source for
-- CDDL specs that need on-wire bytes which round-trip through
-- 'Cardano.Crypto.DSIGN.rawDeserialiseSigDSIGN' — uniformly random 48-byte
-- strings do /not/ decode to valid BLS G1 points and will crash there.
genLeiosSignature :: Gen LeiosSignature
genLeiosSignature = do
  sk <- genLeiosSigningKey
  msg <- Gen.bytes (Range.linear 0 256)
  pure $ signDSIGN leiosSignContext msg sk

-- | Generate a 'LeiosCert' whose @signers@ bitfield length walks the CBOR
-- uint width boundaries (1 / 2 / 3-byte length headers) and whose
-- aggregated signature is a real BLS signature over a random message — but
-- whose bitfield is /not/ correlated with the signers of that signature, so
-- the cert will not pass 'verifyLeiosCert'. Use this for CBOR / AST-shape
-- tests, not for verifier-acceptance tests.
genLeiosCert :: Gen LeiosCert
genLeiosCert = do
  signersLen <- Gen.element [0, 1, 23, 24, 255, 256]
  signersBytes <- Gen.bytes (Range.singleton signersLen)
  sig <- genLeiosSignature
  pure
    LeiosCert
      { signers = bitFieldFromBytes signersBytes
      , aggregatedSignature = sig
      }

-- | Deterministically evaluate a Hedgehog 'Gen' at a fixed seed without needing
-- to 'sample' in 'MonadIO'. Useful for pinning a single value (e.g. for golden
-- tests). Errors if the generator discards at this seed.
generateWith :: Gen a -> Word64 -> a
generateWith gen seed =
  case evalGen (Size 30) (Seed.from seed) gen of
    Just tree -> treeValue tree
    Nothing -> error "generateWith: generator discarded at this seed"
