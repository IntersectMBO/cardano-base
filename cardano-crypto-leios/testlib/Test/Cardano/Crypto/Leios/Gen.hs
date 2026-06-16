{-# LANGUAGE OverloadedStrings #-}
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
  genLeiosSigningKey,
) where

import Cardano.Crypto.DSIGN (genKeyDSIGN, seedSizeDSIGN, signDSIGN)
import Cardano.Crypto.Leios (
  LeiosCert (..),
  LeiosDSIGN,
  LeiosSigningKey,
  bitFieldFromBytes,
  leiosSignContext,
 )
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Data.Proxy (Proxy (Proxy))
import Hedgehog (Gen)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

-- | Generate a 'LeiosSigningKey' from a uniformly random seed of the
-- algorithm's expected size.
genLeiosSigningKey :: Gen LeiosSigningKey
genLeiosSigningKey = do
  let seedLen = fromIntegral (seedSizeDSIGN (Proxy @LeiosDSIGN))
  seedBytes <- Gen.bytes (Range.singleton seedLen)
  pure $ genKeyDSIGN @LeiosDSIGN (mkSeedFromBytes seedBytes)

-- | Generate a 'LeiosCert' whose @signers@ bitfield length walks the CBOR
-- uint width boundaries (1 / 2 / 3-byte length headers) and whose
-- aggregated signature is a real BLS signature over a random message — but
-- whose bitfield is /not/ correlated with the signers of that signature, so
-- the cert will not pass 'verifyLeiosCert'. Use this for CBOR / AST-shape
-- tests, not for verifier-acceptance tests.
genLeiosCert :: Gen LeiosCert
genLeiosCert = do
  sk <- genLeiosSigningKey
  msg <- Gen.bytes (Range.linear 0 256)
  signersLen <- Gen.element [0, 1, 23, 24, 255, 256]
  signersBytes <- Gen.bytes (Range.singleton signersLen)
  pure
    LeiosCert
      { signers = bitFieldFromBytes signersBytes
      , aggregatedSignature = signDSIGN leiosSignContext msg sk
      }
