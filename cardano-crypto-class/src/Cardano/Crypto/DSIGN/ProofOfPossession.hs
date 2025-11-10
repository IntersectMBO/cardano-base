{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE TypeFamilies #-}

-- | DSIGN-level proof-of-possession support.
--
--   This opt-in extension mirrors the structure of 'DSIGNAlgorithm' helpers
--   while reusing each algorithm's 'ContextDSIGN'.  For the BLS instances this
--   means proof-of-possession proving/verification follows the same @(dst, aug)@
--   semantics as signing: @Nothing@ is treated the same as @Just mempty@ for
--   augmentation and as @Just "BLS_DST_CARDANO_BASE_V1"@ for the default DST.
module Cardano.Crypto.DSIGN.ProofOfPossession (
  PoPDSIGN,
  PoPDSIGNData,
  provePoPDSIGN,
  verifyPoPDSIGN,
  rawSerialisePoPDSIGN,
  rawDeserialisePoPDSIGN,
) where

import Data.ByteString (ByteString)
import Data.Kind (Type)
import GHC.Stack (HasCallStack)

import Cardano.Crypto.DSIGN.Class (
  ContextDSIGN,
  DSIGNAlgorithm,
  SignKeyDSIGN,
  VerKeyDSIGN,
 )

-- | Optional DSIGN extension that exposes proof-of-possession operations.
class DSIGNAlgorithm v => PoPDSIGN v where
  data PoPDSIGNData v :: Type

  provePoPDSIGN ::
    HasCallStack =>
    ContextDSIGN v ->
    SignKeyDSIGN v ->
    PoPDSIGNData v

  verifyPoPDSIGN ::
    HasCallStack =>
    ContextDSIGN v ->
    VerKeyDSIGN v ->
    PoPDSIGNData v ->
    Either String ()

  rawSerialisePoPDSIGN ::
    PoPDSIGNData v ->
    ByteString

  rawDeserialisePoPDSIGN ::
    ByteString ->
    Maybe (PoPDSIGNData v)
