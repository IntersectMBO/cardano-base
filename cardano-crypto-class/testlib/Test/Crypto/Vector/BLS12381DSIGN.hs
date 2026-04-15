{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Crypto.Vector.BLS12381DSIGN (
  tests,
) where

import Cardano.Crypto.DSIGN (
  BLS12381SignContext (..),
  DSIGNAggregatable (..),
  DSIGNAlgorithm (ContextDSIGN, SigDSIGN, Signable, VerKeyDSIGN),
  algorithmNameDSIGN,
  verifyDSIGN,
 )
import Data.Either (isRight)
import Data.Proxy (Proxy (..))
import Test.Crypto.Vector.Vectors (
  minSigBLS12381DSIGNAggregatedSignature,
  minSigBLS12381DSIGNPoP,
  minSigBLS12381DSIGNSignature,
  minVerKeyBLS12381DSIGNAggregatedSignature,
  minVerKeyBLS12381DSIGNPoP,
  minVerKeyBLS12381DSIGNSignature,
 )
import Test.HUnit (assertBool)
import Test.Hspec (Spec, describe, it)

tests :: Spec
tests =
  describe "BLS12381 IETF signatures test vectors" $ do
    -- Signature checks

    -- minVerKey means Vk \in G1 and thus sig \in G2 (so hash to curve needs the G2 dst)
    verifyOnlyTest ietfSignatureInG2Context minVerKeyBLS12381DSIGNSignature
    -- minSig means Vk \in G2 and thus sig \in G1 (so hash to curve needs the G1 dst)
    verifyOnlyTest ietfSignatureInG1Context minSigBLS12381DSIGNSignature

    -- PoP Checks

    -- minVerKey means Vk \in G1 and thus pop \in G2 (so hash to curve needs G2 dst)
    verifyPoPTest ietfPoPInG2Context minVerKeyBLS12381DSIGNPoP
    -- minVerKey means Vk \in G2 and thus pop \in G1 (so hash to curve needs G2 dst)
    verifyPoPTest ietfPoPInG1Context minSigBLS12381DSIGNPoP

    -- Aggregated signature checks

    -- minVerKey means Vk \in G1 and thus sig \in G2 (so hash to curve needs G2 dst)
    verifyAggregatedTest ietfSignatureInG2Context minVerKeyBLS12381DSIGNAggregatedSignature
    -- minVerKey means Vk \in G2 and thus sig \in G1 (so hash to curve needs G2 dst)
    verifyAggregatedTest ietfSignatureInG1Context minSigBLS12381DSIGNAggregatedSignature

-- The below Domain seperation tags defined as per IETF draft

-- Basic over G1: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2.1-1
ietfSignatureInG1Context :: BLS12381SignContext
ietfSignatureInG1Context = BLS12381SignContext (Just "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_") Nothing

-- Basic over G2: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2.1-3
ietfSignatureInG2Context :: BLS12381SignContext
ietfSignatureInG2Context = BLS12381SignContext (Just "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") Nothing

-- PoP over G1: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2.3-1
ietfPoPInG1Context :: BLS12381SignContext
ietfPoPInG1Context = BLS12381SignContext (Just "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_") Nothing

-- PoP over G2: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-06.html#section-4.2.3-3
ietfPoPInG2Context :: BLS12381SignContext
ietfPoPInG2Context = BLS12381SignContext (Just "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_") Nothing

verifyOnlyTest ::
  forall v a.
  ( DSIGNAlgorithm v
  , Signable v a
  ) =>
  ContextDSIGN v ->
  (VerKeyDSIGN v, a, SigDSIGN v) ->
  Spec
verifyOnlyTest ctx (vKey, msg, sig) =
  it ("Signature verification only should be successful: " <> algorithmNameDSIGN (Proxy @v)) $ do
    let result = verifyDSIGN ctx vKey msg sig
    assertBool "Test failed. Signature verification only should be successful." $ isRight result

verifyPoPTest ::
  forall v.
  DSIGNAggregatable v =>
  ContextDSIGN v ->
  (VerKeyDSIGN v, PossessionProofDSIGN v) ->
  Spec
verifyPoPTest ctx (vKey, pop) =
  it ("PoP verification only should be successful: " <> algorithmNameDSIGN (Proxy @v)) $ do
    let result = verifyPossessionProofDSIGN ctx vKey pop
    assertBool "Test failed. PoP verification only should be successful." $ isRight result

verifyAggregatedTest ::
  forall v a.
  ( DSIGNAggregatable v
  , Signable v a
  ) =>
  ContextDSIGN v ->
  ([VerKeyDSIGN v], a, SigDSIGN v) ->
  Spec
verifyAggregatedTest ctx (vKeys, msg, sig) =
  it "Aggregated verification should be successful." $ do
    let result =
          case uncheckedAggregateVerKeysDSIGN vKeys of
            Left err -> Left err
            Right avk -> verifyDSIGN ctx avk msg sig

    assertBool "Test failed. Aggregated verification should be successful." $
      isRight result
