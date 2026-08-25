{-# LANGUAGE CPP #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

module Cardano.Crypto.DSIGN.BLS12381.Internal (
  BLS12381DSIGN,
  BLS12381MinVerKeyDSIGN,
  BLS12381MinSigDSIGN,
  BLS12381CurveConstraints,
  VerKeyDSIGN (..),
  SignKeyDSIGN (..),
  SigDSIGN (..),
  PossessionProofDSIGN (..),
) where

#include "blst_util.h"

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
 )
import Cardano.Crypto.DSIGN.Class (
  DSIGNAggregatable (..),
  DSIGNAlgorithm (
    ContextDSIGN,
    KeyGenContextDSIGN,
    SeedSizeDSIGN,
    SigDSIGN,
    SignKeyDSIGN,
    Signable,
    VerKeyDSIGN,
    algorithmNameDSIGN,
    deriveVerKeyDSIGN,
    genKeyDSIGN,
    genKeyDSIGNWithContext,
    signDSIGN,
    verifyDSIGN
  ),
  encodedPossessionProofDSIGNSizeExpr,
  encodedSigDSIGNSizeExpr,
  encodedSignKeyDSIGNSizeExpr,
  encodedVerKeyDSIGNSizeExpr,
  seedSizeDSIGN,
 )
import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  BLS (..),
  BLSTError (..),
  CompressedPointSize,
  Curve1,
  Curve2,
  DualCurve,
  Point (..),
  Scalar (..),
  ScalarPtr (..),
  blsAddOrDouble,
  blsCompress,
  blsIsInf,
  blsUncompress,
  c_blst_keygen,
  mkBLSTError,
  scalarFromBS,
  scalarToBS,
  toAffine,
  withAffine,
  withMaybeCStringLen,
  withNewPoint',
  withNewPoint_,
 )
import Cardano.Crypto.Libsodium.C (c_sodium_compare)
import Cardano.Crypto.PinnedSizedBytes (
  psbCreate,
  psbUseAsCPtr,
 )
import Cardano.Crypto.Seed (getBytesFromSeedT)
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Control.DeepSeq (NFData)
import Control.Monad (when)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Data (Typeable, eqT)
import qualified Data.Foldable as F (foldl')
import Data.Kind (Type)
import Data.Proxy (Proxy (Proxy))
import Data.Type.Equality ((:~:) (Refl))
import Foreign.C.Types
import GHC.Generics (Generic)
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)
import GHC.TypeNats (KnownNat, type (+))
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

failDecodeBLS :: MonadFail m => String -> String -> m a
failDecodeBLS ty msg =
  fail $ ty <> " BLS12381DSIGN: deserialisation failed (" <> msg <> ")"

-- | A BLS12-381 signature scheme implementing the __proof of possession__
-- (@POP@) ciphersuite of the IETF BLS signature draft
-- (draft-irtf-cfrg-bls-signature-06). The @curve@ type parameter selects one
-- of the two standard instantiations, 'BLS12381MinVerKeyDSIGN' or
-- 'BLS12381MinSigDSIGN'.
--
-- == Why only the "PoP" ciphersuite is supported
--
-- The main reason is API clarity and safety.
--
-- The IETF BLS draft defines three schemes:
--
-- * __Basic__ (@NUL@): aggregation is safe only when all messages in an
--   aggregate are distinct.
--
-- * __Message augmentation__ (@AUG@): aggregation is made safe by signing
--   @PK || message@ instead of just @message@.
--
-- * __Proof of possession__ (@POP@): aggregation is made safe by requiring a
--   separate proof that each public key owner knows the corresponding secret
--   key.
--
-- In this module, the supported aggregation workflow is the PoP one:
--
-- * create a proof of possession with 'createPossessionProofDSIGN'
-- * verify it with 'verifyPossessionProofDSIGN'
-- * aggregate verification keys with 'uncheckedAggregateVerKeysDSIGN' only
--   after the relevant proofs have been checked
-- * aggregate signatures with 'aggregateSigsDSIGN'
--
-- By contrast, this module does /not/ provide the draft's general
-- @AggregateVerify((PK_1, ..., PK_n), (message_1, ..., message_n), signature)@
-- API for aggregation over different messages.  Supporting the Basic and AUG
-- schemes would therefore suggest a broader aggregate-signature API than the
-- module actually offers.
--
-- == Curve variants and domain separation
--
-- The two variants are standard BLS ciphersuite instantiations from
-- draft-irtf-cfrg-bls-signature-06, Section 4.2:
--
-- * 'BLS12381MinSigDSIGN' is the __minimal-signature-size__ variant:
--   signatures live in G1 (48 bytes compressed), public keys in G2
--   (96 bytes compressed).
--
-- * 'BLS12381MinVerKeyDSIGN' is the __minimal-pubkey-size__ variant:
--   public keys live in G1 (48 bytes compressed), signatures in G2
--   (96 bytes compressed).
--
-- Within each variant, the PoP ciphersuite prescribes exactly one pair of
-- DSTs (Section 4.2.3): ordinary signing and verification use the
-- @\"BLS_SIG_\"@-prefixed DST, while creating and verifying proofs of
-- possession hash the public key with the @\"BLS_POP_\"@-prefixed DST. Both
-- DSTs are fixed internally from the curve variant, and the POP scheme does
-- not use message augmentation, so the signing context is trivial:
-- @'ContextDSIGN' ('BLS12381DSIGN' curve) = ()@. Users cannot sign, verify,
-- or prove possession under a non-canonical DST.
--
-- The draft recommends the minimal-pubkey-size variant for aggregation,
-- because the size of @(PK_1, ..., PK_n, signature)@ is usually dominated by
-- the public keys. Other protocols, like Leios, might favor minimal-signature-size.
--
-- == Example
--
-- A typical same-message aggregation workflow is:
--
-- -- Minimal-pubkey-size PoP ciphersuite
-- -- Each participant has a signing key and derived verification key
-- -- Each participant proves possession of its secret key
-- >>> :set -XTypeApplications
-- >>> import Cardano.Crypto.Seed (mkSeedFromBytes)
--
-- >>> :{
-- let msg = BS.pack [0, 1, 2, 3]
--     sk1 =
--       genKeyDSIGNWithContext
--         @BLS12381MinVerKeyDSIGN
--         Nothing
--         (mkSeedFromBytes (BS.replicate 32 1))
--     sk2 =
--       genKeyDSIGNWithContext
--         @BLS12381MinVerKeyDSIGN
--         Nothing
--         (mkSeedFromBytes (BS.replicate 32 2))
--     vk1 = deriveVerKeyDSIGN sk1
--     vk2 = deriveVerKeyDSIGN sk2
--     pop1 = createPossessionProofDSIGN sk1
--     pop2 = createPossessionProofDSIGN sk2
-- :}
--
-- >>> verifyPossessionProofDSIGN vk1 pop1
-- Right ()
--
-- >>> verifyPossessionProofDSIGN vk2 pop2
-- Right ()
--
-- -- Once the proofs have been checked, it is safe to aggregate keys
-- >>> Right avk = uncheckedAggregateVerKeysDSIGN [vk1, vk2]
--
-- -- Both participants sign the same message
-- >>> let sig1 = signDSIGN () msg sk1
-- >>> let sig2 = signDSIGN () msg sk2
--
-- The signatures can be aggregated:
--
-- >>> Right asig = aggregateSigsDSIGN [sig1, sig2]
--
-- -- The aggregate signature can then be checked against the aggregate key:
-- >>> verifyDSIGN () avk msg asig
-- Right ()
data BLS12381DSIGN curve

-- Making sure different 'Signature schemes are not 'Coercible', which would ruin the
-- intended type safety:
type role BLS12381DSIGN nominal

-- | The BLS12-381 minimal verification key size variant
type BLS12381MinVerKeyDSIGN = BLS12381DSIGN Curve1

-- | The BLS12-381 minimal signature size variant
type BLS12381MinSigDSIGN = BLS12381DSIGN Curve2

-- The DSTs of the "PoP" ciphersuite of the IETF BLS signature draft
-- (draft-irtf-cfrg-bls-signature-06, Section 4.2.3). Each curve variant has
-- exactly one canonical pair of DSTs: ordinary signing and verification use
-- the @"BLS_SIG_"@-prefixed DST, while creating and verifying proofs of
-- possession use the @"BLS_POP_"@-prefixed one (both are
-- @prefix || H2C_SUITE_ID || SC_TAG || "_"@). None of these are exported:
-- they are selected internally per curve variant via 'signatureDST' and
-- 'popProofDST', so users cannot sign, verify, or prove possession under a
-- non-canonical DST.

-- Signing DST for the minimal signature size variant (signatures in G1).
minSigSignatureDST :: ByteString
minSigSignatureDST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"

-- Signing DST for the minimal verification key size variant (signatures in G2).
minVerKeySignatureDST :: ByteString
minVerKeySignatureDST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

-- Proof-of-possession DST for the minimal signature size variant.
minSigPoPProofDST :: ByteString
minSigPoPProofDST = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"

-- Proof-of-possession DST for the minimal verification key size variant.
minVerKeyPoPProofDST :: ByteString
minVerKeyPoPProofDST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

-- Select the signing DST for the curve the verification keys live on.
signatureDST :: forall curve. Typeable curve => Proxy curve -> ByteString
signatureDST _ =
  case eqT @curve @Curve1 of
    Just Refl -> minVerKeySignatureDST
    Nothing -> minSigSignatureDST

-- Select the proof-of-possession DST for the curve the verification keys
-- live on.
popProofDST :: forall curve. Typeable curve => Proxy curve -> ByteString
popProofDST _ =
  case eqT @curve @Curve1 of
    Just Refl -> minVerKeyPoPProofDST
    Nothing -> minSigPoPProofDST

type family CurveVariant (c :: Type) :: Symbol where
  CurveVariant Curve1 = "BLS-Signature-Minimal-Verification-Key-Size"
  CurveVariant Curve2 = "BLS-Signature-Minimal-Signature-Size"

type BLS12381CurveConstraints curve =
  ( BLS curve
  , BLS (DualCurve curve)
  , KnownSymbol (CurveVariant curve)
  , KnownNat (CompressedPointSize curve)
  , KnownNat (CompressedPointSize (DualCurve curve))
  , Typeable curve
  )

-- The core signing routine shared by 'signDSIGN' and
-- 'createPossessionProofDSIGN'; the caller chooses the DST, which differs
-- between ordinary signatures and proofs of possession. The POP scheme does
-- not use message augmentation, so none is passed.
{-# INLINE blsCoreSign #-}
blsCoreSign ::
  forall curve a.
  (BLS curve, BLS (DualCurve curve), SignableRepresentation a) =>
  ByteString ->
  a ->
  SignKeyDSIGN (BLS12381DSIGN curve) ->
  SigDSIGN (BLS12381DSIGN curve)
blsCoreSign dst msg (SignKeyBLS12381 (Scalar skPsb)) =
  SigBLS12381 $ unsafeDupablePerformIO $ do
    psbUseAsCPtr skPsb $ \skPtp -> do
      withNewPoint_ @(DualCurve curve) $ \hashPtr -> do
        unsafeUseAsCStringLen dst $ \(dstPtr, dstLen) ->
          withMaybeCStringLen Nothing $ \(augPtr, augLen) ->
            unsafeUseAsCStringLen (getSignableRepresentation msg) $ \(msgPtr, msgLen) ->
              c_blst_hash @(DualCurve curve)
                hashPtr
                msgPtr
                (fromIntegral @Int @CSize msgLen)
                dstPtr
                (fromIntegral @Int @CSize dstLen)
                augPtr
                (fromIntegral @Int @CSize augLen)
        withNewPoint' @(DualCurve curve) $ \sigPtr -> do
          c_blst_sign @curve sigPtr hashPtr (ScalarPtr skPtp)

-- The core verification routine shared by 'verifyDSIGN' and
-- 'verifyPossessionProofDSIGN'; as 'blsCoreSign', the caller chooses the DST.
{-# INLINE blsCoreVerify #-}
blsCoreVerify ::
  forall curve a.
  (BLS curve, BLS (DualCurve curve), SignableRepresentation a) =>
  ByteString ->
  VerKeyDSIGN (BLS12381DSIGN curve) ->
  a ->
  SigDSIGN (BLS12381DSIGN curve) ->
  Either String ()
blsCoreVerify dst (VerKeyBLS12381 pbPsb) msg (SigBLS12381 sigPsb) =
  unsafeDupablePerformIO $ do
    unsafeUseAsCStringLen dst $ \(dstPtr, dstLen) -> do
      withAffine (toAffine @curve pbPsb) $ \pkAff ->
        withAffine (toAffine @(DualCurve curve) sigPsb) $ \sigAff ->
          withMaybeCStringLen Nothing $ \(augPtr, augLen) ->
            unsafeUseAsCStringLen (getSignableRepresentation msg) $ \(msgPtr, msgLen) -> do
              err <-
                c_blst_core_verify @curve
                  pkAff
                  sigAff
                  True
                  msgPtr
                  (fromIntegral @Int @CSize msgLen)
                  dstPtr
                  (fromIntegral @Int @CSize dstLen)
                  augPtr
                  (fromIntegral @Int @CSize augLen)
              pure $! case mkBLSTError err of
                BLST_SUCCESS -> Right ()
                _ -> Left "verifyDSIGN: BLS12381DSIGN signature failed to verify"

instance
  BLS12381CurveConstraints curve =>
  DSIGNAlgorithm (BLS12381DSIGN curve)
  where
  type SeedSizeDSIGN (BLS12381DSIGN curve) = CARDANO_BLST_SCALAR_SIZE

  -- These *Sizes* are used in the serialization/deserialization
  -- so these use the compressed sizes of the BLS12-381 `Point curve`
  type Signable (BLS12381DSIGN curve) = SignableRepresentation

  -- The signing context carries no information: the DST is fixed internally
  -- per curve variant, and the POP scheme does not use augmentation.
  type ContextDSIGN (BLS12381DSIGN curve) = ()
  type KeyGenContextDSIGN (BLS12381DSIGN curve) = Maybe ByteString

  newtype VerKeyDSIGN (BLS12381DSIGN curve)
    = -- Note that the internal representation is the uncompressed point size
      VerKeyBLS12381 (Point curve)
    deriving newtype (NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)

  newtype SignKeyDSIGN (BLS12381DSIGN curve)
    = SignKeyBLS12381 Scalar
    deriving newtype (NFData)
    deriving stock (Generic)
    deriving anyclass (NoThunks)

  newtype SigDSIGN (BLS12381DSIGN curve)
    = -- Note that the internal representation is the uncompressed point size
      SigBLS12381 (Point (DualCurve curve))
    deriving newtype (NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)

  algorithmNameDSIGN _ = "bls12-381-" ++ symbolVal (Proxy @(CurveVariant curve))

  {-# INLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeyBLS12381 (Scalar skPsb)) = do
    VerKeyBLS12381 $ unsafeDupablePerformIO . psbUseAsCPtr skPsb $ \skp ->
      withNewPoint' @curve $ \vkPtp -> do
        c_blst_sk_to_pk @curve vkPtp (ScalarPtr skp)

  {-# INLINE signDSIGN #-}
  signDSIGN () = blsCoreSign (signatureDST (Proxy @curve))

  {-# INLINE verifyDSIGN #-}
  verifyDSIGN () = blsCoreVerify (signatureDST (Proxy @curve))

  {-# INLINE genKeyDSIGN #-}
  genKeyDSIGN = genKeyDSIGNWithContext Nothing

  {-# INLINE genKeyDSIGNWithContext #-}
  -- Generate a signing key from a seed and optional key info
  -- as per the IETF bls signature draft 05
  genKeyDSIGNWithContext keyInfo seed =
    SignKeyBLS12381 . Scalar $
      let (bs, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @(BLS12381DSIGN curve))) seed
       in unsafeDupablePerformIO $ do
            withMaybeCStringLen keyInfo $ \(infoPtr, infoLen) ->
              unsafeUseAsCStringLen bs $ \(ikmPtr, ikmLen) ->
                psbCreate $ \skPtr ->
                  c_blst_keygen
                    (ScalarPtr skPtr)
                    ikmPtr
                    (fromIntegral @Int @CSize ikmLen)
                    infoPtr
                    (fromIntegral @Int @CSize infoLen)

deriving stock instance
  BLS curve =>
  Eq (VerKeyDSIGN (BLS12381DSIGN curve))

deriving stock instance
  BLS (DualCurve curve) =>
  Eq (SigDSIGN (BLS12381DSIGN curve))

-- Constant-time equality for signing keys
instance Eq (SignKeyDSIGN (BLS12381DSIGN curve)) where
  SignKeyBLS12381 (Scalar sk1Psb) == SignKeyBLS12381 (Scalar sk2Psb) =
    unsafeDupablePerformIO $
      psbUseAsCPtr sk1Psb $ \sk1Ptr ->
        psbUseAsCPtr sk2Psb $ \sk2Ptr -> do
          res <- c_sodium_compare sk1Ptr sk2Ptr size
          pure (res == 0)
    where
      size = fromIntegral @Int @CSize CARDANO_BLST_SCALAR_SIZE

instance Show (SignKeyDSIGN (BLS12381DSIGN curve)) where
  show _ = "BLS12381DSIGN:<secret>"

instance
  BLS12381CurveConstraints curve =>
  FixedSizeCodec (VerKeyDSIGN (BLS12381DSIGN curve))
  where
  type FixedSize (VerKeyDSIGN (BLS12381DSIGN curve)) = CompressedPointSize curve

  -- Note that this also compresses the verification key according to the ZCash standard
  {-# INLINE rawEncodeFixedSized #-}
  rawEncodeFixedSized (VerKeyBLS12381 vkPSB) = blsCompress @curve vkPSB
  {-# INLINE rawDecodeFixedSized #-}
  rawDecodeFixedSized bs =
    -- Note that this also performs a group membership check.
    -- That is, the deserialised point is in the subgroup of Curve1/Curve2.
    case blsUncompress @curve bs of
      Left err -> failDecodeBLS "VerKeyDSIGN" $ show err
      Right vkPsb ->
        -- Reject the identity (point at infinity) as a verification key
        if blsIsInf @curve vkPsb
          then failDecodeBLS "VerKeyDSIGN" "infinity point"
          else pure (VerKeyBLS12381 vkPsb)

instance FixedSizeCodec (SignKeyDSIGN (BLS12381DSIGN curve)) where
  type FixedSize (SignKeyDSIGN (BLS12381DSIGN curve)) = CARDANO_BLST_SCALAR_SIZE
  {-# INLINE rawEncodeFixedSized #-}
  rawEncodeFixedSized (SignKeyBLS12381 skPSB) = scalarToBS skPSB
  {-# INLINE rawDecodeFixedSized #-}
  rawDecodeFixedSized bs = do
    -- A signing key is strictly a BE integer mod the curve order.
    -- We must ensure they are valid Scalars, i.e., less than the curve order (255 bits).
    case scalarFromBS bs of
      Left err -> failDecodeBLS "SignKeyDSIGN" $ show err
      Right skScalar ->
        -- Reject the zero scalar as a signing key
        if BS.all (== 0) (scalarToBS skScalar)
          then failDecodeBLS "SignKeyDSIGN" "zero scalar"
          else pure (SignKeyBLS12381 skScalar)

instance
  BLS12381CurveConstraints curve =>
  FixedSizeCodec (SigDSIGN (BLS12381DSIGN curve))
  where
  type FixedSize (SigDSIGN (BLS12381DSIGN curve)) = CompressedPointSize (DualCurve curve)

  -- Note that this also compresses the signature according to the ZCash standard
  {-# INLINE rawEncodeFixedSized #-}
  rawEncodeFixedSized (SigBLS12381 sigPSB) = blsCompress @(DualCurve curve) sigPSB
  {-# INLINE rawDecodeFixedSized #-}
  rawDecodeFixedSized bs =
    -- Note that this also performs a group membership check.
    -- That is, the deserialised point is in the subgroup of Curve1/Curve2.
    case blsUncompress @(DualCurve curve) bs of
      Left err -> failDecodeBLS "SigDSIGN" $ show err
      Right sigPsb -> pure (SigBLS12381 sigPsb)

instance
  BLS12381CurveConstraints curve =>
  ToCBOR (VerKeyDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance
  BLS12381CurveConstraints curve =>
  FromCBOR (VerKeyDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeFixedSized

instance
  BLS12381CurveConstraints curve =>
  ToCBOR (SignKeyDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance
  BLS12381CurveConstraints curve =>
  FromCBOR (SignKeyDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeFixedSized

instance
  BLS12381CurveConstraints curve =>
  ToCBOR (SigDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

-- | Helper functions to extract the internal Point representation
verKeyToPoint :: VerKeyDSIGN (BLS12381DSIGN curve) -> Point curve
verKeyToPoint (VerKeyBLS12381 p) = p

-- | Helper functions to extract the internal Point representation
sigToPoint :: SigDSIGN (BLS12381DSIGN curve) -> Point (DualCurve curve)
sigToPoint (SigBLS12381 p) = p

instance
  BLS12381CurveConstraints curve =>
  FromCBOR (SigDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeFixedSized

instance
  BLS12381CurveConstraints curve =>
  DSIGNAggregatable (BLS12381DSIGN curve)
  where
  type
    -- Sizes used in serialization/deserialization
    -- so these use the compressed sizes of the BLS12-381 `Point curve`
    PossessionProofSizeDSIGN (BLS12381DSIGN curve) =
      CompressedPointSize (DualCurve curve)

  newtype PossessionProofDSIGN (BLS12381DSIGN curve) = PossessionProofBLS12381 (Point (DualCurve curve))
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
    deriving anyclass (NFData)

  {-# INLINE uncheckedAggregateVerKeysDSIGN #-}
  uncheckedAggregateVerKeysDSIGN verKeys = do
    let verKeyPoints = map verKeyToPoint verKeys
    -- Reject any input verification key that is the infinity point
    if any (blsIsInf @curve) verKeyPoints
      then Left "uncheckedAggregateVerKeysDSIGN: input verification key is infinity"
      else case verKeyPoints of
        [] -> Left "uncheckedAggregateVerKeysDSIGN: empty list of verification keys"
        (p : ps) ->
          let aggrPoint = F.foldl' blsAddOrDouble p ps
           in -- Unlikely case, but best to reject infinity as an aggregate verification
              -- key. This happens if, for every secret/verification key pair, the inverse
              -- of each secret key (and thus also the verification key) is also present
              -- in the list.
              if blsIsInf @curve aggrPoint
                then Left "uncheckedAggregateVerKeysDSIGN: aggregated verification key is infinity"
                else Right $ VerKeyBLS12381 aggrPoint

  {-# INLINE aggregateSigsDSIGN #-}
  aggregateSigsDSIGN sigs = do
    let sigPoints = map sigToPoint sigs
    -- Reject any input signature that is the infinity point
    if any (blsIsInf @(DualCurve curve)) sigPoints
      then Left "aggregateSigsDSIGN: input signature is infinity"
      else case sigPoints of
        [] -> Left "aggregateSigsDSIGN: empty list of signatures"
        (p : ps) ->
          let aggrPoint = F.foldl' blsAddOrDouble p ps
           in -- Unlikely case, but best to reject infinity as an aggregate signature
              if blsIsInf @(DualCurve curve) aggrPoint
                then Left "aggregateSigsDSIGN: aggregated signature is infinity"
                else Right $ SigBLS12381 aggrPoint

  {-# INLINE createPossessionProofDSIGN #-}
  createPossessionProofDSIGN sk =
    let vk = deriveVerKeyDSIGN sk :: VerKeyDSIGN (BLS12381DSIGN curve)
        SigBLS12381 sig = blsCoreSign (popProofDST (Proxy @curve)) (rawEncodeFixedSized vk) sk
     in PossessionProofBLS12381 sig
  {-# INLINE verifyPossessionProofDSIGN #-}
  verifyPossessionProofDSIGN vk (PossessionProofBLS12381 mu1Psb) =
    first
      (const "verifyPossessionProofDSIGN: BLS12381DSIGN failed to verify.")
      (blsCoreVerify (popProofDST (Proxy @curve)) vk (rawEncodeFixedSized vk) (SigBLS12381 mu1Psb))

deriving stock instance
  BLS (DualCurve curve) =>
  Eq (PossessionProofDSIGN (BLS12381DSIGN curve))

instance
  BLS12381CurveConstraints curve =>
  FixedSizeCodec (PossessionProofDSIGN (BLS12381DSIGN curve))
  where
  type
    FixedSize (PossessionProofDSIGN (BLS12381DSIGN curve)) =
      PossessionProofSizeDSIGN (BLS12381DSIGN curve)
  rawEncodeFixedSized (PossessionProofBLS12381 mu1Psb) =
    blsCompress @(DualCurve curve) mu1Psb
  rawDecodeFixedSized bs = do
    -- Note that these also perform group membership and size checks.
    -- It will also ensure that all of the supplied `ByteString` is consumed
    -- through the size checks.
    case blsUncompress @(DualCurve curve) bs of
      Left err -> failDecodeBLS "PossessionProofDSIGN" (show err)
      Right mu1Point -> do
        -- Reject the zero point (point at infinity) for both mu1 and mu2
        when (blsIsInf @(DualCurve curve) mu1Point) $ do
          failDecodeBLS "PossessionProofDSIGN" "infinity point"
        pure $ PossessionProofBLS12381 mu1Point
  {-# INLINE rawDecodeFixedSized #-}

instance
  ( BLS12381CurveConstraints curve
  , KnownNat (CompressedPointSize (DualCurve curve) + CompressedPointSize (DualCurve curve))
  ) =>
  ToCBOR (PossessionProofDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedPossessionProofDSIGNSizeExpr

instance
  ( BLS12381CurveConstraints curve
  , KnownNat (CompressedPointSize (DualCurve curve) + CompressedPointSize (DualCurve curve))
  ) =>
  FromCBOR (PossessionProofDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeFixedSized
