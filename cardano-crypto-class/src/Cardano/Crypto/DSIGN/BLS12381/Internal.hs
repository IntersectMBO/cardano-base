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
  BLS12381SignContext (..),
  minSigPoPDST,
  minVerKeyPoPDST,
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
import Data.Data (Typeable)
import qualified Data.Foldable as F (foldl')
import Data.Kind (Type)
import Data.Proxy (Proxy (Proxy))
import Foreign.C.Types
import GHC.Generics (Generic)
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)
import GHC.TypeNats (KnownNat, type (+))
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

failDecodeBLS :: MonadFail m => String -> String -> m a
failDecodeBLS ty msg =
  fail $ ty <> " BLS12381DSIGN: deserialisation failed (" <> msg <> ")"

data BLS12381DSIGN curve

-- Making sure different 'Signature schemes are not 'Coercible', which would ruin the
-- intended type safety:
type role BLS12381DSIGN nominal

-- | The BLS12-381 minimal verification key size variant
type BLS12381MinVerKeyDSIGN = BLS12381DSIGN Curve1

-- | The BLS12-381 minimal signature size variant
type BLS12381MinSigDSIGN = BLS12381DSIGN Curve2

-- | The BLS12381 signing context for the "PoP" based ciphersuite for the minimal signature size variant of bls signatures
minSigPoPDST :: BLS12381SignContext
minSigPoPDST = BLS12381SignContext (Just "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_") Nothing

-- | The BLS12381 signing context for the "PoP" based ciphersuite for the minimal verification key size variant of bls signatures
minVerKeyPoPDST :: BLS12381SignContext
minVerKeyPoPDST = BLS12381SignContext (Just "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_") Nothing

type family CurveVariant (c :: Type) :: Symbol where
  CurveVariant Curve1 = "BLS-Signature-Mininimal-Verification-Key-Size"
  CurveVariant Curve2 = "BLS-Signature-Mininimal-Signature-Size"

-- | This module provides support only for proof-of-possession (PoP) ciphersuite
-- contexts:
--
-- * 'minSigPoPDST'
-- * 'minVerKeyPoPDST'
--
-- even though the underlying signing and verification primitives can be used
-- to realise the Basic (@NUL@) and message-augmentation (@AUG@) schemes as
-- well.
--
-- == Why only the "PoP" ciphersuite is exported
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
-- API for aggregation over different messages.  Exporting predefined Basic and
-- AUG contexts would therefore suggest a broader aggregate-signature API than
-- the module actually offers.
--
-- Restricting the public ciphersuite exports to PoP makes the intended usage
-- explicit: this module supports ordinary BLS signing and verification, plus a
-- PoP-based aggregation story.
--
-- == What the exported contexts mean
--
-- The exported values are standard BLS ciphersuite DSTs from
-- draft-irtf-cfrg-bls-signature-06, Section 4.2:
--
-- * 'minSigPoPDST' selects the __minimal-signature-size__ variant:
--   signatures live in G1 (48 bytes compressed), public keys in G2
--   (96 bytes compressed).
--
-- * 'minVerKeyPoPDST' selects the __minimal-pubkey-size__ variant:
--   public keys live in G1 (48 bytes compressed), signatures in G2
--   (96 bytes compressed).
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
-- let ctx = minVerKeyPoPDST
--     msg = BS.pack [0, 1, 2, 3]
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
--     pop1 = createPossessionProofDSIGN ctx sk1
--     pop2 = createPossessionProofDSIGN ctx sk2
-- :}
--
-- >>> verifyPossessionProofDSIGN ctx vk1 pop1
-- Right ()
--
-- >>> verifyPossessionProofDSIGN ctx vk2 pop2
-- Right ()
--
-- -- Once the proofs have been checked, it is safe to aggregate keys
-- >>> Right avk = uncheckedAggregateVerKeysDSIGN [vk1, vk2]
--
-- -- Both participants sign the same message
-- >>> let sig1 = signDSIGN ctx msg sk1
-- >>> let sig2 = signDSIGN ctx msg sk2
--
-- The signatures can be aggregated:
--
-- >>> Right asig = aggregateSigsDSIGN [sig1, sig2]
--
-- -- The aggregate signature can then be checked against the aggregate key:
-- >>> verifyDSIGN ctx avk msg asig
-- Right ()
data BLS12381SignContext = BLS12381SignContext
  { blsSignContextDst :: !(Maybe ByteString)
  , blsSignContextAug :: !(Maybe ByteString)
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

type BLS12381CurveConstraints curve =
  ( BLS curve
  , BLS (DualCurve curve)
  , KnownSymbol (CurveVariant curve)
  , KnownNat (CompressedPointSize curve)
  , KnownNat (CompressedPointSize (DualCurve curve))
  , Typeable curve
  )

instance
  BLS12381CurveConstraints curve =>
  DSIGNAlgorithm (BLS12381DSIGN curve)
  where
  type SeedSizeDSIGN (BLS12381DSIGN curve) = CARDANO_BLST_SCALAR_SIZE

  -- These *Sizes* are used in the serialization/deserialization
  -- so these use the compressed sizes of the BLS12-381 `Point curve`
  type Signable (BLS12381DSIGN curve) = SignableRepresentation

  -- Context can hold domain separation tag and/or augmentation data for signatures
  type ContextDSIGN (BLS12381DSIGN curve) = BLS12381SignContext
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
  signDSIGN BLS12381SignContext {blsSignContextDst = dst, blsSignContextAug = aug} msg (SignKeyBLS12381 (Scalar skPsb)) =
    SigBLS12381 $ unsafeDupablePerformIO $ do
      psbUseAsCPtr skPsb $ \skPtp -> do
        withNewPoint_ @(DualCurve curve) $ \hashPtr -> do
          withMaybeCStringLen dst $ \(dstPtr, dstLen) ->
            withMaybeCStringLen aug $ \(augPtr, augLen) ->
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

  {-# INLINE verifyDSIGN #-}
  -- Context can hold domain separation tag and/or augmentation data for signatures
  verifyDSIGN BLS12381SignContext {blsSignContextDst = dst, blsSignContextAug = aug} (VerKeyBLS12381 pbPsb) msg (SigBLS12381 sigPsb) =
    unsafeDupablePerformIO $ do
      withMaybeCStringLen dst $ \(dstPtr, dstLen) -> do
        withAffine (toAffine @curve pbPsb) $ \pkAff ->
          withAffine (toAffine @(DualCurve curve) sigPsb) $ \sigAff ->
            withMaybeCStringLen aug $ \(augPtr, augLen) ->
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

instance
  BLS12381CurveConstraints curve =>
  FixedSizeCodec (SignKeyDSIGN (BLS12381DSIGN curve))
  where
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
  createPossessionProofDSIGN ctx sk =
    let vk = deriveVerKeyDSIGN sk :: VerKeyDSIGN (BLS12381DSIGN curve)
        SigBLS12381 sig = signDSIGN ctx (rawEncodeFixedSized vk) sk
     in PossessionProofBLS12381 sig
  {-# INLINE verifyPossessionProofDSIGN #-}
  verifyPossessionProofDSIGN ctx vk (PossessionProofBLS12381 mu1Psb) =
    first
      (const "verifyPossessionProofDSIGN: BLS12381DSIGN failed to verify.")
      (verifyDSIGN ctx vk (rawEncodeFixedSized vk) (SigBLS12381 mu1Psb))

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
