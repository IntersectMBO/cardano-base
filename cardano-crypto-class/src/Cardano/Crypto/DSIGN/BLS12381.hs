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
-- According to the documentation for unsafePerformIO:
--
-- > Make sure that the either you switch off let-floating
-- > (-fno-full-laziness), or that the call to unsafePerformIO cannot float
-- > outside a lambda.
--
-- If we do not switch off let-floating, our calls to unsafeDupablePerformIO for
-- FFI functions become nondeterministic in their behaviour when run with
-- parallelism enabled (such as -with-rtsopts=-N), possibly yielding wrong
-- answers on a range of tasks, including serialization.
{-# OPTIONS_GHC -fno-full-laziness #-}

module Cardano.Crypto.DSIGN.BLS12381 (
  BLS12381DSIGN,
  BLS12381MinVerKeyDSIGN,
  BLS12381MinSigDSIGN,
  BLS12381CurveConstraints,
  VerKeyDSIGN (..),
  SignKeyDSIGN (..),
  SigDSIGN (..),
  PossessionProofDSIGN (..),
  BLS12381SignContext (..),
) where

#include "blst_util.h"

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Crypto.DSIGN.Class (
  DSIGNAggregatable (..),
  DSIGNAlgorithm (
    ContextDSIGN,
    KeyGenContextDSIGN,
    SeedSizeDSIGN,
    SigDSIGN,
    SignKeyDSIGN,
    Signable,
    SizeSigDSIGN,
    SizeSignKeyDSIGN,
    SizeVerKeyDSIGN,
    VerKeyDSIGN,
    algorithmNameDSIGN,
    deriveVerKeyDSIGN,
    genKeyDSIGN,
    genKeyDSIGNWithKeyInfo,
    rawDeserialiseSigDSIGN,
    rawDeserialiseSignKeyDSIGN,
    rawDeserialiseVerKeyDSIGN,
    rawSerialiseSigDSIGN,
    rawSerialiseSignKeyDSIGN,
    rawSerialiseVerKeyDSIGN,
    signDSIGN,
    verifyDSIGN
  ),
  decodePossessionProofDSIGN,
  decodeSigDSIGN,
  decodeSignKeyDSIGN,
  decodeVerKeyDSIGN,
  encodePossessionProofDSIGN,
  encodeSigDSIGN,
  encodeSignKeyDSIGN,
  encodeVerKeyDSIGN,
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
  FinalVerifyOrder,
  Point (..),
  Scalar (..),
  ScalarPtr (..),
  blsAddOrDouble,
  blsCompress,
  blsGenerator,
  blsHash,
  blsIsInf,
  blsMult,
  blsUncompress,
  blsZero,
  c_blst_keygen,
  compressedSizePoint,
  finalVerifyPairs,
  mkBLSTError,
  scalarFromBS,
  scalarToBS,
  scalarToInteger,
  toAffine,
  withAffine,
  withMaybeCStringLen,
  withNewPoint',
  withNewPoint_,
 )
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreate,
  psbUseAsCPtr,
 )
import Cardano.Crypto.Seed (getBytesFromSeedT)
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Control.DeepSeq (NFData)
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

data BLS12381DSIGN curve

-- Making sure different 'Signature schemes are not 'Coercible', which would ruin the
-- intended type safety:
type role BLS12381DSIGN nominal

-- | Two versions of BLS12-381 DSIGN: one optimized for minimal verification key size,
-- the other for minimal signature size.
type BLS12381MinVerKeyDSIGN = BLS12381DSIGN Curve1

type BLS12381MinSigDSIGN = BLS12381DSIGN Curve2

type family CurveVariant (c :: Type) :: Symbol where
  CurveVariant Curve1 = "BLS-Signature-Mininimal-Verification-Key-Size"
  CurveVariant Curve2 = "BLS-Signature-Mininimal-Signature-Size"

data BLS12381SignContext = BLS12381SignContext
  { blsSignContextDst :: !(Maybe ByteString)
  , blsSignContextAug :: !(Maybe ByteString)
  }
  deriving stock (Show, Eq, Generic)
  deriving anyclass (NFData, NoThunks)

type BLS12381CurveConstraints curve =
  ( BLS curve
  , BLS (DualCurve curve)
  , FinalVerifyOrder curve
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
  type SizeSignKeyDSIGN (BLS12381DSIGN curve) = CARDANO_BLST_SCALAR_SIZE

  -- These *Sizes* are used in the serialization/deserialization
  -- so these use the compressed sizes of the BLS12-381 `Point curve`
  type SizeVerKeyDSIGN (BLS12381DSIGN curve) = CompressedPointSize curve
  type SizeSigDSIGN (BLS12381DSIGN curve) = CompressedPointSize (DualCurve curve)
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
    = SignKeyBLS12381 (PinnedSizedBytes (SizeSignKeyDSIGN (BLS12381DSIGN curve)))
    -- The use of Eq from PinnedSizedBytes is needed here, as we need constant time
    -- comparison for signing keys
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)

  newtype SigDSIGN (BLS12381DSIGN curve)
    = -- Note that the internal representation is the uncompressed point size
      SigBLS12381 (Point (DualCurve curve))
    deriving newtype (NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)

  algorithmNameDSIGN _ = "bls12-381-" ++ symbolVal (Proxy @(CurveVariant curve))

  {-# INLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeyBLS12381 skPsb) = do
    VerKeyBLS12381 $ unsafeDupablePerformIO . psbUseAsCPtr skPsb $ \skp ->
      withNewPoint' @curve $ \vkPtp -> do
        c_blst_sk_to_pk @curve vkPtp (ScalarPtr skp)

  {-# INLINE signDSIGN #-}
  signDSIGN BLS12381SignContext {blsSignContextDst = dst, blsSignContextAug = aug} msg (SignKeyBLS12381 skPsb) =
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
  genKeyDSIGN = genKeyDSIGNWithKeyInfo Nothing

  {-# INLINE genKeyDSIGNWithKeyInfo #-}
  -- Generate a signing key from a seed and optional key info
  -- as per the IETF bls signature draft 05
  genKeyDSIGNWithKeyInfo keyInfo seed =
    SignKeyBLS12381 $
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

  -- Note that this also compresses the signature according to the ZCash standard
  {-# INLINE rawSerialiseSigDSIGN #-}
  rawSerialiseSigDSIGN (SigBLS12381 sigPSB) = blsCompress @(DualCurve curve) sigPSB

  {-# INLINE rawSerialiseVerKeyDSIGN #-}
  -- Note that this also compresses the verification key according to the ZCash standard
  rawSerialiseVerKeyDSIGN (VerKeyBLS12381 vkPSB) = blsCompress @curve vkPSB

  {-# INLINE rawSerialiseSignKeyDSIGN #-}
  rawSerialiseSignKeyDSIGN (SignKeyBLS12381 skPSB) = scalarToBS (Scalar skPSB)

  {-# INLINE rawDeserialiseVerKeyDSIGN #-}
  rawDeserialiseVerKeyDSIGN bs =
    -- Note that this also performs a group membership check.
    -- That is, the deserialised point is in the subgroup of Curve1/Curve2.
    case blsUncompress @curve bs of
      Left _ -> Nothing
      Right vkPsb -> Just (VerKeyBLS12381 vkPsb)

  {-# INLINE rawDeserialiseSignKeyDSIGN #-}
  rawDeserialiseSignKeyDSIGN bs =
    -- A signing key is strictly a BE integer mod the curve order.
    -- The `DSIGN` interface via PSB would ensure at the type level that
    -- they are of size 32 bytes (256 bits). But we must even ensure
    -- they are valid Scalars, i.e., less than the curve order (255 bits).
    case scalarFromBS bs of
      Left _ -> Nothing
      Right (Scalar skPsb) -> Just (SignKeyBLS12381 skPsb)

  {-# INLINE rawDeserialiseSigDSIGN #-}
  rawDeserialiseSigDSIGN bs =
    -- Note that this also performs a group membership check.
    -- That is, the deserialised point is in the subgroup of Curve1/Curve2.
    case blsUncompress @(DualCurve curve) bs of
      Left _ -> Nothing
      Right sigPsb -> Just (SigBLS12381 sigPsb)

deriving stock instance
  BLS curve =>
  Eq (VerKeyDSIGN (BLS12381DSIGN curve))

deriving stock instance
  BLS (DualCurve curve) =>
  Eq (SigDSIGN (BLS12381DSIGN curve))

instance
  BLS12381CurveConstraints curve =>
  ToCBOR (VerKeyDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance
  BLS12381CurveConstraints curve =>
  FromCBOR (VerKeyDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeVerKeyDSIGN

instance
  BLS12381CurveConstraints curve =>
  ToCBOR (SignKeyDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance
  BLS12381CurveConstraints curve =>
  FromCBOR (SignKeyDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeSignKeyDSIGN

instance
  BLS12381CurveConstraints curve =>
  ToCBOR (SigDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodeSigDSIGN
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
  fromCBOR = decodeSigDSIGN

instance
  ( BLS12381CurveConstraints curve
  , KnownNat (CompressedPointSize (DualCurve curve) + CompressedPointSize (DualCurve curve))
  ) =>
  DSIGNAggregatable (BLS12381DSIGN curve)
  where
  type
    -- Sizes used in serialization/deserialization
    -- so these use the compressed sizes of the BLS12-381 `Point curve`
    PossessionProofSizeDSIGN (BLS12381DSIGN curve) =
      CompressedPointSize (DualCurve curve) + CompressedPointSize (DualCurve curve)

  data PossessionProofDSIGN (BLS12381DSIGN curve) = PossessionProofBLS12381
    { mu1 :: !(Point (DualCurve curve))
    , mu2 :: !(Point (DualCurve curve))
    }
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
    deriving anyclass (NFData)

  {-# INLINE uncheckedAggregateVerKeysDSIGN #-}
  uncheckedAggregateVerKeysDSIGN verKeys = do
    -- Sum the verification keys as curve points
    let aggrPoint =
          F.foldl' blsAddOrDouble (blsZero @curve) (map verKeyToPoint verKeys)
    -- Unlikely case, but best to reject infinity as an aggregate verification
    -- key. This happens if, for every secret/verification key pair, the inverse
    -- of each secret key (and thus also the verification key) is also present
    -- in the list.
    if blsIsInf @curve aggrPoint
      then Left "aggregateVerKeysDSIGN: aggregated verification key is infinity"
      else Right $ VerKeyBLS12381 aggrPoint

  {-# INLINE aggregateSigsDSIGN #-}
  aggregateSigsDSIGN sigs = do
    -- Sum the signatures as curve points
    let aggrPoint =
          F.foldl' blsAddOrDouble (blsZero @(DualCurve curve)) (map sigToPoint sigs)
    -- Unlikely case, but best to reject infinity as an aggregate signature
    if blsIsInf @(DualCurve curve) aggrPoint
      then Left "aggregateSigsDSIGN: aggregated signature is infinity"
      else Right $ SigBLS12381 aggrPoint

  {-# INLINE createPossessionProofDSIGN #-}
  createPossessionProofDSIGN BLS12381SignContext {blsSignContextDst = dst, blsSignContextAug = aug} (SignKeyBLS12381 skPsb) =
    unsafeDupablePerformIO $ do
      skAsInteger <- scalarToInteger (Scalar skPsb)
      let VerKeyBLS12381 vkPsb =
            deriveVerKeyDSIGN (SignKeyBLS12381 skPsb) ::
              VerKeyDSIGN (BLS12381DSIGN curve)
          vk = blsCompress @curve vkPsb
          mu1Psb =
            blsMult (blsHash @(DualCurve curve) vk dst aug) skAsInteger
          mu2Psb =
            blsMult (blsGenerator @(DualCurve curve)) skAsInteger
      return $ PossessionProofBLS12381 mu1Psb mu2Psb
  {-# INLINE verifyPossessionProofDSIGN #-}
  verifyPossessionProofDSIGN BLS12381SignContext {blsSignContextDst = dst, blsSignContextAug = aug} (VerKeyBLS12381 vk) (PossessionProofBLS12381 mu1Psb mu2Psb) =
    let check1 =
          finalVerifyPairs @curve (blsGenerator, mu1Psb) (vk, blsHash (blsCompress vk) dst aug)
        check2 = finalVerifyPairs @curve (vk, blsGenerator) (blsGenerator, mu2Psb)
     in if check1 && check2
          then Right ()
          else Left "verifyPossessionProofDSIGN: BLS12381DSIGN failed to verify."
  {-# INLINE rawSerialisePossessionProofDSIGN #-}
  rawSerialisePossessionProofDSIGN (PossessionProofBLS12381 mu1Psb mu2Psb) =
    blsCompress @(DualCurve curve) mu1Psb <> blsCompress @(DualCurve curve) mu2Psb
  {-# INLINE rawDeserialisePossessionProofDSIGN #-}
  rawDeserialisePossessionProofDSIGN bs =
    let chunkSize = compressedSizePoint (Proxy @(DualCurve curve))
        (mu1Bs, mu2Bs) = BS.splitAt chunkSize bs
     in do
          -- Note that these also perform group membership and size checks.
          -- It will also ensure that all of the supplied `ByteString` is consumed
          -- through the size checks.
          Right mu1Point <- pure $ blsUncompress @(DualCurve curve) mu1Bs
          Right mu2Point <- pure $ blsUncompress @(DualCurve curve) mu2Bs
          Just $ PossessionProofBLS12381 mu1Point mu2Point

deriving stock instance
  BLS (DualCurve curve) =>
  Eq (PossessionProofDSIGN (BLS12381DSIGN curve))

instance
  ( BLS12381CurveConstraints curve
  , KnownNat (CompressedPointSize (DualCurve curve) + CompressedPointSize (DualCurve curve))
  ) =>
  ToCBOR (PossessionProofDSIGN (BLS12381DSIGN curve))
  where
  toCBOR = encodePossessionProofDSIGN
  encodedSizeExpr _ = encodedPossessionProofDSIGNSizeExpr

instance
  ( BLS12381CurveConstraints curve
  , KnownNat (CompressedPointSize (DualCurve curve) + CompressedPointSize (DualCurve curve))
  ) =>
  FromCBOR (PossessionProofDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodePossessionProofDSIGN
