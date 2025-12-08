{-# LANGUAGE CPP #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
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
  BLS12381MinVerKeyDSIGN,
  BLS12381MinSigDSIGN,
  VerKeyDSIGN (..),
  SignKeyDSIGN (..),
  SigDSIGN (..),
) where

#include "blst_util.h"

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Crypto.DSIGN.Class (
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
  decodeSigDSIGN,
  decodeSignKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSigDSIGN,
  encodeSignKeyDSIGN,
  encodeVerKeyDSIGN,
  encodedSigDSIGNSizeExpr,
  encodedSignKeyDSIGNSizeExpr,
  encodedVerKeyDSIGNSizeExpr,
  seedSizeDSIGN,
 )
import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  BLS (..),
  CompressedPointSize,
  Curve1,
  Curve2,
  Dual,
  FinalVerifyOrder,
  Point (..),
  PointPtr (..),
  PointSize,
  Scalar (..),
  ScalarPtr (..),
  blsCompress,
  blsGenerator,
  blsHash,
  blsUncompress,
  c_blst_keygen,
  finalVerifyPairs,
  scalarFromBS,
  scalarToBS,
  withMaybeCStringLen,
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
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Data (Typeable)
import Data.Kind (Type)
import Data.Proxy (Proxy (Proxy))
import GHC.Generics (Generic)
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)
import GHC.TypeNats (KnownNat)
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

-- Manual instance to avoid using the PinnedSizedBytes Eq instance
-- but use the Point Eq instance instead.
--
-- Note that a Point on the curve is a representative of an equivalence class.
-- That is, given a point P, then p ~ [x:y,z] in projective coordinates.
-- If we round trip via the compressed form (via rawSerialise/Deserialise),
-- we get a canonical representative of the equivalence class that might differ!
-- That is, from compressed (x,y) we get back [x:y,0].
instance
  BLS curve =>
  Eq (VerKeyDSIGN (BLS12381DSIGN curve))
  where
  VerKeyBLS12381 vk1 == VerKeyBLS12381 vk2 =
    let p1 = Point @curve vk1
        p2 = Point @curve vk2
     in p1 == p2

-- Manual instance to avoid using the PinnedSizedBytes Eq instance
-- but use the Point Eq instance instead.
--
-- Note that a Point on the curve is a representative of an equivalence class.
-- That is, given a point P, then p ~ [x:y,z] in projective coordinates.
-- If we round trip via the compressed form (via rawSerialise/Deserialise),
-- we get a canonical representative of the equivalence class that might differ!
-- That is, from compressed (x,y) we get back [x:y,0].
instance
  BLS (Dual curve) =>
  Eq (SigDSIGN (BLS12381DSIGN curve))
  where
  SigBLS12381 s1 == SigBLS12381 s2 =
    let p1 = Point @(Dual curve) s1
        p2 = Point @(Dual curve) s2
     in p1 == p2

type BLS12381CurveConstraints curve =
  ( BLS curve
  , BLS (Dual curve)
  , FinalVerifyOrder curve
  , KnownSymbol (CurveVariant curve)
  , KnownNat (CompressedPointSize curve)
  , KnownNat (CompressedPointSize (Dual curve))
  , Typeable curve
  )

instance
  BLS12381CurveConstraints curve =>
  DSIGNAlgorithm (BLS12381DSIGN curve)
  where
  type SeedSizeDSIGN (BLS12381DSIGN curve) = CARDANO_BLST_SCALAR_SIZE
  type SizeSignKeyDSIGN (BLS12381DSIGN curve) = CARDANO_BLST_SCALAR_SIZE

  -- \| These *Sizes* are used in the serialization/deserialization
  -- so these use the compressed sizes of the BLS12-381 `Point curve`
  type SizeVerKeyDSIGN (BLS12381DSIGN curve) = CompressedPointSize curve
  type SizeSigDSIGN (BLS12381DSIGN curve) = CompressedPointSize (Dual curve)
  type Signable (BLS12381DSIGN curve) = SignableRepresentation

  -- \| Context can hold domain seperation tag and/or augmentation data for signatures
  type ContextDSIGN (BLS12381DSIGN curve) = (Maybe ByteString, Maybe ByteString)
  type KeyGenContextDSIGN (BLS12381DSIGN curve) = Maybe ByteString
  newtype VerKeyDSIGN (BLS12381DSIGN curve)
    = -- Note that the internal representation is the uncompressed point size
      VerKeyBLS12381 (PinnedSizedBytes (PointSize curve))
    deriving newtype (NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SignKeyDSIGN (BLS12381DSIGN curve)
    = SignKeyBLS12381 (PinnedSizedBytes (SizeSignKeyDSIGN (BLS12381DSIGN curve)))
    -- Us Eq from PinnedSizedBytes is needed here, as we need constant time
    -- comparison for signing keys
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  newtype SigDSIGN (BLS12381DSIGN curve)
    = -- Note that the internal representation is the uncompressed point size
      SigBLS12381 (PinnedSizedBytes (PointSize (Dual curve)))
    deriving newtype (NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)
  algorithmNameDSIGN _ = "bls12-381-" ++ symbolVal (Proxy @(CurveVariant curve))
  {-# NOINLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeyBLS12381 skPsb) = do
    VerKeyBLS12381 $ unsafeDupablePerformIO . psbUseAsCPtr skPsb $ \skp ->
      psbCreate $ \vkPtp ->
        c_blst_sk_to_pk @curve (PointPtr vkPtp) (ScalarPtr skp)
  {-# NOINLINE signDSIGN #-}
  signDSIGN (dst, aug) msg (SignKeyBLS12381 skPsb) =
    SigBLS12381 $ unsafeDupablePerformIO . psbCreate $ \sigPts -> do
      let bs = getSignableRepresentation msg
      withMaybeCStringLen dst $ \(dstPtr, dstLen) ->
        withMaybeCStringLen aug $ \(augPtr, augLen) ->
          unsafeUseAsCStringLen bs $ \(msgPtr, msgLen) ->
            psbUseAsCPtr skPsb $ \skPtp -> do
              withNewPoint_ @(Dual curve) $ \hashPtr -> do
                c_blst_hash @(Dual curve)
                  hashPtr
                  msgPtr
                  (fromIntegral msgLen)
                  dstPtr
                  (fromIntegral dstLen)
                  augPtr
                  (fromIntegral augLen)
                c_blst_sign @curve
                  (Proxy @curve)
                  (PointPtr sigPts)
                  hashPtr
                  (ScalarPtr skPtp)
  {-# NOINLINE verifyDSIGN #-}
  -- \| Context can hold domain seperation tag and/or augmentation data for signatures
  verifyDSIGN (dst, aug) (VerKeyBLS12381 pbPsb) msg (SigBLS12381 sigPsb) =
    let bs = getSignableRepresentation msg
     in -- here we check that e(g1, sig) == e(pk, H(msg)) or equivalently
        -- e(sig, g2) == e(H(msg),pk) depending on the curve choice for pk/sig.
        if finalVerifyPairs @curve (blsGenerator, Point sigPsb) (Point pbPsb, blsHash bs dst aug)
          then Right ()
          else Left "SigDSIGN BLS12381DSIGN failed to verify."
  {-# NOINLINE genKeyDSIGN #-}
  genKeyDSIGN = genKeyDSIGNWithKeyInfo Nothing
  {-# NOINLINE genKeyDSIGNWithKeyInfo #-}
  -- \| Generate a signing key from a seed and optional key info
  -- as per the IETF bls signature draft 05
  genKeyDSIGNWithKeyInfo keyInfo seed =
    SignKeyBLS12381 $
      let (bs, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @(BLS12381DSIGN curve))) seed
       in unsafeDupablePerformIO $ do
            withMaybeCStringLen keyInfo $ \(infoPtr, infoLen) ->
              unsafeUseAsCStringLen bs $ \(ikmPtr, ikmLen) ->
                psbCreate $ \skp ->
                  c_blst_keygen (ScalarPtr skp) ikmPtr (fromIntegral ikmLen) infoPtr (fromIntegral infoLen)

  -- \| Note that this also compresses the signature according to the ZCash standard
  rawSerialiseSigDSIGN (SigBLS12381 sigPSB) = blsCompress @(Dual curve) (Point sigPSB)
  {-# NOINLINE rawSerialiseVerKeyDSIGN #-}
  -- \| Note that this also compresses the verification key according to the ZCash standard
  rawSerialiseVerKeyDSIGN (VerKeyBLS12381 vkPSB) = blsCompress @curve (Point vkPSB)
  {-# NOINLINE rawSerialiseSignKeyDSIGN #-}
  rawSerialiseSignKeyDSIGN (SignKeyBLS12381 skPSB) = scalarToBS (Scalar skPSB)
  {-# NOINLINE rawDeserialiseVerKeyDSIGN #-}
  rawDeserialiseVerKeyDSIGN bs =
    -- Note that this also performs a group membership check.
    -- That is, the deserialised point is in the subgroup of Curve1/Curve2.
    case blsUncompress @curve bs of
      Left _ -> Nothing
      Right (Point vkPsb) -> Just (VerKeyBLS12381 vkPsb)
  {-# NOINLINE rawDeserialiseSignKeyDSIGN #-}
  rawDeserialiseSignKeyDSIGN bs =
    -- A signing key is strictly a BE integer mod the curve order.
    -- The `DSIGN` interface via PSB would ensure at the type level that
    -- they are of size 32 bytes (256 bits). But we must even ensure
    -- they are valid Scalars, i.e., less than the curve order (255 bits).
    case scalarFromBS bs of
      Left _ -> Nothing
      Right (Scalar skPsb) -> Just (SignKeyBLS12381 skPsb)
  rawDeserialiseSigDSIGN bs =
    -- Note that this also performs a group membership check.
    -- That is, the deserialised point is in the subgroup of Curve1/Curve2.
    case blsUncompress @(Dual curve) bs of
      Left _ -> Nothing
      Right (Point sigPsb) -> Just (SigBLS12381 sigPsb)

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

instance
  BLS12381CurveConstraints curve =>
  FromCBOR (SigDSIGN (BLS12381DSIGN curve))
  where
  fromCBOR = decodeSigDSIGN
