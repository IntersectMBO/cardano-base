{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  -- * Unsafe Types
  ScalarPtr (..),
  PointPtr (..),
  AffinePtr (..),
  PointArrayPtr (..),
  AffineArrayPtr (..),
  AffineBlockPtr (..),
  Point1Ptr,
  Point2Ptr,
  Affine1Ptr,
  Affine2Ptr,
  PTPtr,

  -- * Phantom Types
  Curve1,
  Curve2,

  -- * Error codes
  c_blst_success,
  c_blst_error_bad_encoding,
  c_blst_error_point_not_on_curve,
  c_blst_error_point_not_in_group,
  c_blst_error_aggr_type_mismatch,
  c_blst_error_verify_fail,
  c_blst_error_pk_is_infinity,
  c_blst_error_bad_scalar,

  -- * Safe types
  Affine,
  Affine1,
  Affine2,
  BLSTError (..),
  Point (..),
  Point1,
  Point2,
  PT,
  Scalar (..),
  SecretKey (..),
  PublicKey (..),
  Signature (..),
  Dual,
  FinalVerifyOrder,
  PairingSide,
  ProofOfPossession (..),
  encodeProofOfPossession,
  decodeProofOfPossession,
  Fr (..),
  unsafePointFromPointPtr,

  -- * The period of scalars
  scalarPeriod,

  -- * Curve abstraction
  BLS (
    c_blst_on_curve,
    c_blst_add_or_double,
    c_blst_mult,
    c_blst_cneg,
    c_blst_scratch_sizeof,
    c_blst_to_affines,
    c_blst_mult_pippenger,
    c_blst_hash,
    c_blst_compress,
    c_blst_serialize,
    c_blst_uncompress,
    c_blst_deserialize,
    c_blst_in_g,
    c_blst_to_affine,
    c_blst_from_affine,
    c_blst_affine_in_g,
    c_blst_generator,
    c_blst_p_is_equal,
    c_blst_p_is_inf,
    c_blst_sk_to_pk,
    c_blst_sign
  ),

  -- * Pairing check
  c_blst_miller_loop,

  -- * Keygen
  c_blst_keygen,

  -- * FP12 functions

  --
  c_blst_fp12_mul,
  c_blst_fp12_is_equal,
  c_blst_fp12_finalverify,

  -- * Scalar functions
  c_blst_scalar_fr_check,
  c_blst_scalar_from_fr,
  c_blst_fr_from_scalar,
  c_blst_scalar_from_be_bytes,
  c_blst_bendian_from_scalar,

  -- * Marshalling functions
  sizePoint,
  withPoint,
  withNewPoint,
  withNewPoint_,
  withNewPoint',
  clonePoint,
  compressedSizePoint,
  serializedSizePoint,
  sizeAffine,
  withAffine,
  withNewAffine,
  withNewAffine_,
  withNewAffine',
  withPointArray,
  withAffineBlockArrayPtr,
  sizePT,
  withPT,
  withNewPT,
  withNewPT_,
  withNewPT',
  sizeScalar,
  withScalar,
  withNewScalar,
  withNewScalar_,
  withNewScalar',
  withScalarArray,
  cloneScalar,
  sizeFr,
  withFr,
  withNewFr,
  withNewFr_,
  withNewFr',
  cloneFr,

  -- * PSB sizes
  PointBytes,
  AffineBytes,
  PTBytes,

  -- * Utility
  integerAsCStrL,
  cstrToInteger,
  integerToBS,
  padBS,

  -- * Point1/G1 operations
  blsInGroup,
  blsAddOrDouble,
  blsMult,
  blsCneg,
  blsNeg,
  blsMSM,
  blsCompress,
  blsSerialize,
  blsUncompress,
  blsDeserialize,
  blsHash,
  blsGenerator,
  blsIsInf,
  blsZero,
  toAffine,
  fromAffine,
  affineInG,

  -- * PT operations
  ptMult,
  ptFinalVerify,

  -- * Scalar / Fr operations
  scalarFromFr,
  frFromScalar,
  frFromCanonicalScalar,
  scalarFromBS,
  scalarToBS,
  scalarFromInteger,
  scalarToInteger,
  scalarCanonical,

  -- * Byte encoders/decoders (internal; used later by DSIGN)
  secretKeyToBS,
  secretKeyFromBS,
  publicKeyToCompressedBS,
  publicKeyFromCompressedBS,
  publicKeyToUncompressedBS,
  publicKeyFromUncompressedBS,
  signatureToCompressedBS,
  signatureFromCompressedBS,
  signatureToUncompressedBS,
  signatureFromUncompressedBS,

  -- * Pairings
  millerLoop,
  finalVerifyPairs,

  -- * BLS signature operations
  blsKeyGen,
  blsSkToPk,
  blsSign,
  blsSignatureVerify,
  blsProofOfPossessionProve,
  blsProofOfPossessionVerify,
  blsAggregatePublicKeys,
  blsAggregateSignaturesSameMsg,
  blsAggregateSignaturesDistinctMsg,
  blsVerifyAggregateSameMsg,
  blsVerifyAggregateDistinctMsg,
)
where

import Cardano.Binary (Decoder, Encoding, decodeBytes, encodeBytes, encodeListLen, enforceSize)
import Control.Monad (forM_)
import Data.Bits (shiftL, shiftR, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Data.Foldable (foldrM)
import qualified Data.List as List
import Data.Proxy (Proxy (..))
import Data.Void
import Foreign (Storable (..), poke, sizeOf)
import Foreign.C.String
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreate,
  psbCreateResult,
  psbUseAsCPtr,
 )
import GHC.TypeLits (KnownNat, Nat)

---- Phantom Types

data Curve1
data Curve2

type family PointBytes curve :: Nat where
  PointBytes Curve1 = 144
  PointBytes Curve2 = 288

type family AffineBytes curve :: Nat where
  AffineBytes Curve1 = 96
  AffineBytes Curve2 = 192

-- | A type family mapping a curve to its dual curve (its an involution).
type family Dual curve where
  Dual Curve1 = Curve2
  Dual Curve2 = Curve1

---- Unsafe PointPtr types

-- | A pointer to a (projective) point one of the two elliptical curves
newtype PointPtr curve = PointPtr (Ptr Void)

-- | A pointer to a null-terminated array of pointers to points
newtype PointArrayPtr curve = PointArrayPtr (Ptr Void)

type Point1Ptr = PointPtr Curve1
type Point2Ptr = PointPtr Curve2

type Point1ArrayPtr = PointArrayPtr Curve1
type Point2ArrayPtr = PointArrayPtr Curve2

-- | A pointer to an affine point on one of the two elliptical curves
newtype AffinePtr curve = AffinePtr (Ptr Void)

-- | A pointer to a contiguous array of affine points
newtype AffineBlockPtr curve = AffineBlockPtr (Ptr Void)

-- | A pointer to a null-terminated array of pointers to affine points
newtype AffineArrayPtr curve = AffineArrayPtr (Ptr Void)

type Affine1Ptr = AffinePtr Curve1
type Affine2Ptr = AffinePtr Curve2

type Affine1BlockPtr = AffineBlockPtr Curve1
type Affine2BlockPtr = AffineBlockPtr Curve2

type Affine1ArrayPtr = AffineArrayPtr Curve1
type Affine2ArrayPtr = AffineArrayPtr Curve2

newtype PTPtr = PTPtr (Ptr Void)

unsafePointFromPointPtr ::
  forall curve.
  BLS curve =>
  PointPtr curve ->
  Point curve
unsafePointFromPointPtr (PointPtr ptr) =
  Point . unsafePerformIO $
    psbCreate @(PointBytes curve) $ \dst ->
      copyBytes dst (castPtr ptr) (sizePoint (Proxy @curve))

eqAffinePtr :: forall curve. BLS curve => AffinePtr curve -> AffinePtr curve -> IO Bool
eqAffinePtr (AffinePtr a) (AffinePtr b) =
  (== 0) <$> c_memcmp (castPtr a) (castPtr b) (sizeAffine_ (Proxy @curve))

instance BLS curve => Eq (AffinePtr curve) where
  a == b = unsafePerformIO $ eqAffinePtr a b

---- Safe Point types / marshalling

-- | A point on an elliptic curve. This type guarantees that the point is part of the
-- | prime order subgroup.
newtype Point curve = Point (PinnedSizedBytes (PointBytes curve))

-- Making sure different 'Point's are not 'Coercible', which would ruin the
-- intended type safety:
type role Point nominal

type Point1 = Point Curve1
type Point2 = Point Curve2

newtype Affine curve = Affine (PinnedSizedBytes (AffineBytes curve))

-- Making sure different 'Affine's are not 'Coercible', which would ruin the
-- intended type safety:
type role Affine nominal

type Affine1 = Affine Curve1
type Affine2 = Affine Curve2

-- | Target element without the final exponantiation. By defining target elements
-- | as such, we save up the final exponantiation when computing a pairing, and only
-- | compute it when necessary (e.g. comparison with another point or serialisation)
newtype PT = PT (PinnedSizedBytes PTBytes)

-- | Sizes of various representations of elliptic curve points.
-- | Size of a curve point in memory
sizePoint :: forall curve. BLS curve => Proxy curve -> Int
sizePoint = fromIntegral . sizePoint_

-- | Size of a curved point when serialized in compressed form
compressedSizePoint :: forall curve. BLS curve => Proxy curve -> Int
compressedSizePoint = fromIntegral . compressedSizePoint_

-- | Size of a curved point when serialized in uncompressed form
serializedSizePoint :: forall curve. BLS curve => Proxy curve -> Int
serializedSizePoint = fromIntegral . serializedSizePoint_

-- | In-memory size of the affine representation of a curve point
sizeAffine :: forall curve. BLS curve => Proxy curve -> Int
sizeAffine = fromIntegral . sizeAffine_

withPoint :: forall a curve. Point curve -> (PointPtr curve -> IO a) -> IO a
withPoint (Point psb) go =
  psbUseAsCPtr psb $ \ptr ->
    go (PointPtr (castPtr ptr))

withNewPoint :: forall curve a. BLS curve => (PointPtr curve -> IO a) -> IO (a, Point curve)
withNewPoint go = do
  (psb, res) <-
    psbCreateResult @(PointBytes curve) $ \ptr ->
      go (PointPtr (castPtr ptr))
  pure (res, Point psb)

withNewPoint_ :: BLS curve => (PointPtr curve -> IO a) -> IO a
withNewPoint_ = fmap fst . withNewPoint

withNewPoint' :: BLS curve => (PointPtr curve -> IO a) -> IO (Point curve)
withNewPoint' = fmap snd . withNewPoint

clonePoint :: forall curve. BLS curve => Point curve -> IO (Point curve)
clonePoint (Point src) = do
  Point
    <$> psbCreate @(PointBytes curve)
      ( \dst ->
          psbUseAsCPtr src $ \srcPtr ->
            copyBytes dst srcPtr (sizePoint (Proxy @curve))
      )

withAffine :: forall a curve. Affine curve -> (AffinePtr curve -> IO a) -> IO a
withAffine (Affine psb) go =
  psbUseAsCPtr psb $ \ptr ->
    go (AffinePtr (castPtr ptr))

withNewAffine :: forall curve a. BLS curve => (AffinePtr curve -> IO a) -> IO (a, Affine curve)
withNewAffine go = do
  (psb, res) <-
    psbCreateResult @(AffineBytes curve) $ \ptr ->
      go (AffinePtr (castPtr ptr))
  pure (res, Affine psb)

withNewAffine_ :: BLS curve => (AffinePtr curve -> IO a) -> IO a
withNewAffine_ = fmap fst . withNewAffine

withNewAffine' :: BLS curve => (AffinePtr curve -> IO a) -> IO (Affine curve)
withNewAffine' = fmap snd . withNewAffine

-- | Build a temporary null-terminated array of pointers to the given points.
-- The pointers reference the underlying PSB storage, so the array is only
-- valid for the duration of the continuation supplied to this helper.
withPointArray ::
  [Point curve] ->
  (Int -> PointArrayPtr curve -> IO a) ->
  IO a
withPointArray points go = do
  let numPoints = length points
      sizeReference = sizeOf (nullPtr :: Ptr ())
  -- Allocate space for the points and a null terminator
  allocaBytes ((numPoints + 1) * sizeReference) $ \ptr ->
    -- The accumulate function ensures that each `withPoint` call is properly nested.
    -- This guarantees that the foreign pointers remain valid while we populate `ptr`.
    -- If we instead used `zipWithM_` for example, the pointers could be finalized too early.
    -- By nesting `withPoint` calls in `accumulate`, we ensure they stay in scope until `go` is executed.
    let accumulate curPtr [] = do
          poke curPtr nullPtr
          go numPoints (PointArrayPtr (castPtr ptr))
        accumulate curPtr (point : rest) =
          withPoint point $ \(PointPtr pPtr) -> do
            poke curPtr pPtr
            accumulate (curPtr `plusPtr` sizeReference) rest
     in accumulate ptr points

-- | Given a block of affine points and a count, produce a pointer array
-- | Given a contiguous affine block produced by 'c_blst_to_affines', build a
-- short-lived array-of-pointers view expected by the MSM routines.  The block
-- and the resulting pointer array live only for the duration of the supplied
-- continuation.
withAffineBlockArrayPtr ::
  forall curve a.
  BLS curve =>
  Ptr Void -> Int -> (AffineArrayPtr curve -> IO a) -> IO a
withAffineBlockArrayPtr affinesBlockPtr numPoints go = do
  allocaBytes (numPoints * sizeOf (nullPtr :: Ptr ())) $ \affineVectorPtr -> do
    let ptrArray = castPtr affineVectorPtr :: Ptr (Ptr ())
    forM_ [0 .. numPoints - 1] $ \i -> do
      let ptr = affinesBlockPtr `plusPtr` (i * sizeAffine (Proxy @curve))
      pokeElemOff ptrArray i ptr
    go (AffineArrayPtr affineVectorPtr)

type PTBytes = 576 :: Nat

withPT :: PT -> (PTPtr -> IO a) -> IO a
withPT (PT psb) go =
  psbUseAsCPtr psb $ \ptr ->
    go (PTPtr (castPtr ptr))

withNewPT :: (PTPtr -> IO a) -> IO (a, PT)
withNewPT go = do
  (psb, res) <-
    psbCreateResult @PTBytes $ \ptr ->
      go (PTPtr (castPtr ptr))
  pure (res, PT psb)

withNewPT_ :: (PTPtr -> IO a) -> IO a
withNewPT_ = fmap fst . withNewPT

withNewPT' :: (PTPtr -> IO a) -> IO PT
withNewPT' = fmap snd . withNewPT

sizePT :: Int
sizePT = fromIntegral c_size_blst_fp12

---- Curve operations

-- | BLS curve operations. Class methods are low-level; user code will want to
-- use higher-level wrappers such as 'blsAddOrDouble', 'blsMult', 'blsCneg', 'blsNeg', etc.
class
  ( KnownNat (PointBytes curve)
  , KnownNat (AffineBytes curve)
  ) =>
  BLS curve
  where
  c_blst_on_curve :: PointPtr curve -> IO Bool

  c_blst_add_or_double :: PointPtr curve -> PointPtr curve -> PointPtr curve -> IO ()
  c_blst_mult :: PointPtr curve -> PointPtr curve -> ScalarPtr -> CSize -> IO ()
  c_blst_cneg :: PointPtr curve -> Bool -> IO ()

  c_blst_scratch_sizeof :: Proxy curve -> CSize -> CSize
  c_blst_to_affines :: AffineBlockPtr curve -> PointArrayPtr curve -> CSize -> IO ()
  c_blst_mult_pippenger ::
    PointPtr curve -> AffineArrayPtr curve -> CSize -> ScalarArrayPtr -> CSize -> ScratchPtr -> IO ()

  c_blst_hash ::
    PointPtr curve -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> IO ()
  c_blst_compress :: Ptr CChar -> PointPtr curve -> IO ()
  c_blst_serialize :: Ptr CChar -> PointPtr curve -> IO ()
  c_blst_uncompress :: AffinePtr curve -> Ptr CChar -> IO CInt
  c_blst_deserialize :: AffinePtr curve -> Ptr CChar -> IO CInt

  c_blst_in_g :: PointPtr curve -> IO Bool
  c_blst_to_affine :: AffinePtr curve -> PointPtr curve -> IO ()
  c_blst_from_affine :: PointPtr curve -> AffinePtr curve -> IO ()
  c_blst_affine_in_g :: AffinePtr curve -> IO Bool
  c_blst_generator :: PointPtr curve

  c_blst_p_is_equal :: PointPtr curve -> PointPtr curve -> IO Bool
  c_blst_p_is_inf :: PointPtr curve -> IO Bool

  sizePoint_ :: Proxy curve -> CSize
  serializedSizePoint_ :: Proxy curve -> CSize
  compressedSizePoint_ :: Proxy curve -> CSize
  sizeAffine_ :: Proxy curve -> CSize

  c_blst_sk_to_pk :: PointPtr curve -> ScalarPtr -> IO ()
  c_blst_sign :: Proxy curve -> PointPtr (Dual curve) -> PointPtr (Dual curve) -> ScalarPtr -> IO ()

instance BLS Curve1 where
  c_blst_on_curve = c_blst_p1_on_curve

  c_blst_add_or_double = c_blst_p1_add_or_double
  c_blst_mult = c_blst_p1_mult
  c_blst_cneg = c_blst_p1_cneg

  c_blst_scratch_sizeof _ = c_blst_p1s_mult_pippenger_scratch_sizeof
  c_blst_to_affines = c_blst_p1s_to_affine
  c_blst_mult_pippenger = c_blst_p1s_mult_pippenger

  c_blst_hash = c_blst_hash_to_g1
  c_blst_compress = c_blst_p1_compress
  c_blst_serialize = c_blst_p1_serialize
  c_blst_uncompress = c_blst_p1_uncompress
  c_blst_deserialize = c_blst_p1_deserialize

  c_blst_in_g = c_blst_p1_in_g1
  c_blst_to_affine = c_blst_p1_to_affine
  c_blst_from_affine = c_blst_p1_from_affine
  c_blst_affine_in_g = c_blst_p1_affine_in_g1

  c_blst_generator = c_blst_p1_generator

  c_blst_p_is_equal = c_blst_p1_is_equal
  c_blst_p_is_inf = c_blst_p1_is_inf

  sizePoint_ _ = c_size_blst_p1
  compressedSizePoint_ _ = 48
  serializedSizePoint_ _ = 96
  sizeAffine_ _ = c_size_blst_affine1

  c_blst_sk_to_pk = c_blst_sk_to_pk_in_g1
  c_blst_sign _ = c_blst_sign_pk_in_g1

instance BLS Curve2 where
  c_blst_on_curve = c_blst_p2_on_curve

  c_blst_add_or_double = c_blst_p2_add_or_double
  c_blst_mult = c_blst_p2_mult
  c_blst_cneg = c_blst_p2_cneg

  c_blst_scratch_sizeof _ = c_blst_p2s_mult_pippenger_scratch_sizeof
  c_blst_to_affines = c_blst_p2s_to_affine
  c_blst_mult_pippenger = c_blst_p2s_mult_pippenger

  c_blst_hash = c_blst_hash_to_g2
  c_blst_compress = c_blst_p2_compress
  c_blst_serialize = c_blst_p2_serialize
  c_blst_uncompress = c_blst_p2_uncompress
  c_blst_deserialize = c_blst_p2_deserialize

  c_blst_in_g = c_blst_p2_in_g2
  c_blst_to_affine = c_blst_p2_to_affine
  c_blst_from_affine = c_blst_p2_from_affine
  c_blst_affine_in_g = c_blst_p2_affine_in_g2

  c_blst_generator = c_blst_p2_generator

  c_blst_p_is_equal = c_blst_p2_is_equal
  c_blst_p_is_inf = c_blst_p2_is_inf

  sizePoint_ _ = c_size_blst_p2
  compressedSizePoint_ _ = 96
  serializedSizePoint_ _ = 192
  sizeAffine_ _ = c_size_blst_affine2

  c_blst_sk_to_pk = c_blst_sk_to_pk_in_g2
  c_blst_sign _ = c_blst_sign_pk_in_g2

instance BLS curve => Eq (Affine curve) where
  a == b = unsafePerformIO $
    withAffine a $ \aptr ->
      withAffine b $ \bptr ->
        eqAffinePtr aptr bptr

---- Safe Scalar types / marshalling

sizeScalar :: Int
sizeScalar = fromIntegral c_size_blst_scalar

type ScalarBytes = 32 :: Nat

newtype Scalar = Scalar (PinnedSizedBytes ScalarBytes)

{-
- The BLS signature scheme as specified in the IETF draft
- https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html
-
- Note that the specification defines two variants, 'minimal-signature-size'
- and 'minimal-pubkey-size'. The former uses G1 for signatures and G2 for
- public keys, while the latter does the opposite.
-
- Below we implement both variants, using the phantom types 'Curve1' and
- 'Curve2' to distinguish them. The user-facing API is so that
-
- * Curve1 as 'curve' corresponds to "minimal-pubkey-size", i.e. public keys
-   are points in G1, signatures are points in G2 and POPs are points in G2.
- * Curve2 as 'curve' corresponds to "minimal-signature-size", i.e. public keys
-   are points in G2, signatures are points in G1 and POPs are points in G1.
-
- TODO: Add note on switching these around / reusing secret keys for both variants
-}

-- TODO: Asses is wrapping Scalar is enough to ensure security
-- against accidental leakage of secret keys.
newtype SecretKey = SecretKey {unSecretKey :: Scalar}
newtype PublicKey curve = PublicKey {unPublicKey :: Point curve}
newtype Signature curve = Signature {unSignature :: Point (Dual curve)}
data ProofOfPossession curve = ProofOfPossession
  { unMu1 :: Point (Dual curve)
  , unMu2 :: Point (Dual curve)
  }

encodeProofOfPossession ::
  forall curve.
  BLS (Dual curve) =>
  ProofOfPossession curve ->
  Encoding
encodeProofOfPossession (ProofOfPossession mu1 mu2) =
  encodeListLen 2
    <> encodeBytes (blsCompress @(Dual curve) mu1)
    <> encodeBytes (blsCompress @(Dual curve) mu2)

decodeProofOfPossession ::
  forall curve s.
  BLS (Dual curve) =>
  Decoder s (ProofOfPossession curve)
decodeProofOfPossession = do
  enforceSize "ProofOfPossession" 2
  mu1Bytes <- decodeBytes
  mu2Bytes <- decodeBytes
  mu1 <- decodePoint "mu1" mu1Bytes
  mu2 <- decodePoint "mu2" mu2Bytes
  pure (ProofOfPossession mu1 mu2)
  where
    decodePoint ::
      String ->
      ByteString ->
      Decoder s (Point (Dual curve))
    decodePoint label bytes =
      case blsUncompress @(Dual curve) bytes of
        Right point
          | blsIsInf point ->
              fail $
                "decodeProofOfPossession: "
                  <> label
                  <> " is infinity"
          | otherwise -> pure point
        Left err ->
          fail $
            "decodeProofOfPossession: "
              <> label
              <> " failed with "
              <> show err

instance (BLS curve, BLS (Dual curve)) => Eq (ProofOfPossession curve) where
  (ProofOfPossession mu1a mu2a) == (ProofOfPossession mu1b mu2b) =
    mu1a == mu1b && mu2a == mu2b

withIntScalar :: Integer -> (ScalarPtr -> IO a) -> IO a
withIntScalar i go = do
  s <- scalarFromInteger i
  withScalar s go

withScalar :: Scalar -> (ScalarPtr -> IO a) -> IO a
withScalar (Scalar psb) go =
  psbUseAsCPtr psb $ \ptr ->
    go (ScalarPtr (castPtr ptr))

withNewScalar :: (ScalarPtr -> IO a) -> IO (a, Scalar)
withNewScalar go = do
  (psb, res) <-
    psbCreateResult @ScalarBytes $ \ptr ->
      go (ScalarPtr (castPtr ptr))
  pure (res, Scalar psb)

withNewScalar_ :: (ScalarPtr -> IO a) -> IO a
withNewScalar_ = fmap fst . withNewScalar

withNewScalar' :: (ScalarPtr -> IO a) -> IO Scalar
withNewScalar' = fmap snd . withNewScalar

-- | Marshal a list of scalars into a temporary null-terminated pointer array.
-- Each entry borrows the PSB-backed scalar memory, so the array must not
-- escape the provided continuation.
withScalarArray :: [Scalar] -> (Int -> ScalarArrayPtr -> IO a) -> IO a
withScalarArray scalars go = do
  let numScalars = length scalars
      sizeReference = sizeOf (undefined :: Ptr ())
  -- Allocate space for the scalars and a null terminator
  allocaBytes ((numScalars + 1) * sizeReference) $ \ptr ->
    -- The accumulate function ensures that each `withScalar` call is properly nested.
    -- This guarantees that the foreign pointers remain valid while we populate `ptr`.
    -- If we instead used `zipWithM_` for example, the pointers could be finalized too early.
    -- By nesting `withScalar` calls in `accumulate`, we ensure they stay in scope until `go` is executed.
    let accumulate curPtr [] = do
          poke curPtr nullPtr
          go numScalars (ScalarArrayPtr (castPtr ptr))
        accumulate curPtr (scalar : rest) =
          withScalar scalar $ \(ScalarPtr pPtr) -> do
            poke curPtr pPtr
            accumulate (curPtr `plusPtr` sizeReference) rest
     in accumulate ptr scalars

cloneScalar :: Scalar -> IO Scalar
cloneScalar (Scalar src) =
  Scalar
    <$> psbCreate @ScalarBytes
      ( \dst ->
          psbUseAsCPtr src $ \srcPtr ->
            copyBytes dst srcPtr sizeScalar
      )

sizeFr :: Int
sizeFr = fromIntegral c_size_blst_fr

type FrBytes = 32 :: Nat

newtype Fr = Fr (PinnedSizedBytes FrBytes)

withFr :: Fr -> (FrPtr -> IO a) -> IO a
withFr (Fr psb) go =
  psbUseAsCPtr psb $ \ptr ->
    go (FrPtr (castPtr ptr))

withNewFr :: (FrPtr -> IO a) -> IO (a, Fr)
withNewFr go = do
  (psb, res) <-
    psbCreateResult @FrBytes $ \ptr ->
      go (FrPtr (castPtr ptr))
  pure (res, Fr psb)

withNewFr_ :: (FrPtr -> IO a) -> IO a
withNewFr_ = fmap fst . withNewFr

withNewFr' :: (FrPtr -> IO a) -> IO Fr
withNewFr' = fmap snd . withNewFr

cloneFr :: Fr -> IO Fr
cloneFr (Fr src) =
  Fr
    <$> psbCreate @FrBytes
      ( \dst ->
          psbUseAsCPtr src $ \srcPtr ->
            copyBytes dst srcPtr sizeFr
      )

scalarToInteger :: Scalar -> IO Integer
scalarToInteger scalar = withScalar scalar $ \scalarPtr -> do
  allocaBytes sizeScalar $ \rawPtr -> do
    c_blst_bendian_from_scalar rawPtr scalarPtr
    cstrToInteger rawPtr sizeScalar

cstrToInteger :: Ptr CChar -> Int -> IO Integer
cstrToInteger p l = do
  go l (castPtr p)
  where
    go :: Int -> Ptr CUChar -> IO Integer
    go n ptr
      | n <= 0 = pure 0
      | otherwise = do
          val <- peek ptr
          res <- go (pred n) (plusPtr ptr 1)
          return $ res .|. shiftL (fromIntegral val) (8 * pred n)

integerToBS :: Integer -> ByteString
integerToBS k
  | k < 0 = error "Cannot convert negative Integer to ByteString"
  | otherwise = go 0 [] k
  where
    go !i !acc 0 = BSI.unsafePackLenBytes i acc
    go !i !acc n = go (i + 1) (fromIntegral n : acc) (n `shiftR` 8)

padBS :: Int -> ByteString -> ByteString
padBS i b
  | i > BS.length b =
      BS.replicate (i - BS.length b) 0 <> b
  | otherwise =
      b

integerAsCStrL :: Int -> Integer -> (Ptr CChar -> Int -> IO a) -> IO a
integerAsCStrL i n f = do
  let bs = padBS i $ integerToBS n
  BS.useAsCStringLen bs $ uncurry f

scalarFromInteger :: Integer -> IO Scalar
scalarFromInteger n = do
  withNewScalar' $ \scalarPtr -> do
    integerAsCStrL sizeScalar (n `mod` scalarPeriod) $ \str _length -> do
      c_blst_scalar_from_bendian scalarPtr str

---- Unsafe types

newtype ScalarPtr = ScalarPtr (Ptr Void)

-- A pointer to a null-terminated array of pointers to scalars
newtype ScalarArrayPtr = ScalarArrayPtr (Ptr Void)
newtype FrPtr = FrPtr (Ptr Void)
newtype ScratchPtr = ScratchPtr (Ptr Void)

---- Raw Scalar / Fr functions

foreign import ccall "size_blst_scalar" c_size_blst_scalar :: CSize
foreign import ccall "size_blst_fr" c_size_blst_fr :: CSize

foreign import ccall "blst_scalar_fr_check" c_blst_scalar_fr_check :: ScalarPtr -> IO Bool

foreign import ccall "blst_scalar_from_fr" c_blst_scalar_from_fr :: ScalarPtr -> FrPtr -> IO ()
foreign import ccall "blst_fr_from_scalar" c_blst_fr_from_scalar :: FrPtr -> ScalarPtr -> IO ()
foreign import ccall "blst_scalar_from_be_bytes"
  c_blst_scalar_from_be_bytes :: ScalarPtr -> Ptr CChar -> CSize -> IO Bool
foreign import ccall "blst_scalar_from_bendian"
  c_blst_scalar_from_bendian :: ScalarPtr -> Ptr CChar -> IO ()

---- Raw Point1 functions

foreign import ccall "size_blst_p1" c_size_blst_p1 :: CSize
foreign import ccall "blst_p1_on_curve" c_blst_p1_on_curve :: Point1Ptr -> IO Bool

foreign import ccall "blst_p1_add_or_double"
  c_blst_p1_add_or_double :: Point1Ptr -> Point1Ptr -> Point1Ptr -> IO ()
foreign import ccall "blst_p1_mult"
  c_blst_p1_mult :: Point1Ptr -> Point1Ptr -> ScalarPtr -> CSize -> IO ()
foreign import ccall "blst_p1_cneg" c_blst_p1_cneg :: Point1Ptr -> Bool -> IO ()

foreign import ccall "blst_hash_to_g1"
  c_blst_hash_to_g1 ::
    Point1Ptr -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> IO ()
foreign import ccall "blst_p1_compress" c_blst_p1_compress :: Ptr CChar -> Point1Ptr -> IO ()
foreign import ccall "blst_p1_serialize" c_blst_p1_serialize :: Ptr CChar -> Point1Ptr -> IO ()
foreign import ccall "blst_p1_uncompress" c_blst_p1_uncompress :: Affine1Ptr -> Ptr CChar -> IO CInt
foreign import ccall "blst_p1_deserialize"
  c_blst_p1_deserialize :: Affine1Ptr -> Ptr CChar -> IO CInt

foreign import ccall "blst_p1_in_g1" c_blst_p1_in_g1 :: Point1Ptr -> IO Bool

foreign import ccall "blst_p1_generator" c_blst_p1_generator :: Point1Ptr

foreign import ccall "blst_p1_is_equal" c_blst_p1_is_equal :: Point1Ptr -> Point1Ptr -> IO Bool
foreign import ccall "blst_p1_is_inf" c_blst_p1_is_inf :: Point1Ptr -> IO Bool

foreign import ccall "blst_p1s_mult_pippenger_scratch_sizeof"
  c_blst_p1s_mult_pippenger_scratch_sizeof :: CSize -> CSize
foreign import ccall "blst_p1s_to_affine"
  c_blst_p1s_to_affine :: Affine1BlockPtr -> Point1ArrayPtr -> CSize -> IO ()
foreign import ccall "blst_p1s_mult_pippenger"
  c_blst_p1s_mult_pippenger ::
    Point1Ptr -> Affine1ArrayPtr -> CSize -> ScalarArrayPtr -> CSize -> ScratchPtr -> IO ()

---- Raw Point2 functions

foreign import ccall "size_blst_p2" c_size_blst_p2 :: CSize
foreign import ccall "blst_p2_on_curve" c_blst_p2_on_curve :: Point2Ptr -> IO Bool

foreign import ccall "blst_p2_add_or_double"
  c_blst_p2_add_or_double :: Point2Ptr -> Point2Ptr -> Point2Ptr -> IO ()
foreign import ccall "blst_p2_mult"
  c_blst_p2_mult :: Point2Ptr -> Point2Ptr -> ScalarPtr -> CSize -> IO ()
foreign import ccall "blst_p2_cneg" c_blst_p2_cneg :: Point2Ptr -> Bool -> IO ()

foreign import ccall "blst_hash_to_g2"
  c_blst_hash_to_g2 ::
    Point2Ptr -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> IO ()
foreign import ccall "blst_p2_compress" c_blst_p2_compress :: Ptr CChar -> Point2Ptr -> IO ()
foreign import ccall "blst_p2_serialize" c_blst_p2_serialize :: Ptr CChar -> Point2Ptr -> IO ()
foreign import ccall "blst_p2_uncompress" c_blst_p2_uncompress :: Affine2Ptr -> Ptr CChar -> IO CInt
foreign import ccall "blst_p2_deserialize"
  c_blst_p2_deserialize :: Affine2Ptr -> Ptr CChar -> IO CInt

foreign import ccall "blst_p2_in_g2" c_blst_p2_in_g2 :: Point2Ptr -> IO Bool

foreign import ccall "blst_p2_generator" c_blst_p2_generator :: Point2Ptr

foreign import ccall "blst_p2_is_equal" c_blst_p2_is_equal :: Point2Ptr -> Point2Ptr -> IO Bool
foreign import ccall "blst_p2_is_inf" c_blst_p2_is_inf :: Point2Ptr -> IO Bool

foreign import ccall "blst_p2s_mult_pippenger_scratch_sizeof"
  c_blst_p2s_mult_pippenger_scratch_sizeof :: CSize -> CSize
foreign import ccall "blst_p2s_to_affine"
  c_blst_p2s_to_affine :: Affine2BlockPtr -> Point2ArrayPtr -> CSize -> IO ()
foreign import ccall "blst_p2s_mult_pippenger"
  c_blst_p2s_mult_pippenger ::
    Point2Ptr -> Affine2ArrayPtr -> CSize -> ScalarArrayPtr -> CSize -> ScratchPtr -> IO ()

---- Affine operations

foreign import ccall "size_blst_affine1" c_size_blst_affine1 :: CSize
foreign import ccall "size_blst_affine2" c_size_blst_affine2 :: CSize

foreign import ccall "blst_p1_to_affine"
  c_blst_p1_to_affine :: AffinePtr Curve1 -> PointPtr Curve1 -> IO ()
foreign import ccall "blst_p2_to_affine"
  c_blst_p2_to_affine :: AffinePtr Curve2 -> PointPtr Curve2 -> IO ()
foreign import ccall "blst_p1_from_affine"
  c_blst_p1_from_affine :: PointPtr Curve1 -> AffinePtr Curve1 -> IO ()
foreign import ccall "blst_p2_from_affine"
  c_blst_p2_from_affine :: PointPtr Curve2 -> AffinePtr Curve2 -> IO ()

foreign import ccall "blst_p1_affine_in_g1" c_blst_p1_affine_in_g1 :: AffinePtr Curve1 -> IO Bool
foreign import ccall "blst_p2_affine_in_g2" c_blst_p2_affine_in_g2 :: AffinePtr Curve2 -> IO Bool

---- PT operations

foreign import ccall "size_blst_fp12" c_size_blst_fp12 :: CSize
foreign import ccall "blst_fp12_mul" c_blst_fp12_mul :: PTPtr -> PTPtr -> PTPtr -> IO ()
foreign import ccall "blst_fp12_is_equal" c_blst_fp12_is_equal :: PTPtr -> PTPtr -> IO Bool
foreign import ccall "blst_fp12_finalverify" c_blst_fp12_finalverify :: PTPtr -> PTPtr -> IO Bool

---- Pairing

foreign import ccall "blst_miller_loop"
  c_blst_miller_loop :: PTPtr -> Affine2Ptr -> Affine1Ptr -> IO ()

---- BLS signatures Secret-key operations

foreign import ccall "blst_keygen"
  c_blst_keygen :: ScalarPtr -> Ptr CChar -> CSize -> Ptr CChar -> CSize -> IO ()

foreign import ccall "blst_sk_to_pk_in_g1"
  c_blst_sk_to_pk_in_g1 :: Point1Ptr -> ScalarPtr -> IO ()

foreign import ccall "blst_sign_pk_in_g1"
  c_blst_sign_pk_in_g1 :: Point2Ptr -> Point2Ptr -> ScalarPtr -> IO ()

foreign import ccall "blst_sk_to_pk_in_g2"
  c_blst_sk_to_pk_in_g2 :: Point2Ptr -> ScalarPtr -> IO ()

foreign import ccall "blst_sign_pk_in_g2"
  c_blst_sign_pk_in_g2 :: Point1Ptr -> Point1Ptr -> ScalarPtr -> IO ()

---- Raw BLST error constants

foreign import ccall "blst_success" c_blst_success :: CInt
foreign import ccall "blst_error_bad_encoding" c_blst_error_bad_encoding :: CInt
foreign import ccall "blst_error_point_not_on_curve" c_blst_error_point_not_on_curve :: CInt
foreign import ccall "blst_error_point_not_in_group" c_blst_error_point_not_in_group :: CInt
foreign import ccall "blst_error_aggr_type_mismatch" c_blst_error_aggr_type_mismatch :: CInt
foreign import ccall "blst_error_verify_fail" c_blst_error_verify_fail :: CInt
foreign import ccall "blst_error_pk_is_infinity" c_blst_error_pk_is_infinity :: CInt
foreign import ccall "blst_error_bad_scalar" c_blst_error_bad_scalar :: CInt

---- Utility functions

foreign import ccall "memcmp" c_memcmp :: Ptr a -> Ptr a -> CSize -> IO CSize
foreign import ccall "blst_bendian_from_scalar"
  c_blst_bendian_from_scalar :: Ptr CChar -> ScalarPtr -> IO ()

data BLSTError
  = BLST_SUCCESS
  | BLST_BAD_ENCODING
  | BLST_POINT_NOT_ON_CURVE
  | BLST_POINT_NOT_IN_GROUP
  | BLST_AGGR_TYPE_MISMATCH
  | BLST_VERIFY_FAIL
  | BLST_PK_IS_INFINITY
  | BLST_BAD_SCALAR
  | BLST_UNKNOWN_ERROR
  deriving (Show, Eq, Ord, Enum, Bounded)

mkBLSTError :: CInt -> BLSTError
mkBLSTError e
  | e == c_blst_success =
      BLST_SUCCESS
  | e == c_blst_error_bad_encoding =
      BLST_BAD_ENCODING
  | e == c_blst_error_point_not_on_curve =
      BLST_POINT_NOT_ON_CURVE
  | e == c_blst_error_point_not_in_group =
      BLST_POINT_NOT_IN_GROUP
  | e == c_blst_error_aggr_type_mismatch =
      BLST_AGGR_TYPE_MISMATCH
  | e == c_blst_error_verify_fail =
      BLST_VERIFY_FAIL
  | e == c_blst_error_pk_is_infinity =
      BLST_PK_IS_INFINITY
  | e == c_blst_error_bad_scalar =
      BLST_BAD_SCALAR
  | otherwise =
      BLST_UNKNOWN_ERROR

---- Curve point operations

instance BLS curve => Eq (Point curve) where
  a == b = unsafePerformIO $ do
    withPoint a $ \aptr ->
      withPoint b $ \bptr ->
        c_blst_p_is_equal aptr bptr

instance Eq Scalar where
  a == b = scalarToBS a == scalarToBS b

instance Eq Fr where
  a == b =
    unsafePerformIO $
      (==) <$> scalarFromFr a <*> scalarFromFr b

-- | Check whether a point is in the group corresponding to its elliptic curve
blsInGroup :: BLS curve => Point curve -> Bool
blsInGroup p = unsafePerformIO $ withPoint p c_blst_in_g

-- | Curve point addition.
blsAddOrDouble :: BLS curve => Point curve -> Point curve -> Point curve
blsAddOrDouble in1 in2 = unsafePerformIO $ do
  withNewPoint' $ \outp -> do
    withPoint in1 $ \in1p -> do
      withPoint in2 $ \in2p -> do
        c_blst_add_or_double outp in1p in2p

-- | Scalar multiplication of a curve point. The scalar will be brought into
-- the range of modular arithmetic by means of a modulo operation over the
-- 'scalarPeriod'. Negative number will also be brought to the range
-- [0, 'scalarPeriod' - 1] via modular reduction.
blsMult :: BLS curve => Point curve -> Integer -> Point curve
blsMult in1 inS = unsafePerformIO $ do
  withNewPoint' $ \outp -> do
    withPoint in1 $ \in1p -> do
      withIntScalar inS $ \inSp -> do
        -- Multiply by 8, because blst_mult takes number of *bits*, but
        -- sizeScalar is in *bytes*
        c_blst_mult outp in1p inSp (fromIntegral sizeScalar * 8)

-- | Conditional curve point negation.
-- @blsCneg x cond = if cond then neg x else x@
blsCneg :: BLS curve => Point curve -> Bool -> Point curve
blsCneg in1 cond = unsafePerformIO $ do
  out1 <- clonePoint in1
  withPoint out1 $ \out1p ->
    c_blst_cneg out1p cond
  return out1

-- | Unconditional curve point negation
blsNeg :: BLS curve => Point curve -> Point curve
blsNeg p = blsCneg p True

blsUncompress :: forall curve. BLS curve => ByteString -> Either BLSTError (Point curve)
blsUncompress bs = unsafePerformIO $ do
  BSU.unsafeUseAsCStringLen bs $ \(bytes, numBytes) ->
    if numBytes == compressedSizePoint (Proxy @curve)
      then do
        (err, affine) <- withNewAffine $ \ap -> c_blst_uncompress ap bytes
        let p = fromAffine affine
        if err /= 0
          then
            return $ Left $ mkBLSTError err
          else
            if blsInGroup p
              then
                return $ Right p
              else
                return $ Left BLST_POINT_NOT_IN_GROUP
      else do
        return $ Left BLST_BAD_ENCODING

blsDeserialize :: forall curve. BLS curve => ByteString -> Either BLSTError (Point curve)
blsDeserialize bs = unsafePerformIO $ do
  BSU.unsafeUseAsCStringLen bs $ \(bytes, numBytes) ->
    if numBytes == serializedSizePoint (Proxy @curve)
      then do
        (err, affine) <- withNewAffine $ \ap -> c_blst_deserialize ap bytes
        let p = fromAffine affine
        if err /= 0
          then
            return $ Left $ mkBLSTError err
          else
            if blsInGroup p
              then
                return $ Right p
              else
                return $ Left BLST_POINT_NOT_IN_GROUP
      else do
        return $ Left BLST_BAD_ENCODING

blsCompress :: forall curve. BLS curve => Point curve -> ByteString
blsCompress p = BSI.fromForeignPtr (castForeignPtr ptr) 0 (compressedSizePoint (Proxy @curve))
  where
    ptr = unsafePerformIO $ do
      cstr <- mallocForeignPtrBytes (compressedSizePoint (Proxy @curve))
      withForeignPtr cstr $ \cstrp -> do
        withPoint p $ \pp -> do
          c_blst_compress cstrp pp
      return cstr

blsSerialize :: forall curve. BLS curve => Point curve -> ByteString
blsSerialize p = BSI.fromForeignPtr (castForeignPtr ptr) 0 (serializedSizePoint (Proxy @curve))
  where
    ptr = unsafePerformIO $ do
      cstr <- mallocForeignPtrBytes (serializedSizePoint (Proxy @curve))
      withForeignPtr cstr $ \cstrp -> do
        withPoint p $ \pp -> do
          c_blst_serialize cstrp pp
      return cstr

-- | @blsHash msg mDST mAug@ generates the elliptic curve blsHash for the given
-- message @msg@; @mDST@ and @mAug@ are the optional @aug@ and @dst@
-- arguments.
blsHash :: BLS curve => ByteString -> Maybe ByteString -> Maybe ByteString -> Point curve
blsHash msg mDST mAug = unsafePerformIO $
  BSU.unsafeUseAsCStringLen msg $ \(msgPtr, msgLen) ->
    withMaybeCStringLen mDST $ \(dstPtr, dstLen) ->
      withMaybeCStringLen mAug $ \(augPtr, augLen) ->
        withNewPoint' $ \pPtr ->
          c_blst_hash
            pPtr
            msgPtr
            (fromIntegral msgLen)
            dstPtr
            (fromIntegral dstLen)
            augPtr
            (fromIntegral augLen)

toAffine :: BLS curve => Point curve -> Affine curve
toAffine p = unsafePerformIO $
  withPoint p $ \pp ->
    withNewAffine' $ \affinePtr ->
      c_blst_to_affine affinePtr pp

fromAffine :: BLS curve => Affine curve -> Point curve
fromAffine affine = unsafePerformIO $
  withAffine affine $ \affinePtr ->
    withNewPoint' $ \pp ->
      c_blst_from_affine pp affinePtr

-- | Infinity check on curve points.
blsIsInf :: BLS curve => Point curve -> Bool
blsIsInf p = unsafePerformIO $ withPoint p c_blst_p_is_inf

affineInG :: BLS curve => Affine curve -> Bool
affineInG affine =
  unsafePerformIO $
    withAffine affine c_blst_affine_in_g

blsGenerator :: BLS curve => Point curve
blsGenerator = unsafePointFromPointPtr c_blst_generator

blsZero :: forall curve. BLS curve => Point curve
blsZero =
  -- Compressed serialised G1 points are bytestrings of length 48: see CIP-0381.
  let b = BS.pack (0xc0 : replicate (compressedSizePoint (Proxy @curve) - 1) 0x00)
   in case blsUncompress b of
        Left err ->
          error $ "Unexpected failure deserialising point at infinity on BLS12_381.G1: " ++ show err
        Right infinity ->
          infinity -- The zero point on this curve is chosen to be the point at infinity.
          ---- Scalar / Fr operations

scalarFromFr :: Fr -> IO Scalar
scalarFromFr fr =
  withNewScalar' $ \scalarPtr ->
    withFr fr $ \frPtr ->
      c_blst_scalar_from_fr scalarPtr frPtr

frFromScalar :: Scalar -> IO Fr
frFromScalar scalar =
  withNewFr' $ \frPtr ->
    withScalar scalar $ \scalarPtr ->
      c_blst_fr_from_scalar frPtr scalarPtr

frFromCanonicalScalar :: Scalar -> IO (Maybe Fr)
frFromCanonicalScalar scalar
  | scalarCanonical scalar =
      Just <$> frFromScalar scalar
  | otherwise =
      return Nothing

scalarFromBS :: ByteString -> Either BLSTError Scalar
scalarFromBS bs = unsafePerformIO $ do
  BSU.unsafeUseAsCStringLen bs $ \(cstr, l) ->
    if l == sizeScalar
      then do
        (success, scalar) <- withNewScalar $ \scalarPtr ->
          c_blst_scalar_from_be_bytes scalarPtr cstr (fromIntegral l)
        if success
          then
            return $ Right scalar
          else
            return $ Left BLST_BAD_SCALAR
      else
        return $ Left BLST_BAD_SCALAR

scalarToBS :: Scalar -> ByteString
scalarToBS scalar = BSI.fromForeignPtr (castForeignPtr ptr) 0 sizeScalar
  where
    ptr = unsafePerformIO $ do
      cstr <- mallocForeignPtrBytes sizeScalar
      withForeignPtr cstr $ \cstrp -> do
        withScalar scalar $ \scalarPtr -> do
          c_blst_bendian_from_scalar cstrp scalarPtr
      return cstr

scalarCanonical :: Scalar -> Bool
scalarCanonical scalar =
  unsafePerformIO $
    withScalar scalar c_blst_scalar_fr_check

---- Serialization helpers for SecretKey / PublicKey / Signature
--
-- These helpers provide canonical byte encodings that we will plug into the
-- DSIGN rawSerialise*/rawDeserialise* later. They deliberately:
--   * use compressed encodings for curve points (48 bytes for G1, 96 for G2),
--   * enforce exact input lengths via the underlying bls(De)serialize calls,
--   * reject the point at infinity explicitly (mapped to BLST_PK_IS_INFINITY).
-- All functions are pure and total via Either BLSTError.

-- SecretKey (wraps Scalar) ---------------------------------------------------

-- | Canonical big-endian 32-byte encoding of the secret scalar.
secretKeyToBS :: SecretKey -> ByteString
secretKeyToBS (SecretKey s) = scalarToBS s

-- | Parse a secret key from a 32-byte big-endian scalar.
-- Returns BLST_BAD_SCALAR on bad length or non-canonical input.
secretKeyFromBS :: ByteString -> Either BLSTError SecretKey
secretKeyFromBS bs = SecretKey <$> scalarFromBS bs

-- | Helper to reject the point at infinity uniformly across decoders.
-- It maps successful decodes to an explicit infinity check and
-- returns BLST_PK_IS_INFINITY when the decoded point is the identity.
-- Note: BLST exposes a single 'pk_is_infinity' code; we reuse it for
-- signatures too. Downstream treats it generically as "point is infinity".
rejectInfinity :: BLS curve => Either BLSTError (Point curve) -> Either BLSTError (Point curve)
rejectInfinity = (>>= \p -> if blsIsInf p then Left BLST_PK_IS_INFINITY else Right p)

-- PublicKey ------------------------------------------------------------------

-- | Compressed (canonical) encoding of a public key point.
-- For Curve1 (minimal-pk-size): 48 bytes (G1). For Curve2: 96 bytes (G2).
publicKeyToCompressedBS :: BLS curve => PublicKey curve -> ByteString
publicKeyToCompressedBS (PublicKey pk) = blsCompress pk

-- | Uncompressed (serialized) encoding of a public key point.
publicKeyToUncompressedBS :: BLS curve => PublicKey curve -> ByteString
publicKeyToUncompressedBS (PublicKey pk) = blsSerialize pk

-- | Decode a public key from its compressed encoding, rejecting infinity.
publicKeyFromCompressedBS ::
  forall curve. BLS curve => ByteString -> Either BLSTError (PublicKey curve)
publicKeyFromCompressedBS bs =
  PublicKey <$> rejectInfinity @curve (blsUncompress @curve bs)

-- | Decode a public key from its uncompressed encoding, rejecting infinity.
publicKeyFromUncompressedBS ::
  forall curve. BLS curve => ByteString -> Either BLSTError (PublicKey curve)
publicKeyFromUncompressedBS bs =
  PublicKey <$> rejectInfinity @curve (blsDeserialize @curve bs)

-- Signature ------------------------------------------------------------------

-- | Compressed (canonical) encoding of a signature point.
-- Note: signatures live on the Dual curve of the public key.
signatureToCompressedBS :: forall curve. BLS (Dual curve) => Signature curve -> ByteString
signatureToCompressedBS (Signature sig) = blsCompress @(Dual curve) sig

-- | Uncompressed (serialized) encoding of a signature point.
signatureToUncompressedBS :: forall curve. BLS (Dual curve) => Signature curve -> ByteString
signatureToUncompressedBS (Signature sig) = blsSerialize @(Dual curve) sig

-- Note: BLST does not expose a signature-specific infinity error; we reuse
-- BLST_PK_IS_INFINITY for signatures as well. This is intentional and treated
-- downstream as a generic "point is infinity" condition.

-- | Decode a signature from its compressed encoding, rejecting infinity.
signatureFromCompressedBS ::
  forall curve. BLS (Dual curve) => ByteString -> Either BLSTError (Signature curve)
signatureFromCompressedBS bs =
  Signature <$> rejectInfinity @(Dual curve) (blsUncompress @(Dual curve) bs)

-- | Decode a signature from its uncompressed encoding, rejecting infinity.
signatureFromUncompressedBS ::
  forall curve. BLS (Dual curve) => ByteString -> Either BLSTError (Signature curve)
signatureFromUncompressedBS bs =
  Signature <$> rejectInfinity @(Dual curve) (blsDeserialize @(Dual curve) bs)

---- MSM operations

-- NOTE: 'blsMSM' operates purely on PSB-backed points/scalars.  The helper
-- continuations build temporary pointer tables and workspaces whose sizes are
-- derived from 'sizePoint', 'sizeAffine', 'sizeScalar', and
-- 'c_blst_scratch_sizeof', so no hard-coded lengths leak into the FFI.

-- | Multi-scalar multiplication using the Pippenger algorithm.
-- The scalars will be brought into the range of modular arithmetic
-- by means of a modulo operation over the 'scalarPeriod'.
-- Negative numbers will also be brought to the range
-- [0, 'scalarPeriod' - 1] via modular reduction.
blsMSM :: forall curve. BLS curve => [(Integer, Point curve)] -> Point curve
blsMSM ssAndps = unsafePerformIO $ do
  zeroScalar <- scalarFromInteger 0
  filteredPoints <-
    foldrM
      ( \(s, pt) acc -> do
          -- Here we filter out pairs that will not contribute to the result.
          -- This is also for safety, as the c_blst_to_affines C call
          -- will fail if the input contains the point at infinity.
          -- see https://github.com/supranational/blst/blob/165ec77634495175aefd045a48d3469af6950ea4/src/multi_scalar.c#L11C32-L11C37
          if blsIsInf pt
            then pure acc
            else do
              scalar <- scalarFromInteger s
              -- We also filter out the zero scalar, as for any point pt
              -- we have:
              --
              --    pt ^ 0 = id
              --
              -- Which yields no contribution to summation, and
              -- thus we can skip the point and scalar pair. This filter
              -- saves us an extra input to the more expensive exponential
              -- operation.
              if scalar == zeroScalar
                then return acc
                else return ((scalar, pt) : acc)
      )
      []
      ssAndps
  case filteredPoints of
    [] -> return blsZero
    -- If there is only one point, we revert to blsMult function
    -- The blst_mult_pippenger C call will also not work for
    -- this case on windows builds.
    [(scalar, pt)] -> do
      i <- scalarToInteger scalar
      return (blsMult pt i)
    _ -> do
      let (scalars, points) = unzip filteredPoints

      withNewPoint' @curve $ \resultPtr -> do
        withPointArray points $ \numPoints pointArrayPtr -> do
          withScalarArray scalars $ \_ scalarArrayPtr -> do
            let numPoints' :: CSize
                numPoints' = fromIntegral numPoints
                -- The blst scratch workspace is sized directly from the
                -- curve-specific helper, so we never rely on hard-coded sizes.
                scratchSize :: Int
                scratchSize =
                  fromIntegral @CSize @Int $
                    c_blst_scratch_sizeof (Proxy @curve) numPoints'
            allocaBytes (numPoints * sizeAffine (Proxy @curve)) $ \affinesBlockPtr -> do
              c_blst_to_affines (AffineBlockPtr affinesBlockPtr) pointArrayPtr numPoints'
              withAffineBlockArrayPtr affinesBlockPtr numPoints $ \affineArrayPtr -> do
                allocaBytes scratchSize $ \scratchPtr -> do
                  c_blst_mult_pippenger
                    resultPtr
                    affineArrayPtr
                    numPoints'
                    scalarArrayPtr
                    (255 :: CSize)
                    (ScratchPtr scratchPtr)

---- PT operations

ptMult :: PT -> PT -> PT
ptMult a b = unsafePerformIO $
  withPT a $ \ap ->
    withPT b $ \bp ->
      withNewPT' $ \cp ->
        c_blst_fp12_mul cp ap bp

ptEq :: PT -> PT -> Bool
ptEq a b = unsafePerformIO $
  withPT a $ \ap ->
    withPT b $ \bp ->
      c_blst_fp12_is_equal ap bp

ptFinalVerify :: PT -> PT -> Bool
ptFinalVerify a b = unsafePerformIO $
  withPT a $ \ap ->
    withPT b $ \bp ->
      c_blst_fp12_finalverify ap bp

instance Eq PT where
  (==) = ptEq

---- Pairings

millerLoop :: Point1 -> Point2 -> PT
millerLoop p1 p2 =
  unsafePerformIO $
    withAffine (toAffine p1) $ \ap1 ->
      withAffine (toAffine p2) $ \ap2 ->
        withNewPT' $ \ppt ->
          c_blst_miller_loop ppt ap2 ap1

-- A single side of e(·,·): the point on `curve` and the point on its `Dual`.
type PairingSide curve = (Point curve, Point (Dual curve))

class (BLS curve, BLS (Dual curve)) => FinalVerifyOrder curve where
  millerSide :: PairingSide curve -> PT
  finalVerifyPairs :: PairingSide curve -> PairingSide curve -> Bool
  finalVerifyPairs lhs rhs = ptFinalVerify (millerSide lhs) (millerSide rhs)

instance FinalVerifyOrder Curve1 where
  -- Curve1: miller loop expects (g1, g2)
  millerSide (g1, g2) = millerLoop g1 g2

instance FinalVerifyOrder Curve2 where
  -- Curve2: miller loop expects (g1, g2) but our Pair is (g2, g1)
  millerSide (g2, g1) = millerLoop g1 g2

---- BLS signatures operations

-- Following the rust bindings as per this reference:
-- https://github.com/supranational/blst/blob/f48500c1fdbefa7c0bf9800bccd65d28236799c1/bindings/rust/src/lib.rs#L559

-- | Generate a secret key from the given input keying material (ikm)
-- and optional extra info. The ikm must be at least 32 bytes long.
-- See https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-keygen
-- on this length requirement. Note that the blst library itself does not
-- enforce this length requirement.
blsKeyGen :: ByteString -> Maybe ByteString -> Either BLSTError SecretKey
blsKeyGen ikm info = unsafePerformIO $ do
  withMaybeCStringLen info $ \(infoPtr, infoLen) ->
    BSU.unsafeUseAsCStringLen ikm $ \(ikmPtr, ikmLen) ->
      if ikmLen < 32
        then return $ Left BLST_BAD_ENCODING
        else do
          sk <- withNewScalar' $ \skPtr ->
            c_blst_keygen skPtr ikmPtr (fromIntegral ikmLen) infoPtr (fromIntegral infoLen)
          return $ Right (SecretKey sk)

-- | Derive the public key from a secret key.
-- Note that given the choice of Curve1 or Curve2, the public key
-- will be a point on the corresponding curve.
blsSkToPk :: BLS curve => SecretKey -> PublicKey curve
blsSkToPk (SecretKey sk) = PublicKey . unsafePerformIO $
  withNewPoint' $ \pkPtr ->
    withScalar sk $ \skPtr ->
      c_blst_sk_to_pk pkPtr skPtr

-- | Sign a message with the given secret key.
-- Note that given the choice of Curve1 or Curve2, the signature
-- will be a point on the dual of the corresponding curve.
blsSign ::
  forall curve.
  (BLS curve, BLS (Dual curve)) =>
  Proxy curve ->
  SecretKey -> -- secret key
  ByteString -> -- message
  Maybe ByteString -> -- domain separation tag (for protocol separation)
  Maybe ByteString -> -- augmentation (per message augmentation)
  Signature curve -- signature
blsSign _ (SecretKey sk) msg dst aug = Signature . unsafePerformIO $
  BSU.unsafeUseAsCStringLen msg $ \(msgPtr, msgLen) ->
    withMaybeCStringLen dst $ \(dstPtr, dstLen) ->
      withMaybeCStringLen aug $ \(augPtr, augLen) ->
        withNewPoint' @(Dual curve) $ \sigPtr -> do
          withNewPoint_ @(Dual curve) $ \hPtr -> do
            c_blst_hash @(Dual curve)
              hPtr
              msgPtr
              (fromIntegral msgLen)
              dstPtr
              (fromIntegral dstLen)
              augPtr
              (fromIntegral augLen)
            withScalar sk $ \skPtr ->
              c_blst_sign (Proxy @curve) sigPtr hPtr skPtr

-- | Verify a BLS signature via the naive way.
blsSignatureVerify ::
  forall curve.
  FinalVerifyOrder curve =>
  PublicKey curve -> -- pk on curve
  ByteString -> -- msg
  Signature curve -> -- sig on dual curve
  Maybe ByteString -> -- domain separation tag (for protocol separation)
  Maybe ByteString -> -- augmentation (per message augmentation)
  Bool
blsSignatureVerify (PublicKey pk) msg (Signature sig) dst aug =
  -- here we check that e(g1, sig) == e(pk, H(msg)) or equivalently
  -- e(sig, g2) == e(H(msg),pk) depending on the curve choice for pk/sig.
  finalVerifyPairs @curve (blsGenerator, sig) (pk, blsHash msg dst aug)

blsProofOfPossessionProve ::
  forall curve.
  (BLS curve, BLS (Dual curve)) =>
  SecretKey -> -- secret key
  Maybe ByteString -> -- domain separation tag (for protocol separation)
  Maybe ByteString -> -- augmentation (per message augmentation)
  ProofOfPossession curve -- proof of possession
blsProofOfPossessionProve (SecretKey sk) dst aug = ProofOfPossession mu1 mu2
  where
    skAsInteger = unsafePerformIO $ scalarToInteger sk
    PublicKey pk = blsSkToPk @curve (SecretKey sk)
    mu1 :: Point (Dual curve)
    -- \| μ₁ signs the literal bytes @"PoP" <> compressed(pk)@ with the caller
    -- supplied domain separation tag and augmentation (defaulting to the pin).
    mu1 = blsMult (blsHash ("PoP" <> blsCompress pk) dst aug) skAsInteger
    mu2 :: Point (Dual curve)
    mu2 = blsMult blsGenerator skAsInteger

blsProofOfPossessionVerify ::
  forall curve.
  FinalVerifyOrder curve =>
  PublicKey curve -> -- pk on curve
  ProofOfPossession curve -> -- proof of possession
  Maybe ByteString -> -- domain separation tag (for protocol separation)
  Maybe ByteString -> -- augmentation (per message augmentation)
  Bool
blsProofOfPossessionVerify (PublicKey pk) (ProofOfPossession mu1 mu2) dst aug =
  finalVerifyPairs @curve (blsGenerator, mu1) (pk, blsHash ("PoP" <> blsCompress pk) dst aug)
    && finalVerifyPairs @curve (pk, blsGenerator) (blsGenerator, mu2)

---- Aggregation helpers

-- | Aggregate a non-empty list of public keys by group addition.
-- Returns 'Left BLST_BAD_ENCODING' on empty input.
blsAggregatePublicKeys ::
  forall curve. BLS curve => [PublicKey curve] -> Either BLSTError (PublicKey curve)
blsAggregatePublicKeys [] = Left BLST_BAD_ENCODING
blsAggregatePublicKeys (PublicKey pk0 : rest) =
  Right . PublicKey $
    -- Aggregation is defined as repeated group addition; folding
    -- 'blsAddOrDouble' implements the BLS spec literally.
    List.foldl'
      (\acc (PublicKey pk) -> blsAddOrDouble acc pk)
      pk0
      rest

-- | Aggregate a non-empty list of signatures by group addition. Intended for
-- scenarios where every signer used the same message/ DST / AUG combination.
-- Returns 'Left BLST_BAD_ENCODING' on empty input.
blsAggregateSignaturesSameMsg ::
  forall curve.
  BLS (Dual curve) =>
  [Signature curve] ->
  Either BLSTError (Signature curve)
blsAggregateSignaturesSameMsg = aggregateSignatures

-- | Aggregate signatures when each signer may have used a distinct message.
-- Semantics match 'blsAggregateSignaturesSameMsg'; the dedicated export makes
-- it clear that the caller is in the multi-message case.
blsAggregateSignaturesDistinctMsg ::
  forall curve.
  BLS (Dual curve) =>
  [Signature curve] ->
  Either BLSTError (Signature curve)
blsAggregateSignaturesDistinctMsg = aggregateSignatures

-- | Verify an aggregated signature over a shared message. This is a thin
-- wrapper around 'blsSignatureVerify' that gives the aggregate path a stable
-- entry point.
blsVerifyAggregateSameMsg ::
  forall curve.
  FinalVerifyOrder curve =>
  PublicKey curve ->
  ByteString ->
  Signature curve ->
  Maybe ByteString ->
  Maybe ByteString ->
  Bool
blsVerifyAggregateSameMsg =
  blsSignatureVerify

-- | Verify aggregated signatures where each signer may have signed a distinct
-- message. Implements the standard multi-pairing equation.
blsVerifyAggregateDistinctMsg ::
  forall curve.
  FinalVerifyOrder curve =>
  [(PublicKey curve, ByteString)] ->
  Signature curve ->
  Maybe ByteString ->
  Maybe ByteString ->
  Bool
blsVerifyAggregateDistinctMsg [] _ _ _ = False
blsVerifyAggregateDistinctMsg ((pk0, msg0) : rest) sig dst aug =
  let lhs = millerSide (blsGenerator @curve, unSignature sig)
      rhs0 = millerSide (unPublicKey pk0, blsHash msg0 dst aug)
      rhs =
        List.foldl'
          ( \acc (pk', msg') ->
              ptMult acc (millerSide (unPublicKey pk', blsHash msg' dst aug))
          )
          rhs0
          rest
   in ptFinalVerify lhs rhs

aggregateSignatures ::
  forall curve.
  BLS (Dual curve) =>
  [Signature curve] ->
  Either BLSTError (Signature curve)
aggregateSignatures [] = Left BLST_BAD_ENCODING
aggregateSignatures (Signature sig0 : rest) =
  Right . Signature $
    -- Same/different-message signature aggregation is repeated group addition
    -- over the dual-curve points, as prescribed by the BLS definition.
    List.foldl'
      (\acc (Signature sig) -> blsAddOrDouble acc sig)
      sig0
      rest

withMaybeCStringLen :: Maybe ByteString -> (CStringLen -> IO a) -> IO a
withMaybeCStringLen Nothing go = go (nullPtr, 0)
withMaybeCStringLen (Just bs) go = BSU.unsafeUseAsCStringLen bs go

-- | The period of scalar modulo operations.
scalarPeriod :: Integer
scalarPeriod = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
