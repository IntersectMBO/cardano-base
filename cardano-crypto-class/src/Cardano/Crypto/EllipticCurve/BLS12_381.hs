{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE FlexibleContexts #-}
module Cardano.Crypto.EllipticCurve.BLS12_381
(
  -- * Types
    P
  , P1
  , P2
  , Curve1
  , Curve2
  , Scalar
  , Fr
  , Affine
  , BLSTError (..)

  -- * Class
  , BLS

  -- * P1/G1 operations
  , onCurve
  , add
  , mult
  , cneg
  , neg
  , compress
  , serialize
  , uncompress
  , deserialize
  , hash
  , generator
  , isInf

  , toXYZ
  , toXY

  , toAffine
  , fromAffine
  , affineInG

  -- * Scalar / Fr operations
  , scalarFromFr
  , frFromScalar
  , frFromCanonicalScalar
  , scalarFromBS
  , scalarToBS
  , scalarFromNatural
  , scalarToNatural
  , scalarCanonical

  , frAdd
  , frMult
  , frNeg
  , frInverse
  , frSqr
  , frFromNatural
  , frToNatural

  -- * Pairings
  , pairingCheck
)
where

import Cardano.Crypto.EllipticCurve.BLS12_381.C
import System.IO.Unsafe (unsafePerformIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String
import Foreign.Ptr (nullPtr, castPtr)
import Data.Proxy (Proxy (..))
import Numeric.Natural

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
  deriving (Show, Eq, Ord)

mkBLSTError :: CInt -> BLSTError
mkBLSTError e
  | e == c_blst_success
  = BLST_SUCCESS
  | e == c_blst_error_bad_encoding
  = BLST_BAD_ENCODING
  | e == c_blst_error_point_not_on_curve
  = BLST_POINT_NOT_ON_CURVE
  | e == c_blst_error_point_not_in_group
  = BLST_POINT_NOT_IN_GROUP
  | e == c_blst_error_aggr_type_mismatch
  = BLST_AGGR_TYPE_MISMATCH
  | e == c_blst_error_verify_fail
  = BLST_VERIFY_FAIL
  | e == c_blst_error_pk_is_infinity
  = BLST_PK_IS_INFINITY
  | e == c_blst_error_bad_scalar
  = BLST_BAD_SCALAR
  | otherwise
  = BLST_UNKNOWN_ERROR

class (BLS_Curve a, BLS_P a) => BLS a where

instance BLS Curve1 where

instance BLS Curve2 where

---- Curve point operations

instance BLS curve => Eq (P curve) where
  a == b = unsafePerformIO $ do
    withP a $ \aptr ->
      withP b $ \bptr ->
        c_blst_p_is_equal aptr bptr

instance Eq Scalar where
  a == b = scalarToBS a == scalarToBS b

instance Eq Fr where
  a == b = scalarFromFr a == scalarFromFr b

onCurve :: BLS_Curve curve => P curve -> Bool
onCurve p = unsafePerformIO $ withP p c_blst_on_curve

add :: (BLS_P curve, BLS_Curve curve) => P curve -> P curve -> P curve
add in1 in2 = unsafePerformIO $ do
  withNewP' $ \outp -> do
    withP in1 $ \in1p -> do
      withP in2 $ \in2p -> do
        c_blst_add outp in1p in2p

mult :: (BLS_P curve, BLS_Curve curve) => P curve -> Scalar -> P curve
mult in1 inS = unsafePerformIO $ do
  withNewP' $ \outp -> do
    withP in1 $ \in1p -> do
      withScalar inS $ \inSp -> do
        -- Multiply by 8, because blst_mult takes number of *bits*, but
        -- sizeScalar is in *bytes*
        c_blst_mult outp in1p inSp (sizeScalar * 8)

cneg :: (BLS_P curve, BLS_Curve curve) => P curve -> Bool -> P curve
cneg in1 cond = unsafePerformIO $ do
  out1 <- cloneP in1
  withP out1 $ \out1p ->
    c_blst_cneg out1p cond
  return out1

neg :: (BLS_P curve, BLS_Curve curve) => P curve -> P curve
neg p = cneg p True

uncompress :: forall curve. (BLS_P curve, BLS_Curve curve) => ByteString -> Either BLSTError (P curve)
uncompress bs = unsafePerformIO $ do
  BS.useAsCStringLen bs $ \(bytes, numBytes) -> do
    if numBytes < compressedSizeP (Proxy @curve) then
      return $ Left BLST_BAD_ENCODING
    else do
      (err, affine) <- withNewAffine $ \ap -> c_blst_uncompress ap bytes
      if err /= 0 then
        return $ Left $ mkBLSTError err
      else
        return $ Right (fromAffine affine)

deserialize :: forall curve. (BLS_P curve, BLS_Curve curve) => ByteString -> Either BLSTError (P curve)
deserialize bs = unsafePerformIO $ do
  BS.useAsCStringLen bs $ \(bytes, numBytes) -> do
    if numBytes < serializedSizeP (Proxy @curve) then
      return $ Left BLST_BAD_ENCODING
    else do
      (err, affine) <- withNewAffine $ \ap -> c_blst_deserialize ap bytes
      if err /= 0 then
        return $ Left $ mkBLSTError err
      else
        return $ Right (fromAffine affine)

compress :: forall curve. (BLS_P curve, BLS_Curve curve) => P curve -> ByteString
compress p = unsafePerformIO $ do
  withP p $ \pp -> do
    cstr <- mallocForeignPtrBytes (compressedSizeP (Proxy @curve))
    withForeignPtr cstr $ \cstrp -> do
      c_blst_compress cstrp pp
      BS.packCStringLen (cstrp, compressedSizeP (Proxy @curve))

serialize :: forall curve. (BLS_P curve, BLS_Curve curve) => P curve -> ByteString
serialize p = unsafePerformIO $ do
  withP p $ \pp -> do
    cstr <- mallocForeignPtrBytes (serializedSizeP (Proxy @curve))
    withForeignPtr cstr $ \cstrp -> do
      c_blst_serialize cstrp pp
      BS.packCStringLen (cstrp, serializedSizeP (Proxy @curve))

hash :: (BLS_P curve, BLS_Curve curve) => ByteString -> Maybe ByteString -> Maybe ByteString -> P curve
hash msg mDST mAug = unsafePerformIO $
  BS.useAsCStringLen msg $ \(msgPtr, msgLen) ->
    withMaybeCStringLen mDST $ \(dstPtr, dstLen) ->
      withMaybeCStringLen mAug $ \(augPtr, augLen) ->
        withNewP' $ \pPtr ->
          c_blst_hash pPtr msgPtr (fromIntegral msgLen) dstPtr (fromIntegral dstLen) augPtr (fromIntegral augLen)

toAffine :: (BLS_P curve, BLS_Curve curve) => P curve -> Affine curve
toAffine p = unsafePerformIO $
  withP p $ \pp ->
    withNewAffine' $ \affinePtr ->
      c_blst_to_affine affinePtr pp

fromAffine :: (BLS_P curve, BLS_Curve curve) => Affine curve -> P curve
fromAffine affine = unsafePerformIO $
  withAffine affine $ \affinePtr ->
    withNewP' $ \pp ->
      c_blst_from_affine pp affinePtr

isInf :: (BLS_P curve, BLS_Curve curve) => P curve -> Bool
isInf p = unsafePerformIO $ withP p c_blst_p_is_inf

getX :: (BLS_Curve curve) => P curve -> Natural
getX p = unsafePerformIO $ fpToNat =<< do
  withNewFP' $ \fPtr -> do
    withP p $ \pPtr -> do
      c_blst_x_from_p fPtr pPtr
getY :: (BLS_Curve curve) => P curve -> Natural
getY p = unsafePerformIO $ fpToNat =<< do
  withNewFP' $ \fPtr -> do
    withP p $ \pPtr -> do
      c_blst_y_from_p fPtr pPtr
getZ :: (BLS_Curve curve) => P curve -> Natural
getZ p = unsafePerformIO $ fpToNat =<< do
  withNewFP' $ \fPtr -> do
    withP p $ \pPtr -> do
      c_blst_z_from_p fPtr pPtr

getAX :: (BLS_Curve curve) => Affine curve -> Natural
getAX aff = unsafePerformIO $ fpToNat =<< do
  withNewFP' $ \fPtr -> do
    withAffine aff $ \affPtr -> do
      c_blst_x_from_affine fPtr affPtr
getAY :: (BLS_Curve curve) => Affine curve -> Natural
getAY aff = unsafePerformIO $ fpToNat =<< do
  withNewFP' $ \fPtr -> do
    withAffine aff $ \affPtr -> do
      c_blst_y_from_affine fPtr affPtr

toXYZ :: (BLS_Curve curve) => P curve -> (Natural, Natural, Natural)
toXYZ p = (getX p, getY p, getZ p)

toXY :: (BLS_Curve curve) => Affine curve -> (Natural, Natural)
toXY aff = (getAX aff, getAY aff)

affineInG :: (BLS_Curve curve) => Affine curve -> Bool
affineInG affine = unsafePerformIO $
  withAffine affine c_blst_affine_in_g

generator :: (BLS_Curve curve) => P curve
generator = unsafePFromPPtr c_blst_generator

---- Scalar / Fr operations

scalarFromFr :: Fr -> Scalar
scalarFromFr fr = unsafePerformIO $
  withNewScalar' $ \scalarPtr ->
    withFr fr $ \frPtr ->
      c_blst_scalar_from_fr scalarPtr frPtr

frFromScalar :: Scalar -> Fr
frFromScalar scalar =
  unsafePerformIO $
    withNewFr' $ \frPtr ->
      withScalar scalar $ \scalarPtr ->
        c_blst_fr_from_scalar frPtr scalarPtr

frFromCanonicalScalar :: Scalar -> Maybe Fr
frFromCanonicalScalar scalar
  | scalarCanonical scalar
  = Just $ frFromScalar scalar
  | otherwise
  = Nothing

scalarFromBS :: ByteString -> Either BLSTError Scalar
scalarFromBS bs =
  if success then
    Right scalar
  else
    Left BLST_BAD_SCALAR
  where
    (success, scalar) = unsafePerformIO $
      withNewScalar $ \scalarPtr ->
        BS.useAsCStringLen bs $ \(cstr, l) ->
          c_blst_scalar_from_be_bytes scalarPtr cstr (fromIntegral l)

scalarToBS :: Scalar -> ByteString
scalarToBS scalar = unsafePerformIO $ do
  cstr <- mallocForeignPtrBytes sizeScalar
  withForeignPtr cstr $ \cstrp -> do
    withScalar scalar $ \scalarPtr -> do
      c_blst_bendian_from_scalar cstrp scalarPtr
      BS.packCStringLen (castPtr cstrp, sizeScalar)

frAdd :: Fr -> Fr -> Fr
frAdd a b = unsafePerformIO $
  withNewFr' $ \outPtr ->
    withFr a $ \aPtr ->
      withFr b $ \bPtr ->
        c_blst_fr_add outPtr aPtr bPtr

frMult :: Fr -> Fr -> Fr
frMult a b = unsafePerformIO $
  withNewFr' $ \outPtr ->
    withFr a $ \aPtr ->
      withFr b $ \bPtr ->
        c_blst_fr_mul outPtr aPtr bPtr

frNeg :: Fr -> Fr
frNeg a = unsafePerformIO $
  withNewFr' $ \outPtr ->
    withFr a $ \aPtr ->
      c_blst_fr_cneg outPtr aPtr

frInverse :: Fr -> Fr
frInverse a = unsafePerformIO $
  withNewFr' $ \outPtr ->
    withFr a $ \aPtr ->
      c_blst_fr_inverse outPtr aPtr

frSqr :: Fr -> Fr
frSqr a = unsafePerformIO $
  withNewFr' $ \outPtr ->
    withFr a $ \aPtr ->
      c_blst_fr_sqr outPtr aPtr

scalarCanonical :: Scalar -> Bool
scalarCanonical scalar = unsafePerformIO $
  withScalar scalar c_blst_scalar_fr_check

scalarToNatural :: Scalar -> Natural
scalarToNatural = unsafePerformIO . scalarToNat

scalarFromNatural :: Natural -> Scalar
scalarFromNatural = unsafePerformIO . scalarFromNat

frFromNatural :: Natural -> Fr
frFromNatural = frFromScalar . scalarFromNatural

frToNatural :: Fr -> Natural
frToNatural = scalarToNatural . scalarFromFr

---- Pairings

pairingCheck :: (P1, P2) -> (P1, P2) -> Bool
pairingCheck (p1, p2) (q1, q2) = unsafePerformIO $ do
  withAffine a1 $ \ap1 ->
    withAffine a2 $ \ap2 ->
      withAffine b1 $ \bp1 ->
        withAffine b2 $ \bp2 ->
          c_blst_two_miller_one_exp ap1 bp1 ap2 bp2
  where
    a1 = toAffine (neg p1)
    a2 = toAffine p2
    b1 = toAffine q1
    b2 = toAffine q2



---- Utility

withMaybeCStringLen :: Maybe ByteString -> (CStringLen -> IO a) -> IO a
withMaybeCStringLen Nothing go = go (nullPtr, 0)
withMaybeCStringLen (Just bs) go = BS.useAsCStringLen bs go
