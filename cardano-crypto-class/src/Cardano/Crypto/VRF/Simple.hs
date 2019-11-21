{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementations of verifiable random functions.
module Cardano.Crypto.VRF.Simple
  ( SimpleVRF
  , pointFromMaybe
  )
where

import Cardano.Binary
  ( Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , encodeListLen
  , enforceSize
  )
import Cardano.Crypto.Hash
import Cardano.Crypto.VRF.Class
import Cardano.Prelude (NoUnexpectedThunks, UseIsNormalForm(..))
import Crypto.Number.Generate (generateBetween)
import qualified Crypto.PubKey.ECC.Prim as C
import qualified Crypto.PubKey.ECC.Types as C
import Crypto.Random (MonadRandom (..))
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import Numeric.Natural (Natural)

data SimpleVRF

type H = MD5

curve :: C.Curve
curve = C.getCurveByName C.SEC_t113r1

q :: Integer
q = C.ecc_n $ C.common_curve curve

newtype Point = Point C.Point
  deriving (Eq, Generic)
  deriving NoUnexpectedThunks via UseIsNormalForm C.Point

instance Show Point where
  show (Point p) = show p

instance ToCBOR Point where
  toCBOR (Point p) = toCBOR $ pointToMaybe p

instance FromCBOR Point where
  fromCBOR = Point . pointFromMaybe <$> fromCBOR

instance Semigroup Point where
  Point p <> Point r = Point $ C.pointAdd curve p r

instance Monoid Point where
  mempty = Point C.PointO
  mappend = (<>)

pointToMaybe :: C.Point -> Maybe (Integer, Integer)
pointToMaybe C.PointO = Nothing
pointToMaybe (C.Point x y) = Just (x, y)

pointFromMaybe :: Maybe (Integer, Integer) -> C.Point
pointFromMaybe Nothing = C.PointO
pointFromMaybe (Just (x, y)) = C.Point x y

pow :: Integer -> Point
pow = Point . C.pointBaseMul curve

pow' :: Point -> Integer -> Point
pow' (Point p) n = Point $ C.pointMul curve n p

h :: Encoding -> Natural
h = fromHash . hashWithSerialiser @H id

h' :: Encoding -> Integer -> Point
h' enc l = pow $ mod (l * (fromIntegral $ h enc)) q

getR :: MonadRandom m => m Integer
getR = generateBetween 0 (q - 1)

instance VRFAlgorithm SimpleVRF where

  type Signable SimpleVRF = ToCBOR

  newtype VerKeyVRF SimpleVRF = VerKeySimpleVRF Point
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR, NoUnexpectedThunks)

  newtype SignKeyVRF SimpleVRF = SignKeySimpleVRF C.PrivateNumber
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoUnexpectedThunks via UseIsNormalForm C.PrivateNumber

  data CertVRF SimpleVRF
    = CertSimpleVRF
        { certU :: Point
        , certC :: Natural
        , certS :: Integer
        }
    deriving stock    (Show, Eq, Generic)
    deriving anyclass (NoUnexpectedThunks)

  maxVRF _ = 2 ^ (8 * byteCount (Proxy :: Proxy H)) - 1
  genKeyVRF = SignKeySimpleVRF <$> C.scalarGenerate curve
  deriveVerKeyVRF (SignKeySimpleVRF k) =
    VerKeySimpleVRF $ pow k
  decodeVerKeyVRF = fromCBOR
  encodeVerKeyVRF = toCBOR
  evalVRF () a sk@(SignKeySimpleVRF k) = do
    let u = h' (toCBOR a) k
        y = h $ toCBOR a <> toCBOR u
        VerKeySimpleVRF v = deriveVerKeyVRF sk
    r <- getR
    let c = h $ toCBOR a <> toCBOR v <> toCBOR (pow r) <> toCBOR (h' (toCBOR a) r)
        s = mod (r + k * fromIntegral c) q
    return (y, CertSimpleVRF u c s)
  verifyVRF () (VerKeySimpleVRF v) a (y, cert) =
    let u = certU cert
        c = certC cert
        c' = -fromIntegral c
        s = certS cert
        b1 = y == h (toCBOR a <> toCBOR u)
        rhs =
          h $ toCBOR a <>
            toCBOR v <>
            toCBOR (pow s <> pow' v c') <>
            toCBOR (h' (toCBOR a) s <> pow' u c')
    in b1 && c == rhs

instance ToCBOR (CertVRF SimpleVRF) where
  toCBOR cvrf =
    encodeListLen 3 <>
      toCBOR (certU cvrf) <>
      toCBOR (certC cvrf) <>
      toCBOR (certS cvrf)

instance FromCBOR (CertVRF SimpleVRF) where
  fromCBOR =
    CertSimpleVRF <$
      enforceSize "CertVRF SimpleVRF" 3 <*>
      fromCBOR <*>
      fromCBOR <*>
      fromCBOR
