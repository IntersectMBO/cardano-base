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

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal
