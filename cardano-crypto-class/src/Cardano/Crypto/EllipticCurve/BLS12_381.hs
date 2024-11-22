{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Crypto.EllipticCurve.BLS12_381 (
  -- * Types
  Point,
  Point1,
  Point2,
  PT,
  Curve1,
  Curve2,
  BLSTError (..),

  -- * BLS Class
  BLS,

  -- * Point / Group operations

  -- | These work on both curves, and take phantom parameters of type 'Curve1'
  -- or 'Curve2' to select one of the two provided elliptic curves.
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

  -- * PT operations
  ptMult,
  ptFinalVerify,

  -- * Pairings
  millerLoop,

  -- * The period (modulo) of scalars
  scalarPeriod,
)
where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal
