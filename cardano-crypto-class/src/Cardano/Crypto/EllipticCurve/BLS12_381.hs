{-#LANGUAGE ScopedTypeVariables #-}
{-#LANGUAGE TypeApplications #-}
{-#LANGUAGE FlexibleContexts #-}
module Cardano.Crypto.EllipticCurve.BLS12_381
(
  -- * Types
    P
  , P1
  , P2
  , PT
  , Curve1
  , Curve2
  , BLSTError (..)

  -- * BLS Class
  , BLS
  , BLS_P
  , BLS_Curve

  -- * Point / Group operations
  -- | These work on both curves, and take phantom parameters of type 'Curve1'
  -- or 'Curve2' to select one of the two provided elliptic curves.
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

  -- * PT operations
  , ptInv
  , ptMult

  -- * Pairings
  , pairing
  , pairingCheck

  -- * The period (modulo) of scalars
  , scalarPeriod
)
where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal
