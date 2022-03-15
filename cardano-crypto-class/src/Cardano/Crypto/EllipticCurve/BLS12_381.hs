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

  -- * Pairings
  , pairingCheck

  -- * The period of scalars
  , scalarPeriod
)
where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal
