{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Crypto.Peras (
  -- * Peras round numbers
  PerasRoundNo (..),
  onPerasRoundNo,
) where

import Data.Coerce (coerce)
import Data.Word (Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import Quiet (Quiet (..))

{-------------------------------------------------------------------------------
   Peras round numbers
-------------------------------------------------------------------------------}

newtype PerasRoundNo = PerasRoundNo {unPerasRoundNo :: Word64}
  deriving (Show) via Quiet PerasRoundNo
  deriving stock (Generic)
  deriving newtype (Enum, Eq, Ord, Num, Bounded, NoThunks)

-- | Lift a binary operation on 'Word64' to 'PerasRoundNo'
onPerasRoundNo ::
  (Word64 -> Word64 -> Word64) ->
  (PerasRoundNo -> PerasRoundNo -> PerasRoundNo)
onPerasRoundNo = coerce
