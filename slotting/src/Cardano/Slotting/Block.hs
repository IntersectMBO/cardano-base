{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Slotting.Block
  ( BlockNo (..)
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Prelude (NoUnexpectedThunks)
import Codec.Serialise (Serialise (..))
import Data.Word (Word64)
import GHC.Generics (Generic)

-- | The 0-based index of the block in the blockchain.
-- BlockNo is <= SlotNo and is only equal at slot N if there is a block
-- for every slot where N <= SlotNo.
newtype BlockNo = BlockNo {unBlockNo :: Word64}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Enum, Bounded, Num, Serialise, NoUnexpectedThunks)

instance ToCBOR BlockNo where
  toCBOR = encode

instance FromCBOR BlockNo where
  fromCBOR = decode
