{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Slotting.Block
  ( BlockNo (..)
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Codec.Serialise (Serialise (..))
import Control.DeepSeq (NFData)
import Data.Word (Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import Quiet (Quiet (..))

-- | The 0-based index of the block in the blockchain.
-- BlockNo is <= SlotNo and is only equal at slot N if there is a block
-- for every slot where N <= SlotNo.
newtype BlockNo = BlockNo {unBlockNo :: Word64}
  deriving stock (Eq, Ord, Generic)
  deriving Show via Quiet BlockNo
  deriving newtype (Enum, Bounded, Num, Serialise, NoThunks, NFData)

instance ToCBOR BlockNo where
  toCBOR = encode
  encodedSizeExpr size = encodedSizeExpr size . fmap unBlockNo

instance FromCBOR BlockNo where
  fromCBOR = decode
