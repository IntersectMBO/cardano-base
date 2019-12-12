{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Slotting.Slot
  ( SlotNo (..),
    genesisSlotNo,
    WithOrigin (..),
    at,
    origin,
    fromWithOrigin,
    withOrigin,
    withOriginToMaybe,
    withOriginFromMaybe,
    EpochNo (..),
    EpochSize (..),
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Prelude (NoUnexpectedThunks)
import Codec.Serialise (Serialise (..))
import Data.Word (Word64)
import GHC.Generics (Generic)

-- | The 0-based index for the Ourboros time slot.
newtype SlotNo = SlotNo {unSlotNo :: Word64}
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Enum, Bounded, Num, Serialise, NoUnexpectedThunks)

instance ToCBOR SlotNo where
  toCBOR = encode

instance FromCBOR SlotNo where
  fromCBOR = decode

genesisSlotNo :: SlotNo
genesisSlotNo = SlotNo 0

{-------------------------------------------------------------------------------
  WithOrigin
-------------------------------------------------------------------------------}

data WithOrigin t = Origin | At !t
  deriving (Eq, Ord, Show, Generic, Functor, Foldable, Traversable, NoUnexpectedThunks)

at :: t -> WithOrigin t
at = At

origin :: WithOrigin t
origin = Origin

fromWithOrigin :: t -> WithOrigin t -> t
fromWithOrigin t Origin = t
fromWithOrigin _ (At t) = t

withOrigin :: b -> (t -> b) -> WithOrigin t -> b
withOrigin a _ Origin = a
withOrigin _ f (At t) = f t

withOriginToMaybe :: WithOrigin t -> Maybe t
withOriginToMaybe Origin = Nothing
withOriginToMaybe (At t) = Just t

withOriginFromMaybe :: Maybe t -> WithOrigin t
withOriginFromMaybe Nothing = Origin
withOriginFromMaybe (Just t) = At t

{-------------------------------------------------------------------------------
  Epochs
-------------------------------------------------------------------------------}

-- | An epoch, i.e. the number of the epoch.
newtype EpochNo = EpochNo {unEpochNo :: Word64}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (Enum, Num, Serialise, ToCBOR, NoUnexpectedThunks)

newtype EpochSize = EpochSize {unEpochSize :: Word64}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (Enum, Num, Real, Integral, NoUnexpectedThunks)
