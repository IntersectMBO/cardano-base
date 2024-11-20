{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Cardano.Slotting.Slot (
  SlotNo (..),
  WithOrigin (..),
  at,
  origin,
  fromWithOrigin,
  withOrigin,
  withOriginToMaybe,
  withOriginFromMaybe,
  EpochNo (..),
  EpochSize (..),
  EpochInterval (..),
  binOpEpochNo,
  addEpochInterval,
)
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Codec.Serialise (Serialise (..))
import Control.DeepSeq (NFData (rnf))
import Data.Aeson (FromJSON (..), ToJSON (..), Value (String))
import Data.Typeable (Typeable)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import Quiet (Quiet (..))

-- | The 0-based index for the Ourboros time slot.
newtype SlotNo = SlotNo {unSlotNo :: Word64}
  deriving stock (Eq, Ord, Generic)
  deriving (Show) via Quiet SlotNo
  deriving newtype (Enum, Bounded, Num, NFData, Serialise, NoThunks, ToJSON, FromJSON)

instance ToCBOR SlotNo where
  toCBOR = encode
  encodedSizeExpr size = encodedSizeExpr size . fmap unSlotNo

instance FromCBOR SlotNo where
  fromCBOR = decode

{-------------------------------------------------------------------------------
  WithOrigin
-------------------------------------------------------------------------------}

data WithOrigin t = Origin | At !t
  deriving
    ( Eq
    , Ord
    , Show
    , Generic
    , Functor
    , Foldable
    , Traversable
    , Serialise
    , NoThunks
    )

instance (Serialise t, Typeable t) => ToCBOR (WithOrigin t) where
  toCBOR = encode

instance (Serialise t, Typeable t) => FromCBOR (WithOrigin t) where
  fromCBOR = decode

instance Bounded t => Bounded (WithOrigin t) where
  minBound = Origin
  maxBound = At maxBound

instance NFData a => NFData (WithOrigin a) where
  rnf Origin = ()
  rnf (At t) = rnf t

instance ToJSON a => ToJSON (WithOrigin a) where
  toJSON = \case
    Origin -> String "origin"
    At n -> toJSON n

instance FromJSON a => FromJSON (WithOrigin a) where
  parseJSON = \case
    String "origin" -> pure Origin
    value -> At <$> parseJSON value

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
  deriving stock (Eq, Ord, Generic)
  deriving (Show) via Quiet EpochNo
  deriving newtype (Enum, Serialise, ToCBOR, FromCBOR, NoThunks, ToJSON, FromJSON, NFData)

newtype EpochSize = EpochSize {unEpochSize :: Word64}
  deriving stock (Eq, Ord, Generic)
  deriving (Show) via Quiet EpochSize
  deriving newtype (Enum, ToCBOR, FromCBOR, NoThunks, ToJSON, FromJSON, NFData)

newtype EpochInterval = EpochInterval
  { unEpochInterval :: Word32
  }
  deriving (Eq, Ord, Generic)
  deriving (Show) via Quiet EpochInterval
  deriving newtype (NoThunks, NFData, ToJSON, FromJSON, ToCBOR, FromCBOR)

-- | Convenience function for doing binary operations on two `EpochNo`s
binOpEpochNo :: (Word64 -> Word64 -> Word64) -> EpochNo -> EpochNo -> EpochNo
binOpEpochNo op en1 en2 = EpochNo $ op (unEpochNo en1) (unEpochNo en2)

-- | Add a EpochInterval (a positive change) to an EpochNo to get a new EpochNo
addEpochInterval :: EpochNo -> EpochInterval -> EpochNo
addEpochInterval (EpochNo n) (EpochInterval m) = EpochNo (n + fromIntegral m)
