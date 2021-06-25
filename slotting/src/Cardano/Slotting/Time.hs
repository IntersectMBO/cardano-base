{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingVia                #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Slotting.Time (
    -- * System time
    SystemStart (..)
    -- * Relative time
  , RelativeTime (..)
  , addRelativeTime
  , diffRelativeTime
  , fromRelativeTime
  , toRelativeTime
    -- * Slot length
  , getSlotLength
  , mkSlotLength
    -- ** Conversions
  , slotLengthFromMillisec
  , slotLengthFromSec
  , slotLengthToMillisec
  , slotLengthToSec
    -- ** opaque
  , SlotLength
  ) where

import           Cardano.Binary (FromCBOR(..), ToCBOR(..))
import           Codec.Serialise
import           Control.Exception (assert)
import           Data.Fixed
import           Data.Time (NominalDiffTime, UTCTime, addUTCTime, diffUTCTime)
import           GHC.Generics (Generic)
import           NoThunks.Class (InspectHeap (..), NoThunks)
import           Quiet

{-------------------------------------------------------------------------------
  System start
-------------------------------------------------------------------------------}

-- | System start
--
-- Slots are counted from the system start.
newtype SystemStart = SystemStart { getSystemStart :: UTCTime }
  deriving (Eq, Generic)
  deriving NoThunks via InspectHeap SystemStart
  deriving Show via Quiet SystemStart
  deriving newtype Serialise
  deriving newtype (ToCBOR, FromCBOR)

{-------------------------------------------------------------------------------
  Relative time
-------------------------------------------------------------------------------}

-- | 'RelativeTime' is time relative to the 'SystemStart'
newtype RelativeTime = RelativeTime { getRelativeTime :: NominalDiffTime }
  deriving stock   (Eq, Ord, Generic)
  deriving newtype (NoThunks)
  deriving Show via Quiet RelativeTime

addRelativeTime :: NominalDiffTime -> RelativeTime -> RelativeTime
addRelativeTime delta (RelativeTime t) = RelativeTime (t + delta)

diffRelativeTime :: RelativeTime -> RelativeTime -> NominalDiffTime
diffRelativeTime (RelativeTime t) (RelativeTime t') = t - t'

toRelativeTime :: SystemStart -> UTCTime -> RelativeTime
toRelativeTime (SystemStart t) t' = assert (t' >= t) $
                                      RelativeTime (diffUTCTime t' t)

fromRelativeTime :: SystemStart -> RelativeTime -> UTCTime
fromRelativeTime (SystemStart t) (RelativeTime t') = addUTCTime t' t

{-------------------------------------------------------------------------------
  SlotLength
-------------------------------------------------------------------------------}

-- | Slot length
newtype SlotLength = SlotLength { getSlotLength :: NominalDiffTime }
  deriving (Eq, Generic, NoThunks)
  deriving Show via Quiet SlotLength

-- | Constructor for 'SlotLength'
mkSlotLength :: NominalDiffTime -> SlotLength
mkSlotLength = SlotLength

slotLengthFromSec :: Integer -> SlotLength
slotLengthFromSec = slotLengthFromMillisec . (* 1000)

slotLengthToSec :: SlotLength -> Integer
slotLengthToSec = (`div` 1000) . slotLengthToMillisec

slotLengthFromMillisec :: Integer -> SlotLength
slotLengthFromMillisec = mkSlotLength . conv
  where
    -- Explicit type annotation here means that /if/ we change the precision,
    -- we are forced to reconsider this code.
    conv :: Integer -> NominalDiffTime
    conv = (realToFrac :: Pico -> NominalDiffTime)
         . (/ 1000)
         . (fromInteger :: Integer -> Pico)

slotLengthToMillisec :: SlotLength -> Integer
slotLengthToMillisec = conv . getSlotLength
  where
    -- Explicit type annotation here means that /if/ we change the precision,
    -- we are forced to reconsider this code.
    conv :: NominalDiffTime -> Integer
    conv = truncate
         . (* 1000)
         . (realToFrac :: NominalDiffTime -> Pico)

{-------------------------------------------------------------------------------
  Serialisation
-------------------------------------------------------------------------------}

instance Serialise RelativeTime where
  encode = encode . toPico . getRelativeTime
    where
      toPico :: NominalDiffTime -> Pico
      toPico = realToFrac

  decode = (RelativeTime . fromPico) <$> decode
    where
      fromPico :: Pico -> NominalDiffTime
      fromPico = realToFrac

instance Serialise SlotLength where
  encode = toCBOR
  decode = fromCBOR

instance ToCBOR SlotLength where
  toCBOR = toCBOR . slotLengthToMillisec

instance FromCBOR SlotLength where
  fromCBOR = slotLengthFromMillisec <$> fromCBOR
