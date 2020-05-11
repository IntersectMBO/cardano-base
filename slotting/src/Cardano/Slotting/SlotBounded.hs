{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Intended for qualified import
module Cardano.Slotting.SlotBounded
  ( -- * Bounds
    Bounds (..),
    InBounds (..),

    -- * Slot-bounded values
    SlotBounded (..),
    bounds,
    bounded,
    maximal,
    at,
    contains,
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Prelude (CanonicalExamples, NoUnexpectedThunks)
import Cardano.Slotting.Slot (SlotNo, WithOrigin(..))
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Encoding as CBOR
import Codec.Serialise (Serialise)
import Data.Proxy
import Data.Typeable (Typeable)
import GHC.Generics (Generic)

{-------------------------------------------------------------------------------
  Bounds
-------------------------------------------------------------------------------}

data Bounds
  = -- | Both bounds are inclusive
    II
  | -- | Lower bound is inclusive, upper bound is exclusive
    IX

class InBounds (bounds :: Bounds) where
  inBounds :: proxy bounds
           -> WithOrigin SlotNo
           -> (WithOrigin SlotNo, SlotNo) -> Bool

instance InBounds 'II where
  inBounds _ x (lo, hi) = lo <= x && x <= At hi

instance InBounds 'IX where
  inBounds _ x (lo, hi) = lo <= x && x < At hi

{-------------------------------------------------------------------------------
  Slot-bounded values
-------------------------------------------------------------------------------}

-- | An item bounded to be valid within particular slots
data SlotBounded (bounds :: Bounds) a
  = SlotBounded
      { sbLower   :: !(WithOrigin SlotNo),
        sbUpper   :: !SlotNo,
        sbContent :: !a
      }
  deriving (Eq, Functor, Show, Generic, Serialise, NoUnexpectedThunks, CanonicalExamples)

instance (FromCBOR a, Typeable b) => FromCBOR (SlotBounded b a) where
  fromCBOR = do
    CBOR.decodeListLenOf 3
    SlotBounded
      <$> fromCBOR
      <*> fromCBOR
      <*> fromCBOR

instance (ToCBOR a, Typeable b) => ToCBOR (SlotBounded b a) where
  toCBOR SlotBounded {sbLower, sbUpper, sbContent} =
    mconcat
      [ CBOR.encodeListLen 3,
        toCBOR sbLower,
        toCBOR sbUpper,
        toCBOR sbContent
      ]

bounds :: SlotBounded bounds a -> (WithOrigin SlotNo, SlotNo)
bounds (SlotBounded lo hi _) = (lo, hi)

contains ::
  forall bounds a.
  InBounds bounds =>
  SlotBounded bounds a ->
  WithOrigin SlotNo ->
  Bool
sb `contains` slot = inBounds (Proxy @bounds) slot (bounds sb)

-- | Construct a slot bounded item.
--
-- We choose not to validate that the slot bounds are reasonable here.
bounded :: WithOrigin SlotNo -> SlotNo -> a -> SlotBounded bounds a
bounded = SlotBounded

maximal :: a -> SlotBounded bounds a
maximal = SlotBounded Origin maxBound

at :: InBounds bounds => SlotBounded bounds a -> WithOrigin SlotNo -> Maybe a
sb `at` slot =
  if sb `contains` slot
    then Just $ sbContent sb
    else Nothing
