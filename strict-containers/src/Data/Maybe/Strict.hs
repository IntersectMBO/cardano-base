{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveTraversable #-}

-- | Strict version of the 'Maybe' type.
module Data.Maybe.Strict
  ( StrictMaybe (SNothing, SJust),

    -- * Conversion: StrictMaybe <--> Maybe
    strictMaybeToMaybe,
    maybeToStrictMaybe,

    -- * accessing the optional component
    fromSMaybe,
  )
where

import Cardano.Binary
  ( FromCBOR (fromCBOR),
    ToCBOR (toCBOR),
    decodeBreakOr,
    decodeListLenOrIndef,
    encodeListLen,
  )
import Control.DeepSeq (NFData)
import Data.Aeson (FromJSON (..), ToJSON (..))
import Data.Default.Class (Default (..))
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks (..))

data StrictMaybe a
  = SNothing
  | SJust !a
  deriving
    ( Eq,
      Ord,
      Show,
      Generic,
      Functor,
      Foldable,
      Traversable,
      NoThunks,
      NFData
    )

instance Applicative StrictMaybe where
  pure = SJust

  SJust f <*> m = fmap f m
  SNothing <*> _m = SNothing

  SJust _m1 *> m2 = m2
  SNothing *> _m2 = SNothing

instance Monad StrictMaybe where
  SJust x >>= k = k x
  SNothing >>= _ = SNothing

  (>>) = (*>)

  return = SJust

instance MonadFail StrictMaybe where
  fail _ = SNothing

instance ToCBOR a => ToCBOR (StrictMaybe a) where
  toCBOR SNothing = encodeListLen 0
  toCBOR (SJust x) = encodeListLen 1 <> toCBOR x

instance FromCBOR a => FromCBOR (StrictMaybe a) where
  fromCBOR = do
    maybeN <- decodeListLenOrIndef
    case maybeN of
      Just 0 -> pure SNothing
      Just 1 -> SJust <$> fromCBOR
      Just _ -> fail "too many elements in length-style decoding of StrictMaybe."
      Nothing -> do
        isBreak <- decodeBreakOr
        if isBreak
          then pure SNothing
          else do
            x <- fromCBOR
            isBreak2 <- decodeBreakOr
            if isBreak2
              then pure (SJust x)
              else fail "too many elements in break-style decoding of StrictMaybe."

instance ToJSON a => ToJSON (StrictMaybe a) where
  toJSON = toJSON . strictMaybeToMaybe

instance FromJSON a => FromJSON (StrictMaybe a) where
  parseJSON v = maybeToStrictMaybe <$> parseJSON v

strictMaybeToMaybe :: StrictMaybe a -> Maybe a
strictMaybeToMaybe SNothing = Nothing
strictMaybeToMaybe (SJust x) = Just x

maybeToStrictMaybe :: Maybe a -> StrictMaybe a
maybeToStrictMaybe Nothing = SNothing
maybeToStrictMaybe (Just x) = SJust x

fromSMaybe :: a -> StrictMaybe a -> a
fromSMaybe d SNothing = d
fromSMaybe _ (SJust x) = x

instance Default (StrictMaybe t) where
  def = SNothing
