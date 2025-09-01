{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveTraversable #-}

-- | Strict version of the 'Maybe' type.
module Data.Maybe.Strict (
  StrictMaybe (SNothing, SJust),

  -- * Conversion: StrictMaybe <--> Maybe
  strictMaybeToMaybe,
  maybeToStrictMaybe,

  -- * Accessing the underlying value
  fromSMaybe,
  isSNothing,
  isSJust,
  strictMaybe,
)
where

import Cardano.Binary (
  FromCBOR (fromCBOR),
  ToCBOR (toCBOR),
  decodeBreakOr,
  decodeListLenOrIndef,
  encodeListLen,
 )
import Control.Applicative (Alternative (..))
import Control.DeepSeq (NFData)
import Data.Aeson (FromJSON (..), ToJSON (..))
import Data.Default.Class (Default (..))
import Data.Functor (($>))
import Data.Functor.Classes (
  Eq1 (..),
  Ord1 (..),
  Read1 (..),
  Show1 (..),
  liftReadListDefault,
  liftReadListPrecDefault,
  readData,
  readUnaryWith,
  showsUnaryWith,
 )
import GHC.Generics (Generic)
import GHC.Read (expectP)
import NoThunks.Class (NoThunks (..))
import Text.Read (Lexeme (..), parens)

data StrictMaybe a
  = SNothing
  | SJust !a
  deriving
    ( Eq
    , Ord
    , Show
    , Read
    , Generic
    , Functor
    , Foldable
    , Traversable
    , NoThunks
    , NFData
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

  return = pure

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
  toEncoding = toEncoding . strictMaybeToMaybe

instance FromJSON a => FromJSON (StrictMaybe a) where
  parseJSON v = maybeToStrictMaybe <$> parseJSON v

strictMaybeToMaybe :: StrictMaybe a -> Maybe a
strictMaybeToMaybe SNothing = Nothing
strictMaybeToMaybe (SJust x) = Just x

maybeToStrictMaybe :: Maybe a -> StrictMaybe a
maybeToStrictMaybe Nothing = SNothing
maybeToStrictMaybe (Just x) = SJust x

-- | Same as `Data.Maybe.fromMaybe`
fromSMaybe :: a -> StrictMaybe a -> a
fromSMaybe d SNothing = d
fromSMaybe _ (SJust x) = x

-- | Same as `Data.Maybe.isNothing`
isSNothing :: StrictMaybe a -> Bool
isSNothing SNothing = True
isSNothing _ = False

-- | Same as `Data.Maybe.isJust`
isSJust :: StrictMaybe a -> Bool
isSJust = not . isSNothing

-- | Same as `Data.Maybe.maybe`
strictMaybe :: a -> (b -> a) -> StrictMaybe b -> a
strictMaybe x _ SNothing = x
strictMaybe _ f (SJust y) = f y

instance Default (StrictMaybe t) where
  def = SNothing

instance Semigroup a => Semigroup (StrictMaybe a) where
  SNothing <> x = x
  x <> SNothing = x
  SJust x <> SJust y = SJust (x <> y)

instance Semigroup a => Monoid (StrictMaybe a) where
  mempty = SNothing

instance Alternative StrictMaybe where
  empty = SNothing
  SNothing <|> r = r
  l <|> _ = l

instance Eq1 StrictMaybe where
  liftEq f (SJust a) (SJust b) = f a b
  liftEq _ SNothing SNothing = True
  liftEq _ _ _ = False

instance Ord1 StrictMaybe where
  liftCompare _ SNothing SNothing = EQ
  liftCompare _ SNothing (SJust _) = LT
  liftCompare _ (SJust _) SNothing = GT
  liftCompare comp (SJust x) (SJust y) = comp x y

instance Show1 StrictMaybe where
  liftShowsPrec sp _ d (SJust x) = showsUnaryWith sp "SJust" d x
  liftShowsPrec _ _ _ SNothing = showString "SNothing"

instance Read1 StrictMaybe where
  liftReadPrec rp _ =
    parens (expectP (Ident "SNothing") $> SNothing)
      <|> readData (readUnaryWith rp "SJust" SJust)

  liftReadListPrec = liftReadListPrecDefault
  liftReadList = liftReadListDefault
