{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}

-- | Wrapper for Data.Typeable, plus convenience functions
module Cardano.Base.Typeable (
  module X,
  TypeName (..),
) where

import Data.String (IsString (fromString))
import Data.Typeable as X

data TypeName a where
  TypeNameString :: String -> TypeName a
  TypeName :: Typeable a => TypeName a

instance IsString (TypeName a) where
  fromString = TypeNameString

instance Show (TypeName a) where
  show = \case
    TypeNameString name -> name
    t@(TypeName {}) -> show (typeRep t)
