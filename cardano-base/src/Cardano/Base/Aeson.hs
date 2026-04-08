{-# LANGUAGE GADTs #-}

module Cardano.Base.Aeson (
  fromJSONKeyText,
) where

import Data.Aeson (FromJSONKey (..), Value (String))
import Data.Aeson.Types (
  FromJSONKeyFunction (..),
  parseEither,
 )
import Data.Coerce (coerce)
import Data.Text (Text)

fromJSONKeyText :: FromJSONKey k => Text -> Either String k
fromJSONKeyText t = case fromJSONKey of
  FromJSONKeyCoerce -> Right (coerce t)
  FromJSONKeyText g -> Right (g t)
  FromJSONKeyTextParser p -> parseEither p t
  FromJSONKeyValue p -> parseEither p (String t)
