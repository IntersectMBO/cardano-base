-- | Basic types for configuration
module Cardano.Configuration.Basic (
  -- * Codecs
  diffTimeCodec,

  -- * Resolution
  requireField,
) where

import Autodocodec (JSONCodec, dimapCodec, scientificCodec)
import Data.Functor.Identity (Identity (..))
import Data.Time.Clock (DiffTime)

-- | Turn an @f@-parameter field into its resolved 'Identity' form. The value is
-- expected to have been supplied by the always-applied base defaults, so a
-- missing one is a configuration-packaging error and is reported by name.
requireField :: String -> Maybe a -> Either String (Identity a)
requireField name = maybe (Left ("missing default value for " <> name)) (Right . Identity)

-- | A codec for 'DiffTime', represented in JSON as a (possibly fractional)
-- number of seconds, matching the node.
diffTimeCodec :: JSONCodec DiffTime
diffTimeCodec = dimapCodec realToFrac realToFrac scientificCodec
