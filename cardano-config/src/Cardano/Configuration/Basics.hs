-- | Basic types for configuration
module Cardano.Configuration.Basics (
  -- * Codecs
  diffTimeCodec,
) where

import Autodocodec (JSONCodec, dimapCodec, scientificCodec)
import Data.Time.Clock (DiffTime)

-- | A codec for 'DiffTime', represented in JSON as a (possibly fractional)
-- number of seconds, matching the node.
diffTimeCodec :: JSONCodec DiffTime
diffTimeCodec = dimapCodec realToFrac realToFrac scientificCodec
