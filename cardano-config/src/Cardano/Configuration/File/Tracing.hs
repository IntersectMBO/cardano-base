-- | Tracing configuration.
--
-- Tracing is owned by the node's tracing system (hermod / @trace-dispatcher@),
-- not by @cardano-config@. The @HermodTracing@ key below is accepted but parsed
-- /opaquely/: its contents are neither interpreted nor validated here. The
-- authoritative schema for them lives in the @trace-dispatcher@ package.
--
-- This type exists as an /informational placeholder/, so that the tracing key is
-- visible in the configuration schema (rather than silently ignored) and is
-- preserved when round-tripping a configuration through the parser.
module Cardano.Configuration.File.Tracing (
  TracingConfiguration (..),
) where

import Autodocodec
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | The tracing configuration is given under a single @HermodTracing@ key,
-- whose value is a path (a string) to a separate file holding that object. It
-- is captured opaquely; see the module documentation.
newtype TracingConfiguration = TracingConfiguration
  { hermodTracing :: Maybe Text
  -- ^ A path to a file holding the tracing configuration .
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec TracingConfiguration)

instance HasCodec TracingConfiguration where
  codec =
    object "TracingConfiguration" $
      TracingConfiguration
        <$> optionalFieldWith
          "HermodTracing"
          (codec @Text)
          ( "Tracing configuration as a path to a separate file holding it. "
              <> "Consumed by the node tracing system (trace-dispatcher), not parsed or validated by cardano-config."
          )
          .= hermodTracing
