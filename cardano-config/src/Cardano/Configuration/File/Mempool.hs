-- | Options related to the mempool
module Cardano.Configuration.File.Mempool (
  MempoolConfiguration (..),
) where

import Autodocodec
import Cardano.Configuration.Basic (diffTimeCodec)
import Data.Aeson (FromJSON, ToJSON)
import Data.Time.Clock (DiffTime)
import Data.Word
import GHC.Generics (Generic)

-- | The mempool configuration. All fields are optional; when unset the node
-- applies its own defaults.
data MempoolConfiguration = MempoolConfiguration
  { mempoolCapacityOverride :: Maybe Word64
  , mempoolTimeoutSoft :: Maybe DiffTime
  , mempoolTimeoutHard :: Maybe DiffTime
  , mempoolTimeoutCapacity :: Maybe DiffTime
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec MempoolConfiguration)

instance HasCodec MempoolConfiguration where
  codec =
    object "MempoolConfiguration" $
      MempoolConfiguration
        <$> optionalFieldWithDefaultWith
          "MempoolCapacityBytesOverride"
          mempoolCapacityOverrideCodec
          Nothing
          "Override for the maximum mempool size in bytes, or the string \"NoOverride\""
          .= mempoolCapacityOverride
        <*> optionalFieldWith "MempoolTimeoutSoft" diffTimeCodec "Soft mempool timeout, in seconds"
          .= mempoolTimeoutSoft
        <*> optionalFieldWith "MempoolTimeoutHard" diffTimeCodec "Hard mempool timeout, in seconds"
          .= mempoolTimeoutHard
        <*> optionalFieldWith "MempoolTimeoutCapacity" diffTimeCodec "Capacity mempool timeout, in seconds"
          .= mempoolTimeoutCapacity

-- | The mempool capacity override is either a byte count or the string
-- @"NoOverride"@ (which, like omitting the key, means \"use the default\").
mempoolCapacityOverrideCodec :: JSONCodec (Maybe Word64)
mempoolCapacityOverrideCodec =
  dimapCodec toOverride fromOverride $
    eitherCodec
      (codec @Word64)
      (literalTextCodec "NoOverride")
  where
    toOverride = either Just (const Nothing)
    fromOverride (Just c) = Left c
    fromOverride Nothing = Right "NoOverride"
