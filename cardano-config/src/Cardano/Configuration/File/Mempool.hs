-- | Options related to the mempool
module Cardano.Configuration.File.Mempool (
  MempoolConfiguration (..),
  finalizeMempool,
) where

import Autodocodec
import Cardano.Configuration.Basic (diffTimeCodec)
import Data.Aeson (FromJSON, ToJSON)
import Data.Functor.Identity (Identity (..))
import Data.Time.Clock (DiffTime)
import Data.Word
import GHC.Generics (Generic)

-- | The mempool configuration. Every field is optional by nature (the node's
-- default is "no override" / "no timeout"), so the @f@ parameter is phantom and
-- the fields stay @Maybe@ in both the partial and resolved forms. See
-- "Cardano.Configuration.File" for the @f@-parameter convention.
data MempoolConfiguration f = MempoolConfiguration
  { mempoolCapacityOverride :: Maybe Word64
  , mempoolTimeoutSoft :: Maybe DiffTime
  , mempoolTimeoutHard :: Maybe DiffTime
  , mempoolTimeoutCapacity :: Maybe DiffTime
  }
  deriving (Generic)

deriving instance Show (MempoolConfiguration Maybe)
deriving instance Show (MempoolConfiguration Identity)

deriving via
  (Autodocodec (MempoolConfiguration Maybe))
  instance
    FromJSON (MempoolConfiguration Maybe)

deriving via
  (Autodocodec (MempoolConfiguration Maybe))
  instance
    ToJSON (MempoolConfiguration Maybe)

instance HasCodec (MempoolConfiguration Maybe) where
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

-- | Resolve a partial mempool configuration. All fields are optional, so this
-- cannot fail.
finalizeMempool :: MempoolConfiguration Maybe -> Either String (MempoolConfiguration Identity)
finalizeMempool c =
  Right
    MempoolConfiguration
      { mempoolCapacityOverride = mempoolCapacityOverride c
      , mempoolTimeoutSoft = mempoolTimeoutSoft c
      , mempoolTimeoutHard = mempoolTimeoutHard c
      , mempoolTimeoutCapacity = mempoolTimeoutCapacity c
      }

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
