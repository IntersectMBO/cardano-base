-- | Options related to the Consensus layer
module Cardano.Configuration.File.Consensus (
  ConsensusConfiguration (..),
  ConsensusMode (..),
  GenesisConfigFlags (..),
) where

import Autodocodec
import Cardano.Configuration.Basic (diffTimeCodec)
import Data.Aeson (FromJSON, ToJSON)
import Data.Default
import Data.Functor.Identity (Identity)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (DiffTime)
import Data.Word
import GHC.Generics (Generic)

data ConsensusMode
  = PraosMode
  | GenesisMode GenesisConfigFlags
  deriving (Generic, Show)

instance Default ConsensusMode where
  def = PraosMode

-- | In which mode should the node run.
newtype ConsensusConfiguration f = ConsensusConfiguration {getConsensusConfiguration :: f ConsensusMode}

deriving instance Show (ConsensusConfiguration Maybe)
deriving instance Show (ConsensusConfiguration Identity)

deriving via
  (Autodocodec (ConsensusConfiguration Maybe))
  instance
    FromJSON (ConsensusConfiguration Maybe)

deriving via
  (Autodocodec (ConsensusConfiguration Maybe))
  instance
    ToJSON (ConsensusConfiguration Maybe)

-- | The consensus mode is selected by the @ConsensusMode@ key; the Genesis
-- flags only apply in Genesis mode, so they are read (from the
-- @LowLevelGenesisOptions@ key) only then.
instance HasCodec (ConsensusConfiguration Maybe) where
  codec =
    bimapCodec toConfig fromConfig $
      object "ConsensusConfiguration" $
        (,)
          <$> optionalField "ConsensusMode" "Which consensus mode to run (PraosMode or GenesisMode)" .= fst
          <*> optionalField "LowLevelGenesisOptions" "Low-level Genesis tuning (GenesisMode only)" .= snd
    where
      toConfig :: (Maybe Text, Maybe GenesisConfigFlags) -> Either String (ConsensusConfiguration Maybe)
      toConfig (Nothing, _) = Right (ConsensusConfiguration Nothing)
      toConfig (Just "PraosMode", _) = Right (ConsensusConfiguration (Just PraosMode))
      toConfig (Just "GenesisMode", mflags) = Right (ConsensusConfiguration (Just (GenesisMode (fromMaybe def mflags))))
      toConfig (Just other, _) = Left $ "Unknown consensus mode: " <> T.unpack other
      fromConfig (ConsensusConfiguration Nothing) = (Nothing, Nothing)
      fromConfig (ConsensusConfiguration (Just PraosMode)) = (Just "PraosMode", Nothing)
      fromConfig (ConsensusConfiguration (Just (GenesisMode flags))) = (Just "GenesisMode", Just flags)

-- | Configuration options for Genesis parameters
data GenesisConfigFlags = GenesisConfigFlags
  { gcfEnableCSJ :: Bool
  , gcfEnableLoEAndGDD :: Bool
  , gcfEnableLoP :: Bool
  , gcfBlockFetchGracePeriod :: Maybe DiffTime
  , gcfBucketCapacity :: Maybe Integer
  , gcfBucketRate :: Maybe Integer
  , gcfCSJJumpSize :: Maybe Word64
  , gcfGDDRateLimit :: Maybe DiffTime
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec GenesisConfigFlags)

instance Default GenesisConfigFlags where
  def = GenesisConfigFlags True True True Nothing Nothing Nothing Nothing Nothing

instance HasCodec GenesisConfigFlags where
  codec =
    object "GenesisConfigFlags" $
      GenesisConfigFlags
        <$> optionalFieldWithDefault "EnableCSJ" True "Enable ChainSync Jumping" .= gcfEnableCSJ
        <*> optionalFieldWithDefault
          "EnableLoEAndGDD"
          True
          "Enable the Limit on Eagerness and the Genesis Density Disconnection"
          .= gcfEnableLoEAndGDD
        <*> optionalFieldWithDefault "EnableLoP" True "Enable the Limit on Patience" .= gcfEnableLoP
        <*> optionalFieldWith "BlockFetchGracePeriod" diffTimeCodec "Grace period, in seconds, for BlockFetch"
          .= gcfBlockFetchGracePeriod
        <*> optionalField "BucketCapacity" "Token bucket capacity for the LoP" .= gcfBucketCapacity
        <*> optionalField "BucketRate" "Token bucket refill rate for the LoP" .= gcfBucketRate
        <*> optionalField "CSJJumpSize" "Size, in slots, of ChainSync jumps" .= gcfCSJJumpSize
        <*> optionalFieldWith "GDDRateLimit" diffTimeCodec "Rate limit, in seconds, for the GDD"
          .= gcfGDDRateLimit
