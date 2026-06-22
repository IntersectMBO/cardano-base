-- | Parse the configuration for a @cardano-node@, combining both the
-- t'Cardano.Configuration.CliArgs' and the
-- t'Cardano.Configuration.NodeConfigurationFromFile'
--
-- The configuration file can be either in JSON or in YAML format.
module Cardano.Configuration (
  -- * Configuration
  NodeConfiguration (..),
  resolveConfiguration,
  ConfigResolutionError (..),

  -- ** Storage
  File.StorageConfiguration (..),
  File.LedgerDbConfiguration (..),
  File.NodeDatabasePaths (..),

  -- ** Consensus
  File.ConsensusConfiguration (..),
  File.GenesisConfigFlags (..),

  -- ** Protocol
  File.ProtocolConfiguration (..),
  File.ByronGenesisConfiguration (..),
  File.RequiresNetworkMagic (..),
  File.Hashed (..),
  CLI.Credentials (..),
  CLI.KESSource (..),

  -- ** Network
  File.NetworkConfiguration (..),
  File.DiffusionMode (..),
  File.LocalConnectionsConfig (..),

  -- ** Testing
  File.TestingConfiguration (..),
  CLI.TracerConnection (..),

  -- ** Mempool
  File.MempoolConfiguration (..),

  -- ** Operational
  CLI.ShutdownOn (..),

  -- * CLI
  CLI.CliArgs,
  CLI.parseCliArgs,

  -- ** Reusable option parsers
  CLI.parseConfigFile,
  CLI.parseTopologyFile,
  CLI.parseSocketPath,
  CLI.parseValidateDB,
  CLI.parseEnableRpc,
  CLI.parseRpcSocketPath,
  CLI.parseCredentials,
  CLI.parseKESSource,
  CLI.parseHostIPv4Addr,
  CLI.parseHostIPv6Addr,
  CLI.parsePort,
  CLI.parseTracerSocketMode,
  CLI.parseShutdownIPC,
  CLI.parseShutdownOn,
  CLI.parseNodeAddress,
  CLI.parseHostPort,

  -- * Configuration file
  File.NodeConfigurationFromFile,
  File.parseConfigurationFiles,
  File.parseConfigurationFilesWith,
  File.UnknownKeyPolicy (..),
  File.ConfigurationParsingError (..),
) where

import qualified Cardano.Configuration.CliArgs as CLI
import qualified Cardano.Configuration.Common as File
import qualified Cardano.Configuration.File as File
import Cardano.Configuration.File.Consensus
import qualified Cardano.Configuration.File.Consensus as File
import qualified Cardano.Configuration.File.Protocol as File
import qualified Cardano.Configuration.File.Storage as File
import Control.Applicative ((<|>))
import Control.Exception (Exception)
import Data.Default
import Data.Functor.Identity
import Data.IP
import Data.Maybe
import Network.Socket
import System.Posix.Types

-- | The complete configuration for a cardano-node, combining the configuration
-- file and the cli arguments
data NodeConfiguration = NodeConfiguration
  { storageConfiguration :: File.StorageConfiguration Identity
  , consensusConfiguration :: File.ConsensusConfiguration Identity
  , protocolConfiguration :: File.ProtocolConfiguration Identity
  , networkConfiguration :: File.NetworkConfiguration
  , localConnectionsConfig :: File.LocalConnectionsConfig
  , testingConfiguration :: File.TestingConfiguration
  , mempoolConfiguration :: File.MempoolConfiguration
  , configFilePath :: FilePath
  , topologyFile :: FilePath
  , validateDatabase :: Bool
  , credentials :: CLI.Credentials
  , hostAddr :: Maybe IPv4
  , hostIPv6Addr :: Maybe IPv6
  , port :: Maybe PortNumber
  , tracerSocket :: Maybe CLI.TracerConnection
  , shutdownIPC :: Maybe Fd
  , shutdownOnTarget :: Maybe CLI.ShutdownOn
  }
  deriving (Show)

-- | An error detected while resolving the configuration, i.e. a combination of
-- CLI arguments and file values that is individually well-formed but
-- inconsistent as a whole.
data ConfigResolutionError
  = -- | The gRPC endpoint was enabled but there is neither an explicit gRPC
    -- socket path nor a node socket path to derive one from.
    RpcEnabledWithoutSocketPath
  deriving (Eq, Show)

instance Exception ConfigResolutionError

-- | Combine the cli arguments and configuration file values into a full
-- configuration, then check it for cross-field consistency. CLI values take
-- precedence over file values.
resolveConfiguration ::
  CLI.CliArgs -> File.NodeConfigurationFromFile -> Either ConfigResolutionError NodeConfiguration
resolveConfiguration cli file =
  validateConfiguration $
    NodeConfiguration
      { storageConfiguration =
          let sc = runIdentity $ File.storageConfiguration file
           in File.adjustDbPath
                sc
                (fromMaybe def $ CLI.databasePathCLI cli <|> File.databasePath sc)
      , consensusConfiguration =
          ConsensusConfiguration $
            Identity $
              fromMaybe def $
                getConsensusConfiguration (runIdentity (File.consensusConfiguration file))
      , protocolConfiguration =
          let pc = runIdentity $ File.protocolConfiguration file
           in pc
                { File.startAsNonProducingNode =
                    Identity $
                      fromMaybe False $
                        CLI.startAsNonProducingNode cli <|> File.startAsNonProducingNode pc
                }
      , networkConfiguration = runIdentity $ File.networkConfiguration file
      , localConnectionsConfig =
          let lcc = runIdentity $ File.localConnectionsConfig file
           in File.LocalConnectionsConfig
                (CLI.socketPath cli <|> File.socketPath lcc)
                (CLI.enableRpcCLI cli <|> File.enableRpc lcc)
                (CLI.rpcSocketPathCLI cli <|> File.rpcSocketPath lcc)
      , testingConfiguration = runIdentity $ File.testingConfiguration file
      , mempoolConfiguration = runIdentity $ File.mempoolConfiguration file
      , configFilePath = CLI.configFilePath cli
      , topologyFile = CLI.topologyFile cli
      , validateDatabase = CLI.validateDatabase cli
      , credentials = CLI.credentials cli
      , hostAddr = CLI.hostAddr cli
      , hostIPv6Addr = CLI.hostIPv6Addr cli
      , port = CLI.port cli
      , tracerSocket = CLI.tracerSocket cli
      , shutdownIPC = CLI.shutdownIPC cli
      , shutdownOnTarget = CLI.shutdownOnTarget cli
      }

-- | Cross-field validation of a resolved configuration. This is the place for
-- consistency checks that span CLI and file values or multiple components;
-- structural validation of individual values lives in the codecs.
validateConfiguration :: NodeConfiguration -> Either ConfigResolutionError NodeConfiguration
validateConfiguration nc = nc <$ rpcSocketCheck
  where
    lcc = localConnectionsConfig nc
    -- With the gRPC endpoint enabled, the gRPC socket path defaults to a file
    -- next to the node socket; if neither path is known, there is nothing to
    -- derive it from.
    rpcSocketCheck
      | File.enableRpc lcc == Just True
      , isNothing (File.rpcSocketPath lcc)
      , isNothing (File.socketPath lcc) =
          Left RpcEnabledWithoutSocketPath
      | otherwise = Right ()
