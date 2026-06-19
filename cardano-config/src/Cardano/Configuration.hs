-- | Parse the configuration for a @cardano-node@, combining both the
-- t'Cardano.Configuration.CliArgs' and the
-- t'Cardano.Configuration.NodeConfigurationFromFile'
--
-- The configuration file can be either in JSON or in YAML format.
module Cardano.Configuration (
  -- * Configuration
  NodeConfiguration (..),
  resolveConfiguration,

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
  File.Hashed (..),
  CLI.Credentials (..),
  CLI.KESSource (..),

  -- ** Network
  File.NetworkConfiguration (..),
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

  -- * Configuration file
  File.NodeConfigurationFromFile,
  File.parseConfigurationFiles,
) where

import qualified Cardano.Configuration.CliArgs as CLI
import qualified Cardano.Configuration.Common as File
import qualified Cardano.Configuration.File as File
import Cardano.Configuration.File.Consensus
import qualified Cardano.Configuration.File.Consensus as File
import qualified Cardano.Configuration.File.Protocol as File
import qualified Cardano.Configuration.File.Storage as File
import Control.Applicative ((<|>))
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

-- | Combine the cli arguments and configuration file values into a full
-- configuration
resolveConfiguration :: CLI.CliArgs -> File.NodeConfigurationFromFile -> NodeConfiguration
resolveConfiguration cli file =
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
              (CLI.socketPath cli <|> File.pncSocketPath lcc)
              (CLI.enableRpcCLI cli <|> File.pncEnableRpc lcc)
              (CLI.rpcSocketPathCLI cli <|> File.pncRpcSocketPath lcc)
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
