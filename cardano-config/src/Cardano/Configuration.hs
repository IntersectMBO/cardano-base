-- | Parse the configuration for a @cardano-node@, combining both the
-- t'Cardano.Configuration.CliArgs' and the
-- t'Cardano.Configuration.NodeConfigurationFromFile'
--
-- The configuration file can be either in JSON or in YAML format.
module Cardano.Configuration (
  -- * Configuration
  NodeConfiguration (..),
  resolveConfiguration,
  resolveConfigurationWith,

  -- ** Consistency checks
  ConfigCheck (..),
  defaultConfigChecks,
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
import Data.List.NonEmpty (NonEmpty (..))
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

-- | A single consistency check over a resolved 'NodeConfiguration': an
-- invariant that must hold, together with a description used when it fails.
-- Consumers can define their own and pass them to 'resolveConfigurationWith'.
data ConfigCheck = ConfigCheck
  { checkDescription :: String
  -- ^ A description of the invariant, phrased as what must hold (used in the
  -- error message when it does not).
  , checkHolds :: NodeConfiguration -> Bool
  -- ^ The invariant. 'True' means the configuration satisfies it.
  }

-- | An error detected while resolving the configuration: one or more
-- consistency checks failed on a configuration whose individual values were
-- each well-formed. Carries the descriptions of the violated checks.
newtype ConfigResolutionError = ConfigResolutionError
  { violatedChecks :: NonEmpty String
  }
  deriving (Eq, Show)

instance Exception ConfigResolutionError

-- | The built-in consistency checks applied by 'resolveConfiguration'. Exported
-- so consumers can extend them, e.g.
-- @'resolveConfigurationWith' (defaultConfigChecks <> myChecks)@.
defaultConfigChecks :: [ConfigCheck]
defaultConfigChecks =
  [ ConfigCheck
      "enabling the gRPC endpoint requires a gRPC socket path, or a node socket path to derive one from"
      ( \nc ->
          let lcc = localConnectionsConfig nc
           in not
                ( File.enableRpc lcc == Just True
                    && isNothing (File.rpcSocketPath lcc)
                    && isNothing (File.socketPath lcc)
                )
      )
  , ConfigCheck
      "the Mithril snapshot policy requires the V2LSM backend with an LSMExportPath, or the V2InMemory backend"
      ( \nc ->
          let ldb = runIdentity (File.ledgerDbConfiguration (storageConfiguration nc))
           in case File.snapshots ldb of
                Just (File.NamedSnapshotPolicy "Mithril") ->
                  case File.backendSelector ldb of
                    File.V2InMemory -> True
                    File.V2LSM _ exportPath -> isJust exportPath
                _ -> True
      )
  ]

-- | Run a set of consistency checks over a resolved configuration, collecting
-- the descriptions of every check that fails.
runConfigChecks :: [ConfigCheck] -> NodeConfiguration -> Either ConfigResolutionError NodeConfiguration
runConfigChecks checks nc =
  case [checkDescription c | c <- checks, not (checkHolds c nc)] of
    [] -> Right nc
    (violation : violations) -> Left (ConfigResolutionError (violation :| violations))

-- | Combine the cli arguments and configuration file values into a full
-- configuration, then check it with 'defaultConfigChecks'. CLI values take
-- precedence over file values.
resolveConfiguration ::
  CLI.CliArgs -> File.NodeConfigurationFromFile -> Either ConfigResolutionError NodeConfiguration
resolveConfiguration = resolveConfigurationWith defaultConfigChecks

-- | As 'resolveConfiguration', but with an explicit set of consistency checks,
-- so consumers can add their own (typically @'defaultConfigChecks' <> myChecks@).
resolveConfigurationWith ::
  [ConfigCheck] ->
  CLI.CliArgs ->
  File.NodeConfigurationFromFile ->
  Either ConfigResolutionError NodeConfiguration
resolveConfigurationWith checks cli file =
  runConfigChecks checks $
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
