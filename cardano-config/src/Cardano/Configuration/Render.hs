-- | Render a resolved 'NodeConfiguration' as a JSON 'Value' that uses the
-- documented configuration keys (the same ones accepted on input), rather than
-- the Haskell record/constructor names. Intended for human-facing output (e.g.
-- dumping the resolved configuration as YAML); it is not a canonical encoding and
-- there is no matching parser.
--
-- Each component is rendered by lifting its resolved (@Identity@) form back into
-- the @Maybe@-parameterised form and reusing that form's 'ToJSON' instance, so
-- the keys stay in sync with the parsers. The operational arguments that come
-- only from the CLI (credentials, host\/port, shutdown, …) are grouped under a
-- @Runtime@ key.
module Cardano.Configuration.Render (
  nodeConfigurationToJSON,
) where

import Cardano.Configuration (NodeConfiguration (..))
import qualified Cardano.Configuration.CliArgs as CLI
import qualified Cardano.Configuration.File as File
import Data.Aeson (Value, object, toJSON, (.=))
import Data.Functor.Identity (Identity, runIdentity)
import Data.Maybe (catMaybes)

-- | Render the complete resolved configuration: each component under its name,
-- plus the operational CLI-only arguments under @Runtime@.
nodeConfigurationToJSON :: NodeConfiguration -> Value
nodeConfigurationToJSON nc =
  object
    [ "Storage" .= toJSON (weakenStorage (storageConfiguration nc))
    , "Consensus" .= toJSON (weakenConsensus (consensusConfiguration nc))
    , "Protocol" .= toJSON (weakenProtocol (protocolConfiguration nc))
    , "Network" .= toJSON (weakenNetwork (networkConfiguration nc))
    , "LocalConnections" .= toJSON (weakenLocalConnections (localConnectionsConfig nc))
    , "Mempool" .= toJSON (weakenMempool (mempoolConfiguration nc))
    , "Testing" .= toJSON (weakenTesting (testingConfiguration nc))
    , "Runtime" .= runtimeValue nc
    ]

-- | Lift a resolved (@Identity@) field back into the @Maybe@-parameterised form
-- the component's 'ToJSON' instance expects.
j :: Identity a -> Maybe a
j = Just . runIdentity

weakenStorage :: File.StorageConfiguration Identity -> File.StorageConfiguration Maybe
weakenStorage s =
  File.StorageConfiguration
    { File.databasePath = j (File.databasePath s)
    , File.ledgerDbConfiguration = j (File.ledgerDbConfiguration s)
    }

weakenConsensus :: File.ConsensusConfiguration Identity -> File.ConsensusConfiguration Maybe
weakenConsensus c =
  File.ConsensusConfiguration {File.getConsensusConfiguration = j (File.getConsensusConfiguration c)}

weakenProtocol :: File.ProtocolConfiguration Identity -> File.ProtocolConfiguration Maybe
weakenProtocol p =
  File.ProtocolConfiguration
    { File.byronGenesis = File.byronGenesis p
    , File.shelleyGenesis = File.shelleyGenesis p
    , File.alonzoGenesis = File.alonzoGenesis p
    , File.conwayGenesis = File.conwayGenesis p
    , File.startAsNonProducingNode = j (File.startAsNonProducingNode p)
    , File.checkpointsFile = File.checkpointsFile p
    }

weakenNetwork :: File.NetworkConfiguration Identity -> File.NetworkConfiguration Maybe
weakenNetwork n =
  File.NetworkConfiguration
    { File.diffusionMode = j (File.diffusionMode n)
    , File.maxConcurrencyBulkSync = j (File.maxConcurrencyBulkSync n)
    , File.maxConcurrencyDeadline = j (File.maxConcurrencyDeadline n)
    , File.protocolIdleTimeout = j (File.protocolIdleTimeout n)
    , File.timeWaitTimeout = j (File.timeWaitTimeout n)
    , File.egressPollInterval = j (File.egressPollInterval n)
    , File.chainSyncIdleTimeout = j (File.chainSyncIdleTimeout n)
    , File.acceptedConnectionsLimit = j (File.acceptedConnectionsLimit n)
    , File.deadlineTargetOfRootPeers = File.deadlineTargetOfRootPeers n
    , File.deadlineTargetOfKnownPeers = File.deadlineTargetOfKnownPeers n
    , File.deadlineTargetOfEstablishedPeers = File.deadlineTargetOfEstablishedPeers n
    , File.deadlineTargetOfActivePeers = File.deadlineTargetOfActivePeers n
    , File.deadlineTargetOfKnownBigLedgerPeers = File.deadlineTargetOfKnownBigLedgerPeers n
    , File.deadlineTargetOfEstablishedBigLedgerPeers = File.deadlineTargetOfEstablishedBigLedgerPeers n
    , File.deadlineTargetOfActiveBigLedgerPeers = File.deadlineTargetOfActiveBigLedgerPeers n
    , File.syncTargetOfRootPeers = j (File.syncTargetOfRootPeers n)
    , File.syncTargetOfKnownPeers = j (File.syncTargetOfKnownPeers n)
    , File.syncTargetOfEstablishedPeers = j (File.syncTargetOfEstablishedPeers n)
    , File.syncTargetOfActivePeers = j (File.syncTargetOfActivePeers n)
    , File.syncTargetOfKnownBigLedgerPeers = j (File.syncTargetOfKnownBigLedgerPeers n)
    , File.syncTargetOfEstablishedBigLedgerPeers = j (File.syncTargetOfEstablishedBigLedgerPeers n)
    , File.syncTargetOfActiveBigLedgerPeers = j (File.syncTargetOfActiveBigLedgerPeers n)
    , File.minBigLedgerPeersForTrustedState = j (File.minBigLedgerPeersForTrustedState n)
    , File.peerSharing = File.peerSharing n
    , File.responderCoreAffinityPolicy = j (File.responderCoreAffinityPolicy n)
    , File.experimentalProtocolsEnabled = j (File.experimentalProtocolsEnabled n)
    , File.txSubmissionLogicVersion = j (File.txSubmissionLogicVersion n)
    , File.txSubmissionInitDelay = j (File.txSubmissionInitDelay n)
    }

weakenLocalConnections :: File.LocalConnectionsConfig Identity -> File.LocalConnectionsConfig Maybe
weakenLocalConnections l =
  File.LocalConnectionsConfig
    { File.socketPath = File.socketPath l
    , File.enableRpc = j (File.enableRpc l)
    , File.rpcSocketPath = File.rpcSocketPath l
    }

weakenTesting :: File.TestingConfiguration Identity -> File.TestingConfiguration Maybe
weakenTesting t =
  File.TestingConfiguration
    { File.experimentalHardForksEnabled = j (File.experimentalHardForksEnabled t)
    , File.testShelleyHardForkAtEpoch = File.testShelleyHardForkAtEpoch t
    , File.testShelleyHardForkAtVersion = File.testShelleyHardForkAtVersion t
    , File.testAllegraHardForkAtEpoch = File.testAllegraHardForkAtEpoch t
    , File.testAllegraHardForkAtVersion = File.testAllegraHardForkAtVersion t
    , File.testMaryHardForkAtEpoch = File.testMaryHardForkAtEpoch t
    , File.testMaryHardForkAtVersion = File.testMaryHardForkAtVersion t
    , File.testAlonzoHardForkAtEpoch = File.testAlonzoHardForkAtEpoch t
    , File.testAlonzoHardForkAtVersion = File.testAlonzoHardForkAtVersion t
    , File.testBabbageHardForkAtEpoch = File.testBabbageHardForkAtEpoch t
    , File.testBabbageHardForkAtVersion = File.testBabbageHardForkAtVersion t
    , File.testConwayHardForkAtEpoch = File.testConwayHardForkAtEpoch t
    , File.testConwayHardForkAtVersion = File.testConwayHardForkAtVersion t
    , File.testDijkstraHardForkAtEpoch = File.testDijkstraHardForkAtEpoch t
    , File.testDijkstraHardForkAtVersion = File.testDijkstraHardForkAtVersion t
    , File.experimentalGenesis = File.experimentalGenesis t
    }

weakenMempool :: File.MempoolConfiguration Identity -> File.MempoolConfiguration Maybe
weakenMempool m =
  File.MempoolConfiguration
    { File.mempoolCapacityOverride = File.mempoolCapacityOverride m
    , File.mempoolTimeoutSoft = File.mempoolTimeoutSoft m
    , File.mempoolTimeoutHard = File.mempoolTimeoutHard m
    , File.mempoolTimeoutCapacity = File.mempoolTimeoutCapacity m
    }

-- | The operational arguments that come only from the CLI. Unset optional values
-- are omitted.
runtimeValue :: NodeConfiguration -> Value
runtimeValue nc =
  object $
    [ "ConfigFile" .= configFilePath nc
    , "TopologyFile" .= topologyFile nc
    , "ValidateDatabase" .= validateDatabase nc
    , "Credentials" .= credentialsValue (credentials nc)
    ]
      <> catMaybes
        [ ("HostAddr" .=) . show <$> hostAddr nc
        , ("HostIPv6Addr" .=) . show <$> hostIPv6Addr nc
        , ("Port" .=) . portNumber <$> port nc
        , ("TracerSocket" .=) . tracerConnectionValue <$> tracerSocket nc
        , ("ShutdownIPC" .=) . fdNumber <$> shutdownIPC nc
        , ("ShutdownOn" .=) . shutdownOnValue <$> shutdownOnTarget nc
        ]
  where
    portNumber p = toJSON (fromIntegral p :: Integer)
    fdNumber fd = toJSON (fromIntegral fd :: Integer)

credentialsValue :: CLI.Credentials -> Value
credentialsValue c =
  object $
    catMaybes
      [ ("ByronDelegationCertificate" .=) <$> CLI.byronDelegationCertificate c
      , ("ByronSigningKey" .=) <$> CLI.byronSigningKey c
      , ("ShelleyKES" .=) . kesSourceValue <$> CLI.shelleyKES c
      , ("ShelleyVRFKey" .=) <$> CLI.shelleyVRFKey c
      , ("ShelleyOperationalCertificate" .=) <$> CLI.shelleyOperationalCertificate c
      , ("BulkCredentialsFile" .=) <$> CLI.bulkCredentialsFile c
      ]

kesSourceValue :: CLI.KESSource -> Value
kesSourceValue = \case
  CLI.KESKeyFilePath p -> object ["KeyFile" .= p]
  CLI.KESAgentSocketPath p -> object ["AgentSocket" .= p]

tracerConnectionValue :: CLI.TracerConnection -> Value
tracerConnectionValue (CLI.TracerConnection name method) =
  object ["Name" .= name, "Method" .= methodValue method]
  where
    methodValue :: CLI.TracerConnectionMethod -> Value
    methodValue = \case
      CLI.TracerConnectViaPipe p -> object ["Pipe" .= p]
      CLI.TracerConnectViaRemote host p ->
        object ["Host" .= host, "Port" .= (fromIntegral p :: Integer)]

shutdownOnValue :: CLI.ShutdownOn -> Value
shutdownOnValue = \case
  CLI.ShutdownAtSlot n -> object ["AtSlot" .= n]
  CLI.ShutdownAtBlock n -> object ["AtBlock" .= n]
