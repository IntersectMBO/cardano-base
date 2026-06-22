-- | Configuration options related to networking
module Cardano.Configuration.File.Network (
  NetworkConfiguration (..),
  AcceptedConnectionsLimit (..),
  LocalConnectionsConfig (..),
) where

import Autodocodec
import Cardano.Configuration.Basic (diffTimeCodec)
import Data.Aeson (FromJSON, ToJSON)
import Data.Time.Clock (DiffTime)
import Data.Word
import GHC.Generics (Generic)

-- | Limits on the number of accepted connections.
data AcceptedConnectionsLimit = AcceptedConnectionsLimit Word32 Word32 DiffTime
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec AcceptedConnectionsLimit)

instance HasCodec AcceptedConnectionsLimit where
  codec =
    object "AcceptedConnectionsLimit" $
      AcceptedConnectionsLimit
        <$> requiredField "hardLimit" "Hard limit on the number of connections"
          .= (\(AcceptedConnectionsLimit h _ _) -> h)
        <*> requiredField "softLimit" "Soft limit on the number of connections"
          .= (\(AcceptedConnectionsLimit _ s _) -> s)
        <*> requiredFieldWith "delay" diffTimeCodec "Delay, in seconds, applied once the soft limit is reached"
          .= (\(AcceptedConnectionsLimit _ _ d) -> d)

-- | Options related to Networking configuration. Most of the fields are
-- @Maybe@ such that the networking layer can then set the appropriate
-- defaults.
data NetworkConfiguration = NetworkConfiguration
  { diffusionMode :: String
  , maxConcurrencyBulkSync :: Maybe Word
  , maxConcurrencyDeadline :: Maybe Word
  , protocolIdleTimeout :: Maybe DiffTime
  , timeWaitTimeout :: Maybe DiffTime
  , egressPollInterval :: Maybe DiffTime
  , chainSyncIdleTimeout :: Maybe DiffTime
  , acceptedConnectionsLimit :: Maybe AcceptedConnectionsLimit
  , deadlineTargetOfRootPeers :: Maybe Int
  , deadlineTargetOfKnownPeers :: Maybe Int
  , deadlineTargetOfEstablishedPeers :: Maybe Int
  , deadlineTargetOfActivePeers :: Maybe Int
  , deadlineTargetOfKnownBigLedgerPeers :: Maybe Int
  , deadlineTargetOfEstablishedBigLedgerPeers :: Maybe Int
  , deadlineTargetOfActiveBigLedgerPeers :: Maybe Int
  , syncTargetOfRootPeers :: Maybe Int
  , syncTargetOfKnownPeers :: Maybe Int
  , syncTargetOfEstablishedPeers :: Maybe Int
  , syncTargetOfActivePeers :: Maybe Int
  , syncTargetOfKnownBigLedgerPeers :: Maybe Int
  , syncTargetOfEstablishedBigLedgerPeers :: Maybe Int
  , syncTargetOfActiveBigLedgerPeers :: Maybe Int
  , minBigLedgerPeersForTrustedState :: Maybe Int
  , peerSharing :: Maybe Bool
  , responderCoreAffinityPolicy :: Maybe String
  , experimentalProtocolsEnabled :: Maybe Bool
  , txSubmissionLogicVersion :: Maybe String
  , txSubmissionInitDelay :: Maybe DiffTime
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec NetworkConfiguration)

instance HasCodec NetworkConfiguration where
  codec =
    object "NetworkConfiguration" $
      NetworkConfiguration
        <$> optionalFieldWithDefault
          "DiffusionMode"
          "InitiatorAndResponder"
          "Initiator-only or initiator-and-responder"
          .= diffusionMode
        <*> optionalField "MaxConcurrencyBulkSync" "Bulk-sync block-fetch concurrency"
          .= maxConcurrencyBulkSync
        <*> optionalField "MaxConcurrencyDeadline" "Deadline block-fetch concurrency"
          .= maxConcurrencyDeadline
        <*> optionalFieldWith "ProtocolIdleTimeout" diffTimeCodec "Protocol idle timeout, in seconds"
          .= protocolIdleTimeout
        <*> optionalFieldWith "TimeWaitTimeout" diffTimeCodec "TIME-WAIT timeout, in seconds"
          .= timeWaitTimeout
        <*> optionalFieldWith "EgressPollInterval" diffTimeCodec "Egress poll interval, in seconds"
          .= egressPollInterval
        <*> optionalFieldWith "ChainSyncIdleTimeout" diffTimeCodec "ChainSync idle timeout, in seconds"
          .= chainSyncIdleTimeout
        <*> optionalField "AcceptedConnectionsLimit" "Limits on accepted connections"
          .= acceptedConnectionsLimit
        <*> optionalField "TargetNumberOfRootPeers" "Deadline target of root peers"
          .= deadlineTargetOfRootPeers
        <*> optionalField "TargetNumberOfKnownPeers" "Deadline target of known peers"
          .= deadlineTargetOfKnownPeers
        <*> optionalField "TargetNumberOfEstablishedPeers" "Deadline target of established peers"
          .= deadlineTargetOfEstablishedPeers
        <*> optionalField "TargetNumberOfActivePeers" "Deadline target of active peers"
          .= deadlineTargetOfActivePeers
        <*> optionalField "TargetNumberOfKnownBigLedgerPeers" "Deadline target of known big ledger peers"
          .= deadlineTargetOfKnownBigLedgerPeers
        <*> optionalField
          "TargetNumberOfEstablishedBigLedgerPeers"
          "Deadline target of established big ledger peers"
          .= deadlineTargetOfEstablishedBigLedgerPeers
        <*> optionalField "TargetNumberOfActiveBigLedgerPeers" "Deadline target of active big ledger peers"
          .= deadlineTargetOfActiveBigLedgerPeers
        <*> optionalField "SyncTargetNumberOfRootPeers" "Sync target of root peers" .= syncTargetOfRootPeers
        <*> optionalField "SyncTargetNumberOfKnownPeers" "Sync target of known peers"
          .= syncTargetOfKnownPeers
        <*> optionalField "SyncTargetNumberOfEstablishedPeers" "Sync target of established peers"
          .= syncTargetOfEstablishedPeers
        <*> optionalField "SyncTargetNumberOfActivePeers" "Sync target of active peers"
          .= syncTargetOfActivePeers
        <*> optionalField "SyncTargetNumberOfKnownBigLedgerPeers" "Sync target of known big ledger peers"
          .= syncTargetOfKnownBigLedgerPeers
        <*> optionalField
          "SyncTargetNumberOfEstablishedBigLedgerPeers"
          "Sync target of established big ledger peers"
          .= syncTargetOfEstablishedBigLedgerPeers
        <*> optionalField "SyncTargetNumberOfActiveBigLedgerPeers" "Sync target of active big ledger peers"
          .= syncTargetOfActiveBigLedgerPeers
        <*> optionalField "MinBigLedgerPeersForTrustedState" "Minimum big ledger peers for trusted state"
          .= minBigLedgerPeersForTrustedState
        <*> optionalField "PeerSharing" "Whether to enable peer sharing" .= peerSharing
        <*> optionalField "ResponderCoreAffinityPolicy" "Whether responders are pinned to a core"
          .= responderCoreAffinityPolicy
        <*> optionalField "ExperimentalProtocolsEnabled" "Enable experimental network protocols"
          .= experimentalProtocolsEnabled
        <*> optionalField "TxSubmissionLogicVersion" "Which tx-submission inbound logic to run"
          .= txSubmissionLogicVersion
        <*> optionalFieldWith "TxSubmissionInitDelay" diffTimeCodec "Tx-submission initial delay, in seconds"
          .= txSubmissionInitDelay

-- | Connections for local clients
data LocalConnectionsConfig = LocalConnectionsConfig
  { socketPath :: Maybe FilePath
  , enableRpc :: Maybe Bool
  , rpcSocketPath :: Maybe FilePath
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec LocalConnectionsConfig)

instance HasCodec LocalConnectionsConfig where
  codec =
    object "LocalConnectionsConfig" $
      LocalConnectionsConfig
        <$> optionalField "SocketPath" "Path of the socket for local clients" .= socketPath
        <*> optionalField "EnableRpc" "Whether to enable the gRPC server" .= enableRpc
        <*> optionalField "RpcSocketPath" "Path of the gRPC server socket" .= rpcSocketPath
