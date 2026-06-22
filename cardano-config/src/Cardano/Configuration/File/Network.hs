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
  { pncDiffusionMode :: String
  , pncMaxConcurrencyBulkSync :: Maybe Word
  , pncMaxConcurrencyDeadline :: Maybe Word
  , pncProtocolIdleTimeout :: Maybe DiffTime
  , pncTimeWaitTimeout :: Maybe DiffTime
  , pncEgressPollInterval :: Maybe DiffTime
  , pncChainSyncIdleTimeout :: Maybe DiffTime
  , pncAcceptedConnectionsLimit :: Maybe AcceptedConnectionsLimit
  , pncDeadlineTargetOfRootPeers :: Maybe Int
  , pncDeadlineTargetOfKnownPeers :: Maybe Int
  , pncDeadlineTargetOfEstablishedPeers :: Maybe Int
  , pncDeadlineTargetOfActivePeers :: Maybe Int
  , pncDeadlineTargetOfKnownBigLedgerPeers :: Maybe Int
  , pncDeadlineTargetOfEstablishedBigLedgerPeers :: Maybe Int
  , pncDeadlineTargetOfActiveBigLedgerPeers :: Maybe Int
  , pncSyncTargetOfRootPeers :: Maybe Int
  , pncSyncTargetOfKnownPeers :: Maybe Int
  , pncSyncTargetOfEstablishedPeers :: Maybe Int
  , pncSyncTargetOfActivePeers :: Maybe Int
  , pncSyncTargetOfKnownBigLedgerPeers :: Maybe Int
  , pncSyncTargetOfEstablishedBigLedgerPeers :: Maybe Int
  , pncSyncTargetOfActiveBigLedgerPeers :: Maybe Int
  , pncMinBigLedgerPeersForTrustedState :: Maybe Int
  , pncPeerSharing :: Maybe Bool
  , pncResponderCoreAffinityPolicy :: Maybe String
  , pncExperimentalProtocolsEnabled :: Maybe Bool
  , pncTxSubmissionLogicVersion :: Maybe String
  , pncTxSubmissionInitDelay :: Maybe DiffTime
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
          .= pncDiffusionMode
        <*> optionalField "MaxConcurrencyBulkSync" "Bulk-sync block-fetch concurrency"
          .= pncMaxConcurrencyBulkSync
        <*> optionalField "MaxConcurrencyDeadline" "Deadline block-fetch concurrency"
          .= pncMaxConcurrencyDeadline
        <*> optionalFieldWith "ProtocolIdleTimeout" diffTimeCodec "Protocol idle timeout, in seconds"
          .= pncProtocolIdleTimeout
        <*> optionalFieldWith "TimeWaitTimeout" diffTimeCodec "TIME-WAIT timeout, in seconds"
          .= pncTimeWaitTimeout
        <*> optionalFieldWith "EgressPollInterval" diffTimeCodec "Egress poll interval, in seconds"
          .= pncEgressPollInterval
        <*> optionalFieldWith "ChainSyncIdleTimeout" diffTimeCodec "ChainSync idle timeout, in seconds"
          .= pncChainSyncIdleTimeout
        <*> optionalField "AcceptedConnectionsLimit" "Limits on accepted connections"
          .= pncAcceptedConnectionsLimit
        <*> optionalField "TargetNumberOfRootPeers" "Deadline target of root peers"
          .= pncDeadlineTargetOfRootPeers
        <*> optionalField "TargetNumberOfKnownPeers" "Deadline target of known peers"
          .= pncDeadlineTargetOfKnownPeers
        <*> optionalField "TargetNumberOfEstablishedPeers" "Deadline target of established peers"
          .= pncDeadlineTargetOfEstablishedPeers
        <*> optionalField "TargetNumberOfActivePeers" "Deadline target of active peers"
          .= pncDeadlineTargetOfActivePeers
        <*> optionalField "TargetNumberOfKnownBigLedgerPeers" "Deadline target of known big ledger peers"
          .= pncDeadlineTargetOfKnownBigLedgerPeers
        <*> optionalField
          "TargetNumberOfEstablishedBigLedgerPeers"
          "Deadline target of established big ledger peers"
          .= pncDeadlineTargetOfEstablishedBigLedgerPeers
        <*> optionalField "TargetNumberOfActiveBigLedgerPeers" "Deadline target of active big ledger peers"
          .= pncDeadlineTargetOfActiveBigLedgerPeers
        <*> optionalField "SyncTargetNumberOfRootPeers" "Sync target of root peers" .= pncSyncTargetOfRootPeers
        <*> optionalField "SyncTargetNumberOfKnownPeers" "Sync target of known peers"
          .= pncSyncTargetOfKnownPeers
        <*> optionalField "SyncTargetNumberOfEstablishedPeers" "Sync target of established peers"
          .= pncSyncTargetOfEstablishedPeers
        <*> optionalField "SyncTargetNumberOfActivePeers" "Sync target of active peers"
          .= pncSyncTargetOfActivePeers
        <*> optionalField "SyncTargetNumberOfKnownBigLedgerPeers" "Sync target of known big ledger peers"
          .= pncSyncTargetOfKnownBigLedgerPeers
        <*> optionalField
          "SyncTargetNumberOfEstablishedBigLedgerPeers"
          "Sync target of established big ledger peers"
          .= pncSyncTargetOfEstablishedBigLedgerPeers
        <*> optionalField "SyncTargetNumberOfActiveBigLedgerPeers" "Sync target of active big ledger peers"
          .= pncSyncTargetOfActiveBigLedgerPeers
        <*> optionalField "MinBigLedgerPeersForTrustedState" "Minimum big ledger peers for trusted state"
          .= pncMinBigLedgerPeersForTrustedState
        <*> optionalField "PeerSharing" "Whether to enable peer sharing" .= pncPeerSharing
        <*> optionalField "ResponderCoreAffinityPolicy" "Whether responders are pinned to a core"
          .= pncResponderCoreAffinityPolicy
        <*> optionalField "ExperimentalProtocolsEnabled" "Enable experimental network protocols"
          .= pncExperimentalProtocolsEnabled
        <*> optionalField "TxSubmissionLogicVersion" "Which tx-submission inbound logic to run"
          .= pncTxSubmissionLogicVersion
        <*> optionalFieldWith "TxSubmissionInitDelay" diffTimeCodec "Tx-submission initial delay, in seconds"
          .= pncTxSubmissionInitDelay

-- | Connections for local clients
data LocalConnectionsConfig = LocalConnectionsConfig
  { pncSocketPath :: Maybe FilePath
  , pncEnableRpc :: Maybe Bool
  , pncRpcSocketPath :: Maybe FilePath
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec LocalConnectionsConfig)

instance HasCodec LocalConnectionsConfig where
  codec =
    object "LocalConnectionsConfig" $
      LocalConnectionsConfig
        <$> optionalField "SocketPath" "Path of the socket for local clients" .= pncSocketPath
        <*> optionalField "EnableRpc" "Whether to enable the gRPC server" .= pncEnableRpc
        <*> optionalField "RpcSocketPath" "Path of the gRPC server socket" .= pncRpcSocketPath
