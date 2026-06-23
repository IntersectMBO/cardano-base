-- | Configuration options related to networking
module Cardano.Configuration.File.Network (
  NetworkConfiguration (..),
  DiffusionMode (..),
  AcceptedConnectionsLimit (..),
  LocalConnectionsConfig (..),
  finalizeNetwork,
  finalizeLocalConnections,
) where

import Autodocodec
import Cardano.Configuration.Basic (diffTimeCodec, requireField)
import Cardano.Configuration.Common (filePathCodec)
import Data.Aeson (FromJSON, ToJSON)
import Data.Functor.Identity (Identity (..))
import Data.Time.Clock (DiffTime)
import Data.Word
import GHC.Generics (Generic)

-- | Whether the node runs as an initiator only, or as both an initiator and a
-- responder. Enumerated so the schema lists the valid values and typos are
-- caught at parse time.
data DiffusionMode
  = InitiatorOnly
  | InitiatorAndResponder
  deriving (Generic, Show, Eq, Enum, Bounded)
  deriving (FromJSON, ToJSON) via (Autodocodec DiffusionMode)

instance HasCodec DiffusionMode where
  codec = shownBoundedEnumCodec

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

-- | Options related to networking. Fields that have an always-applied default
-- (see @defaults\/Network.json@) carry the @f@ parameter; the deadline peer
-- targets and @PeerSharing@ only have defaults in the opt-in role variants and
-- so stay @Maybe@.
data NetworkConfiguration f = NetworkConfiguration
  { diffusionMode :: f DiffusionMode
  , maxConcurrencyBulkSync :: f Word
  , maxConcurrencyDeadline :: f Word
  , protocolIdleTimeout :: f DiffTime
  , timeWaitTimeout :: f DiffTime
  , egressPollInterval :: f DiffTime
  , chainSyncIdleTimeout :: f DiffTime
  , acceptedConnectionsLimit :: f AcceptedConnectionsLimit
  , deadlineTargetOfRootPeers :: Maybe Int
  , deadlineTargetOfKnownPeers :: Maybe Int
  , deadlineTargetOfEstablishedPeers :: Maybe Int
  , deadlineTargetOfActivePeers :: Maybe Int
  , deadlineTargetOfKnownBigLedgerPeers :: Maybe Int
  , deadlineTargetOfEstablishedBigLedgerPeers :: Maybe Int
  , deadlineTargetOfActiveBigLedgerPeers :: Maybe Int
  , syncTargetOfRootPeers :: f Int
  , syncTargetOfKnownPeers :: f Int
  , syncTargetOfEstablishedPeers :: f Int
  , syncTargetOfActivePeers :: f Int
  , syncTargetOfKnownBigLedgerPeers :: f Int
  , syncTargetOfEstablishedBigLedgerPeers :: f Int
  , syncTargetOfActiveBigLedgerPeers :: f Int
  , minBigLedgerPeersForTrustedState :: f Int
  , peerSharing :: Maybe Bool
  , responderCoreAffinityPolicy :: f String
  , experimentalProtocolsEnabled :: f Bool
  , txSubmissionLogicVersion :: f String
  , txSubmissionInitDelay :: f DiffTime
  }
  deriving (Generic)

deriving instance Show (NetworkConfiguration Maybe)
deriving instance Show (NetworkConfiguration Identity)

deriving via
  (Autodocodec (NetworkConfiguration Maybe))
  instance
    FromJSON (NetworkConfiguration Maybe)

deriving via
  (Autodocodec (NetworkConfiguration Maybe))
  instance
    ToJSON (NetworkConfiguration Maybe)

instance HasCodec (NetworkConfiguration Maybe) where
  codec =
    object "NetworkConfiguration" $
      NetworkConfiguration
        <$> optionalField "DiffusionMode" "Initiator-only or initiator-and-responder"
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

-- | Resolve a partial network configuration, taking the defaulted fields from
-- the (always-applied) base defaults.
finalizeNetwork :: NetworkConfiguration Maybe -> Either String (NetworkConfiguration Identity)
finalizeNetwork c = do
  diffusionMode' <- requireField "DiffusionMode" (diffusionMode c)
  maxBulk <- requireField "MaxConcurrencyBulkSync" (maxConcurrencyBulkSync c)
  maxDeadline <- requireField "MaxConcurrencyDeadline" (maxConcurrencyDeadline c)
  protocolIdle <- requireField "ProtocolIdleTimeout" (protocolIdleTimeout c)
  timeWait <- requireField "TimeWaitTimeout" (timeWaitTimeout c)
  egress <- requireField "EgressPollInterval" (egressPollInterval c)
  chainSyncIdle <- requireField "ChainSyncIdleTimeout" (chainSyncIdleTimeout c)
  acceptedLimit <- requireField "AcceptedConnectionsLimit" (acceptedConnectionsLimit c)
  syncRoot <- requireField "SyncTargetNumberOfRootPeers" (syncTargetOfRootPeers c)
  syncKnown <- requireField "SyncTargetNumberOfKnownPeers" (syncTargetOfKnownPeers c)
  syncEstablished <-
    requireField "SyncTargetNumberOfEstablishedPeers" (syncTargetOfEstablishedPeers c)
  syncActive <- requireField "SyncTargetNumberOfActivePeers" (syncTargetOfActivePeers c)
  syncKnownBig <-
    requireField "SyncTargetNumberOfKnownBigLedgerPeers" (syncTargetOfKnownBigLedgerPeers c)
  syncEstBig <-
    requireField "SyncTargetNumberOfEstablishedBigLedgerPeers" (syncTargetOfEstablishedBigLedgerPeers c)
  syncActiveBig <-
    requireField "SyncTargetNumberOfActiveBigLedgerPeers" (syncTargetOfActiveBigLedgerPeers c)
  minBigTrusted <-
    requireField "MinBigLedgerPeersForTrustedState" (minBigLedgerPeersForTrustedState c)
  responderCore <- requireField "ResponderCoreAffinityPolicy" (responderCoreAffinityPolicy c)
  experimental <- requireField "ExperimentalProtocolsEnabled" (experimentalProtocolsEnabled c)
  txLogic <- requireField "TxSubmissionLogicVersion" (txSubmissionLogicVersion c)
  txInitDelay <- requireField "TxSubmissionInitDelay" (txSubmissionInitDelay c)
  pure $
    NetworkConfiguration
      diffusionMode'
      maxBulk
      maxDeadline
      protocolIdle
      timeWait
      egress
      chainSyncIdle
      acceptedLimit
      (deadlineTargetOfRootPeers c)
      (deadlineTargetOfKnownPeers c)
      (deadlineTargetOfEstablishedPeers c)
      (deadlineTargetOfActivePeers c)
      (deadlineTargetOfKnownBigLedgerPeers c)
      (deadlineTargetOfEstablishedBigLedgerPeers c)
      (deadlineTargetOfActiveBigLedgerPeers c)
      syncRoot
      syncKnown
      syncEstablished
      syncActive
      syncKnownBig
      syncEstBig
      syncActiveBig
      minBigTrusted
      (peerSharing c)
      responderCore
      experimental
      txLogic
      txInitDelay

-- | Connections for local clients. @EnableRpc@ has a default; the socket paths
-- are optional.
data LocalConnectionsConfig f = LocalConnectionsConfig
  { socketPath :: Maybe FilePath
  , enableRpc :: f Bool
  , rpcSocketPath :: Maybe FilePath
  }
  deriving (Generic)

deriving instance Show (LocalConnectionsConfig Maybe)
deriving instance Show (LocalConnectionsConfig Identity)

deriving via
  (Autodocodec (LocalConnectionsConfig Maybe))
  instance
    FromJSON (LocalConnectionsConfig Maybe)

deriving via
  (Autodocodec (LocalConnectionsConfig Maybe))
  instance
    ToJSON (LocalConnectionsConfig Maybe)

instance HasCodec (LocalConnectionsConfig Maybe) where
  codec =
    object "LocalConnectionsConfig" $
      LocalConnectionsConfig
        <$> optionalFieldWith "SocketPath" filePathCodec "Path of the socket for local clients" .= socketPath
        <*> optionalField "EnableRpc" "Whether to enable the gRPC server" .= enableRpc
        <*> optionalFieldWith "RpcSocketPath" filePathCodec "Path of the gRPC server socket" .= rpcSocketPath

-- | Resolve a partial local-connections configuration, taking @EnableRpc@ from
-- the (always-applied) defaults.
finalizeLocalConnections ::
  LocalConnectionsConfig Maybe -> Either String (LocalConnectionsConfig Identity)
finalizeLocalConnections c = do
  rpc <- requireField "EnableRpc" (enableRpc c)
  pure $ LocalConnectionsConfig (socketPath c) rpc (rpcSocketPath c)
