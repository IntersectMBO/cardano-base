-- | Options related to storage
module Cardano.Configuration.File.Storage (
  adjustDbPath,
  StorageConfiguration (..),

  -- * LedgerDB
  LedgerDbConfiguration (..),

  -- ** Snapshots
  SnapshotPolicy (..),
  SnapshotOptions (..),

  -- ** Backend
  LedgerDbBackendSelector (..),
) where

import Autodocodec
import Cardano.Configuration.Common
import Data.Aeson (FromJSON, ToJSON)
import Data.Default
import Data.Functor.Identity
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word
import GHC.Generics

-- | A non-zero snapshot interval, in slots: the node rejects 0.
snapshotIntervalCodec :: JSONCodec Word64
snapshotIntervalCodec = bimapCodec validate id codec
  where
    validate 0 = Left "Non-positive SnapshotInterval: 0"
    validate w = Right w

-- | An explicit set of snapshot policy options. All fields are optional; when
-- unset the node applies its own defaults.
data SnapshotOptions = SnapshotOptions
  { snapshotInterval :: Maybe Word64
  -- ^ How many slots between attempts to write a snapshot to disk (non-zero).
  , slotOffset :: Maybe Word64
  -- ^ The slot at which the snapshot schedule is anchored: snapshots are taken
  -- at @slotOffset + n * snapshotInterval@.
  , snapshotRateLimit :: Maybe Word64
  -- ^ The minimum wall-clock time, in seconds, between two snapshots.
  , minDelay :: Maybe Word64
  -- ^ Lower bound, in seconds, of the random delay before taking a snapshot.
  , maxDelay :: Maybe Word64
  -- ^ Upper bound, in seconds, of the random delay before taking a snapshot.
  , numOfDiskSnapshots :: Maybe Word64
  -- ^ How many snapshots the node should keep on disk.
  }
  deriving (Generic, Show)

instance HasCodec SnapshotOptions where
  codec =
    bimapCodec validateDelays id $
      object "SnapshotOptions" $
        SnapshotOptions
          <$> optionalFieldWith "SnapshotInterval" snapshotIntervalCodec "Slots between snapshots (non-zero)"
            .= snapshotInterval
          <*> optionalField "SlotOffset" "Slot at which the snapshot schedule is anchored" .= slotOffset
          <*> optionalField "RateLimit" "Minimum seconds between snapshots" .= snapshotRateLimit
          <*> optionalField "MinDelay" "Lower bound (seconds) of the random snapshot delay" .= minDelay
          <*> optionalField "MaxDelay" "Upper bound (seconds) of the random snapshot delay" .= maxDelay
          <*> optionalField "NumOfDiskSnapshots" "How many snapshots to keep on disk" .= numOfDiskSnapshots
    where
      validateDelays so@SnapshotOptions {minDelay = Just lo, maxDelay = Just hi}
        | lo > hi =
            Left $ "Invalid snapshot delay range, MinDelay > MaxDelay: " <> show lo <> " > " <> show hi
        | otherwise = Right so
      validateDelays so = Right so

-- | The snapshot policy: either the predefined @"Mithril"@ policy (the only
-- named policy currently accepted) or an explicit set of options.
data SnapshotPolicy
  = MithrilSnapshotPolicy
  | CustomSnapshotPolicy SnapshotOptions
  deriving (Generic, Show)

-- | The Mithril policy is the JSON string @"Mithril"@ (and nothing else); a
-- custom policy is a JSON object. We dispatch on that shape so that, when an
-- object is supplied, a validation failure inside 'SnapshotOptions' is reported
-- on its own rather than alongside the irrelevant other-branch failure. Using a
-- literal @"Mithril"@ codec (rather than an arbitrary string) means any other
-- string is rejected at parse time, and the schema lists @"Mithril"@ as the only
-- accepted value.
instance HasCodec SnapshotPolicy where
  codec =
    matchChoiceCodec
      (literalTextValueCodec MithrilSnapshotPolicy "Mithril")
      (dimapCodec CustomSnapshotPolicy id (codec @SnapshotOptions))
      selector
    where
      selector MithrilSnapshotPolicy = Left MithrilSnapshotPolicy
      selector (CustomSnapshotPolicy o) = Right o

-- | Selector for the backend that keeps track of differences in the UTxO set.
data LedgerDbBackendSelector
  = -- | The in-memory backend.
    V2InMemory
  | -- | The LSM-tree backend. The first field is an optional custom path to the
    -- database (the @LSMDatabasePath@ key); if it is not provided, the default
    -- is used. The second field is an optional directory into which the backend
    -- exports snapshots as it takes them (the @LSMExportPath@ key). Both are
    -- only meaningful for the LSM backend.
    V2LSM (Maybe FilePath) (Maybe FilePath)
  deriving (Generic, Show)

instance Default LedgerDbBackendSelector where
  def = V2InMemory

-- | The @Backend@, @LSMDatabasePath@ and @LSMExportPath@ keys, parsed together
-- as they describe a single choice of backend. @Backend@ is optional here (its
-- default, @V2InMemory@, comes from @defaults/Storage.json@, not the codec), so
-- the result is 'Nothing' when the key is absent.
backendCodec :: JSONObjectCodec (Maybe LedgerDbBackendSelector)
backendCodec =
  bimapCodec toSelector fromSelector $
    (,,)
      <$> optionalFieldWith "Backend" (codec @Text) "Which LedgerDB backend to use (V2InMemory or V2LSM)"
        .= (\(b, _, _) -> b)
      <*> optionalFieldWith "LSMDatabasePath" filePathCodec "Custom path to the LSM database (V2LSM only)"
        .= (\(_, p, _) -> p)
      <*> optionalFieldWith "LSMExportPath" filePathCodec "Directory into which the LSM backend exports snapshots (V2LSM only)"
        .= (\(_, _, e) -> e)
  where
    toSelector (Nothing, _, _) = Right Nothing
    toSelector (Just "V2InMemory", _, _) = Right (Just V2InMemory)
    toSelector (Just "V2LSM", p, e) = Right (Just (V2LSM p e))
    toSelector (Just other, _, _) = Left $ "Malformed LedgerDB Backend: " <> T.unpack other
    fromSelector Nothing = (Nothing, Nothing, Nothing)
    fromSelector (Just V2InMemory) = (Just "V2InMemory", Nothing, Nothing)
    fromSelector (Just (V2LSM p e)) = (Just "V2LSM", p, e)

-- | The Ledger DB configuration
data LedgerDbConfiguration = LedgerDbConfiguration
  { snapshots :: Maybe SnapshotPolicy
  , queryBatchSize :: Maybe Word64
  , backendSelector :: Maybe LedgerDbBackendSelector
  }
  deriving (Generic, Show)
  deriving (FromJSON, ToJSON) via (Autodocodec LedgerDbConfiguration)

instance HasCodec LedgerDbConfiguration where
  codec =
    object "LedgerDB" $
      LedgerDbConfiguration
        <$> optionalField "Snapshots" "Snapshot policy: \"Mithril\" or an object of snapshot options"
          .= snapshots
        <*> optionalField "QueryBatchSize" "Chunk size for large backend reads" .= queryBatchSize
        <*> backendCodec .= backendSelector

instance Default LedgerDbConfiguration where
  def = LedgerDbConfiguration Nothing Nothing Nothing

-- | Finally resolve the storage configuration with a final 'NodeDatabasePaths'.
adjustDbPath :: StorageConfiguration Maybe -> NodeDatabasePaths -> StorageConfiguration Identity
adjustDbPath sc db =
  sc
    { databasePath = Identity db
    , ledgerDbConfiguration = Identity $ fromMaybe def $ ledgerDbConfiguration sc
    }

-- | The storage configuration
data StorageConfiguration f = StorageConfiguration
  { databasePath :: f NodeDatabasePaths
  , ledgerDbConfiguration :: f LedgerDbConfiguration
  }
  deriving (Generic)

deriving instance Show (StorageConfiguration Maybe)
deriving instance Show (StorageConfiguration Identity)

deriving via
  (Autodocodec (StorageConfiguration Maybe))
  instance
    FromJSON (StorageConfiguration Maybe)

deriving via (Autodocodec (StorageConfiguration Maybe)) instance ToJSON (StorageConfiguration Maybe)

instance HasCodec (StorageConfiguration Maybe) where
  codec =
    object "StorageConfiguration" $
      StorageConfiguration
        <$> optionalField "DatabasePath" "Directory (or split directories) where the state is stored"
          .= databasePath
        <*> optionalField "LedgerDB" "The LedgerDB configuration" .= ledgerDbConfiguration
