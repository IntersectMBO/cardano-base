-- | Options related to the Cardano protocol
module Cardano.Configuration.File.Protocol (
  -- * Configuration
  ProtocolConfiguration (..),

  -- * Hashed files
  Hashed (..),
  optionalHashedFileObjectCodec,

  -- * Particular eras
  ByronGenesisConfiguration (..),
  RequiresNetworkMagic (..),
) where

import Autodocodec
import Cardano.Configuration.Common (filePathCodec)
import Cardano.Crypto.Hash (Blake2b_256, Hash, hashFromTextAsHex, hashToTextAsHex)
import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString (ByteString)
import Data.Functor.Identity (Identity)
import Data.Text (Text)
import Data.Word
import GHC.Generics

-- | A maybe hashed entity, possibly a file.
data Hashed a = Hashed
  { hashed :: a
  , hash :: Maybe (Hash Blake2b_256 ByteString)
  }
  deriving (Generic, Show)

-- | A 'Double' codec via 'scientificCodec', so the schema declares
-- @"type": "number"@ (autodocodec ships no 'HasCodec' instance for 'Double').
doubleCodec :: JSONCodec Double
doubleCodec = dimapCodec realToFrac realToFrac scientificCodec

-- | A codec for a Blake2b-256 hash: a hex string. We bimap over the string codec
-- (rather than 'codecViaAeson') so the schema declares @"type": "string"@.
hashCodec :: JSONCodec (Hash Blake2b_256 ByteString)
hashCodec =
  bimapCodec
    (maybe (Left "invalid Blake2b_256 hash (expected a hex string)") Right . hashFromTextAsHex)
    hashToTextAsHex
    (codec @Text)
    <?> "Blake2b_256 hash"

-- | An object-codec fragment reading a file path and its optional hash from two
-- sibling keys of the enclosing object.
hashedFileObjectCodec :: Text -> Text -> JSONObjectCodec (Hashed FilePath)
hashedFileObjectCodec fileKey hashKey =
  Hashed
    <$> requiredFieldWith fileKey filePathCodec "Path to the file" .= hashed
    <*> optionalFieldWith hashKey hashCodec "Hash of the file" .= hash

-- | An optional hashed file: 'Nothing' when the file key is absent.
optionalHashedFileObjectCodec :: Text -> Text -> JSONObjectCodec (Maybe (Hashed FilePath))
optionalHashedFileObjectCodec fileKey hashKey =
  dimapCodec toG fromG $
    (,)
      <$> optionalFieldWith fileKey filePathCodec "Path to the file" .= fst
      <*> optionalFieldWith hashKey hashCodec "Hash of the file" .= snd
  where
    toG (Nothing, _) = Nothing
    toG (Just f, mh) = Just (Hashed f mh)
    fromG Nothing = (Nothing, Nothing)
    fromG (Just (Hashed f mh)) = (Just f, mh)

-- | Whether the Byron network magic is required. Enumerated so the schema lists
-- the valid values and typos are caught at parse time.
data RequiresNetworkMagic
  = RequiresNoMagic
  | RequiresMagic
  deriving (Generic, Show, Eq, Enum, Bounded)
  deriving (FromJSON, ToJSON) via (Autodocodec RequiresNetworkMagic)

instance HasCodec RequiresNetworkMagic where
  codec = shownBoundedEnumCodec

-- | Configuration for byron era
data ByronGenesisConfiguration = ByronGenesisConfiguration
  { byronGenesisFile :: !(Hashed FilePath)
  , byronReqNetworkMagic :: !(Maybe RequiresNetworkMagic)
  , byronPbftSignatureThresh :: !(Maybe Double)
  , byronSupportedProtocolVersionMajor :: !Word16
  , byronSupportedProtocolVersionMinor :: !Word16
  , byronSupportedProtocolVersionAlt :: !(Maybe Word8)
  }
  deriving (Generic, Show)

byronGenesisObjectCodec :: JSONObjectCodec ByronGenesisConfiguration
byronGenesisObjectCodec =
  ByronGenesisConfiguration
    <$> hashedFileObjectCodec "ByronGenesisFile" "ByronGenesisHash" .= byronGenesisFile
    <*> optionalField "RequiresNetworkMagic" "Whether network magic is required"
      .= byronReqNetworkMagic
    <*> optionalFieldWith "PBftSignatureThreshold" doubleCodec "Byron PBFT signature threshold"
      .= byronPbftSignatureThresh
    <*> requiredField "LastKnownBlockVersion-Major" "Last known block version, major"
      .= byronSupportedProtocolVersionMajor
    <*> requiredField "LastKnownBlockVersion-Minor" "Last known block version, minor"
      .= byronSupportedProtocolVersionMinor
    <*> optionalField "LastKnownBlockVersion-Alt" "Last known block version, alt"
      .= byronSupportedProtocolVersionAlt

-- | The genesis file (and optional hash) for the checkpoints.
checkpointsObjectCodec :: JSONObjectCodec (Maybe (Hashed FilePath))
checkpointsObjectCodec = optionalHashedFileObjectCodec "CheckpointsFile" "CheckpointsFileHash"

-- | Configuration for the protocol
data ProtocolConfiguration f = ProtocolConfiguration
  { byronGenesis :: ByronGenesisConfiguration
  , shelleyGenesis :: !(Hashed FilePath)
  , alonzoGenesis :: !(Hashed FilePath)
  , conwayGenesis :: !(Hashed FilePath)
  , startAsNonProducingNode :: !(f Bool)
  , checkpointsFile :: !(Maybe (Hashed FilePath))
  }
  deriving (Generic)

deriving instance Show (ProtocolConfiguration Maybe)
deriving instance Show (ProtocolConfiguration Identity)

deriving via
  (Autodocodec (ProtocolConfiguration Maybe))
  instance
    FromJSON (ProtocolConfiguration Maybe)

deriving via
  (Autodocodec (ProtocolConfiguration Maybe))
  instance
    ToJSON (ProtocolConfiguration Maybe)

instance HasCodec (ProtocolConfiguration Maybe) where
  codec =
    object "ProtocolConfiguration" $
      ProtocolConfiguration
        <$> byronGenesisObjectCodec .= byronGenesis
        <*> hashedFileObjectCodec "ShelleyGenesisFile" "ShelleyGenesisHash" .= shelleyGenesis
        <*> hashedFileObjectCodec "AlonzoGenesisFile" "AlonzoGenesisHash" .= alonzoGenesis
        <*> hashedFileObjectCodec "ConwayGenesisFile" "ConwayGenesisHash" .= conwayGenesis
        <*> optionalField "StartAsNonProducingNode" "Start without producing blocks" .= startAsNonProducingNode
        <*> checkpointsObjectCodec .= checkpointsFile
