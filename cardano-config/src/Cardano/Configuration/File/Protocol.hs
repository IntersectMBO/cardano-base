-- | Options related to the Cardano protocol
module Cardano.Configuration.File.Protocol (
  -- * Configuration
  ProtocolConfiguration (..),

  -- * Hashed files
  Hashed (..),
  optionalHashedFileObjectCodec,

  -- * Particular eras
  ByronGenesisConfiguration (..),
) where

import Autodocodec
import Cardano.Crypto.Hash (Blake2b_256, Hash)
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

-- | A codec for a Blake2b-256 hash, reusing its aeson instances (a hex string).
hashCodec :: JSONCodec (Hash Blake2b_256 ByteString)
hashCodec = codecViaAeson "Blake2b_256 hash"

-- | An object-codec fragment reading a file path and its optional hash from two
-- sibling keys of the enclosing object.
hashedFileObjectCodec :: Text -> Text -> JSONObjectCodec (Hashed FilePath)
hashedFileObjectCodec fileKey hashKey =
  Hashed
    <$> requiredField fileKey "Path to the file" .= hashed
    <*> optionalFieldWith hashKey hashCodec "Hash of the file" .= hash

-- | An optional hashed file: 'Nothing' when the file key is absent.
optionalHashedFileObjectCodec :: Text -> Text -> JSONObjectCodec (Maybe (Hashed FilePath))
optionalHashedFileObjectCodec fileKey hashKey =
  dimapCodec toG fromG $
    (,)
      <$> optionalField fileKey "Path to the file" .= fst
      <*> optionalFieldWith hashKey hashCodec "Hash of the file" .= snd
  where
    toG (Nothing, _) = Nothing
    toG (Just f, mh) = Just (Hashed f mh)
    fromG Nothing = (Nothing, Nothing)
    fromG (Just (Hashed f mh)) = (Just f, mh)

-- | Configuration for byron era
data ByronGenesisConfiguration = ByronGenesisConfiguration
  { byronGenesisFile :: !(Hashed FilePath)
  , byronReqNetworkMagic :: !String
  , byronPbftSignatureThresh :: !(Maybe Double)
  , byronSupportedProtocolVersionMajor :: !Word16
  , byronSupportedProtocolVersionMinor :: !Word16
  , byronSupportedProtocolVersionAlt :: !Word8
  }
  deriving (Generic, Show)

byronGenesisObjectCodec :: JSONObjectCodec ByronGenesisConfiguration
byronGenesisObjectCodec =
  ByronGenesisConfiguration
    <$> hashedFileObjectCodec "ByronGenesisFile" "ByronGenesisHash" .= byronGenesisFile
    <*> optionalFieldWithDefault
      "RequiresNetworkMagic"
      "RequiresNoMagic"
      "Whether network magic is required"
      .= byronReqNetworkMagic
    <*> optionalFieldWith "PBftSignatureThreshold" (codecViaAeson "Double") "Byron PBFT signature threshold"
      .= byronPbftSignatureThresh
    <*> requiredField "LastKnownBlockVersion-Major" "Last known block version, major"
      .= byronSupportedProtocolVersionMajor
    <*> requiredField "LastKnownBlockVersion-Minor" "Last known block version, minor"
      .= byronSupportedProtocolVersionMinor
    <*> optionalFieldWithDefault "LastKnownBlockVersion-Alt" 0 "Last known block version, alt"
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
