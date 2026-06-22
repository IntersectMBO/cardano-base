{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE GADTs #-}

-- | The representation of the configuration file
module Cardano.Configuration.File (
  -- * Configuration file
  NodeConfigurationFromFile,
  NodeConfigurationFromFileF (..),
  parseConfigurationFiles,

  -- * Specific components configurations
  StorageConfiguration (..),
  ConsensusConfiguration (..),
  ProtocolConfiguration (..),
  NetworkConfiguration (..),
  DiffusionMode (..),
  LocalConnectionsConfig (..),
  TestingConfiguration (..),
  MempoolConfiguration (..),
  TracingConfiguration (..),
) where

import Cardano.Configuration.File.Consensus
import Cardano.Configuration.File.Mempool
import Cardano.Configuration.File.Network
import Cardano.Configuration.File.Protocol
import Cardano.Configuration.File.Storage
import Cardano.Configuration.File.Testing
import Cardano.Configuration.File.Tracing
import Control.Exception
import qualified Data.ByteString as BS
import Data.Functor.Identity (Identity (..))
import Data.String (fromString)
import Data.Yaml
import GHC.Generics (Generic)
import GHC.Stack
import System.Directory (doesFileExist)
import System.FilePath (takeDirectory, (</>))

-- | The configuration from the files, parsed with 'parseConfigurationFiles'
type NodeConfigurationFromFile = NodeConfigurationFromFileF Identity

-- | The configuration from the files, initially maybe pointing to sub-files and
-- finally fully parsed.
data NodeConfigurationFromFileF f
  = NodeConfigurationFromFileV1
  { storageConfiguration :: f (StorageConfiguration Maybe)
  , consensusConfiguration :: f (ConsensusConfiguration Maybe)
  , protocolConfiguration :: f (ProtocolConfiguration Maybe)
  , networkConfiguration :: f NetworkConfiguration
  , localConnectionsConfig :: f LocalConnectionsConfig
  , testingConfiguration :: f TestingConfiguration
  , mempoolConfiguration :: f MempoolConfiguration
  , tracingConfiguration :: TracingConfiguration
  -- ^ Tracing keys, captured opaquely; see 'TracingConfiguration'. Unlike the
  -- other components this is never read from a sub-file: the node's tracing
  -- system resolves its own @HermodTracing@ file indirection.
  }
  deriving (Generic)

deriving instance Show (NodeConfigurationFromFileF (Either FilePath))
deriving instance Show (NodeConfigurationFromFileF Identity)

-- | If the consulted key is a filepath, then prepare an action to parse that
-- other file.
subFileParser ::
  FilePath ->
  String ->
  (Value -> Parser a) ->
  Value ->
  Parser (IO a)
subFileParser root sectionName p val = do
  withObject
    "Configuration"
    ( \v -> do
        v .:? fromString sectionName >>= \case
          Just fn ->
            pure $
              do
                exists <- doesFileExist $ root </> fn
                if exists
                  then do
                    bs <- BS.readFile (root </> fn)
                    json <- decodeThrow bs
                    parseOrThrow p json
                  else parseOrThrow p val
          Nothing ->
            pure $ parseOrThrow p val
    )
    val

data ConfigurationParsingError = ConfigurationParsingError String
  deriving (Show, Exception)

parseOrThrow :: (a -> Parser b) -> a -> IO b
parseOrThrow p v = case parseEither p v of
  Left err -> throwIO (ConfigurationParsingError err)
  Right res -> pure res

parseConfigurationVersion1 ::
  FilePath ->
  Value ->
  Parser (NodeConfigurationFromFileF IO)
parseConfigurationVersion1 root v =
  NodeConfigurationFromFileV1
    <$> subFileParser root "Storage" parseJSON v
    <*> subFileParser root "Consensus" parseJSON v
    <*> subFileParser root "Protocol" parseJSON v
    <*> subFileParser root "Network" parseJSON v
    <*> subFileParser root "LocalConnections" parseJSON v
    <*> subFileParser root "Testing" parseJSON v
    <*> subFileParser root "Mempool" parseJSON v
    <*> parseJSON v

-- | Parse the configuration file, but do not parse the children files
-- referenced from it yet.
parseConfigurationFile ::
  FilePath -> Value -> Parser (NodeConfigurationFromFileF IO)
parseConfigurationFile root val =
  withObject
    "Configuration"
    ( \v -> do
        configVersion <- v .:? "ConfigurationVersion"
        case configVersion :: Maybe Int of
          Nothing -> parseConfigurationVersion1 root val
          Just 1 -> parseConfigurationVersion1 root val
          _ -> fail $ "Unknown configuration version: " <> show configVersion
    )
    val

-- | Parse the configuration file and parse any other children configuration
-- files referenced from it.
parseConfigurationFiles :: HasCallStack => FilePath -> IO NodeConfigurationFromFile
parseConfigurationFiles cfgFile = do
  bs <- BS.readFile cfgFile
  v <- decodeThrow bs
  cfg <- parseOrThrow (parseConfigurationFile (takeDirectory cfgFile)) v
  NodeConfigurationFromFileV1
    <$> (Identity <$> storageConfiguration cfg)
    <*> (Identity <$> consensusConfiguration cfg)
    <*> (Identity <$> protocolConfiguration cfg)
    <*> (Identity <$> networkConfiguration cfg)
    <*> (Identity <$> localConnectionsConfig cfg)
    <*> (Identity <$> testingConfiguration cfg)
    <*> (Identity <$> mempoolConfiguration cfg)
    <*> pure (tracingConfiguration cfg)
