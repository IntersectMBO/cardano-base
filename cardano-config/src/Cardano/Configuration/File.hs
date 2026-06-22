{-# LANGUAGE GADTs #-}

-- | The representation of the configuration file
module Cardano.Configuration.File (
  -- * Configuration file
  NodeConfigurationFromFile,
  NodeConfigurationFromFileF (..),
  parseConfigurationFiles,

  -- * Errors
  ConfigurationParsingError (..),

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
import Data.Aeson (FromJSON, Value (..), parseJSON)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import Data.Aeson.Types (JSONPath, JSONPathElement (..), formatError, iparseEither)
import Data.Functor.Identity (Identity (..))
import qualified Data.Text as T
import qualified Data.Yaml as Yaml
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

deriving instance Show (NodeConfigurationFromFileF Identity)

-- | An error encountered while reading or parsing the configuration. It records
-- enough context to point the user at the offending file, section and location.
data ConfigurationParsingError = ConfigurationParsingError
  { errFile :: Maybe FilePath
  -- ^ The referenced sub-file the failure occurred in, if any (otherwise the
  -- failure was in the main configuration file).
  , errSection :: Maybe String
  -- ^ The top-level configuration section being parsed (e.g. @"Storage"@).
  , errPath :: JSONPath
  -- ^ The path to the offending value within the JSON\/YAML document.
  , errMessage :: String
  -- ^ The underlying error message.
  }
  deriving (Eq)

instance Exception ConfigurationParsingError

instance Show ConfigurationParsingError where
  show ConfigurationParsingError {errFile, errSection, errPath, errMessage} =
    mconcat
      [ "Error parsing the cardano-node configuration"
      , maybe "" (\s -> " (section " <> show s <> ")") errSection
      , maybe " in the main configuration file" (\f -> " in " <> f) errFile
      , ":\n  "
      , formatError errPath errMessage
      ]

-- | Read and decode a YAML\/JSON file into a 'Value', reporting syntax errors as
-- a 'ConfigurationParsingError' that names the file and section.
decodeValueFile ::
  -- | The section being read, for error reporting.
  Maybe String ->
  -- | The file to read.
  FilePath ->
  IO Value
decodeValueFile section fp = do
  result <- Yaml.decodeFileEither fp
  case result of
    Left e ->
      throwIO $
        ConfigurationParsingError (Just fp) section [] (Yaml.prettyPrintParseException e)
    Right v -> pure v

-- | Run a component parser on a 'Value', turning a failure into a structured
-- 'ConfigurationParsingError' carrying the file, section and JSON path.
runCodec ::
  FromJSON a =>
  -- | The sub-file the value came from, if any.
  Maybe FilePath ->
  -- | The section being parsed, for error reporting.
  String ->
  -- | The value to parse.
  Value ->
  IO a
runCodec mFile section value =
  case iparseEither parseJSON value of
    Left (path, msg) -> throwIO $ ConfigurationParsingError mFile (Just section) path msg
    Right a -> pure a

-- | Parse a single component. A section is read inline from the main file when
-- the section key is absent (its keys live at the top level), from an inline
-- object when the key holds one, or from a referenced sub-file when the key
-- holds a path. Unlike a previous version, a path to a missing file is an
-- explicit error rather than a silent fall back to inline parsing.
parseSection ::
  FromJSON a =>
  -- | The directory the main file lives in, against which sub-file paths are
  -- resolved.
  FilePath ->
  -- | The (unwrapped) configuration object.
  Value ->
  -- | The section name.
  String ->
  IO a
parseSection root configValue section =
  case configValue of
    Object o ->
      case KM.lookup (K.fromString section) o of
        -- No dedicated key: the section's keys live at the top level.
        Nothing -> runCodec Nothing section configValue
        -- A path to a sub-file.
        Just (String path) -> do
          let fp = root </> T.unpack path
          exists <- doesFileExist fp
          if exists
            then decodeValueFile (Just section) fp >>= runCodec (Just fp) section
            else
              throwIO $
                ConfigurationParsingError
                  (Just fp)
                  (Just section)
                  [Key (K.fromString section)]
                  "the referenced configuration file does not exist"
        -- An inline object.
        Just inline@(Object _) -> runCodec Nothing section inline
        Just _ ->
          throwIO $
            ConfigurationParsingError
              Nothing
              (Just section)
              [Key (K.fromString section)]
              "expected either a path to a configuration file (a string) or an inline object"
    _ ->
      throwIO $
        ConfigurationParsingError Nothing Nothing [] "expected the configuration to be a JSON/YAML object"

-- | Split the optional configuration envelope @{ \"ConfigurationVersion\": N,
-- \"Config\": {..} }@ into the version and the configuration object. A document
-- that is not wrapped in an envelope is treated as the legacy version-1 format,
-- in which the configuration keys sit at the top level (and an optional flat
-- @ConfigurationVersion@ key may select the version).
splitEnvelope :: Value -> IO (Int, Value)
splitEnvelope value =
  case value of
    Object o
      | Just config <- KM.lookup "Config" o -> pure (lookupVersion o, config)
      | otherwise -> pure (lookupVersion o, value)
    _ ->
      throwIO $
        ConfigurationParsingError Nothing Nothing [] "expected the configuration to be a JSON/YAML object"
  where
    lookupVersion o = case KM.lookup "ConfigurationVersion" o of
      Just (Number n) -> round n
      _ -> 1

-- | Parse the configuration file and any sub-files referenced from it.
--
-- The configuration may be given in JSON or YAML. Errors are reported as
-- 'ConfigurationParsingError', identifying the offending file, section and
-- location.
parseConfigurationFiles :: HasCallStack => FilePath -> IO NodeConfigurationFromFile
parseConfigurationFiles cfgFile = do
  mainValue <- decodeValueFile Nothing cfgFile
  (version, configValue) <- splitEnvelope mainValue
  case version of
    1 -> parseConfigurationVersion1 (takeDirectory cfgFile) configValue
    n ->
      throwIO $
        ConfigurationParsingError
          (Just cfgFile)
          Nothing
          [Key "ConfigurationVersion"]
          ("unsupported configuration version: " <> show n)

-- | Parse a version-1 configuration object, reading each component either
-- inline or from its referenced sub-file.
parseConfigurationVersion1 ::
  -- | The directory sub-file paths are resolved against.
  FilePath ->
  -- | The configuration object.
  Value ->
  IO NodeConfigurationFromFile
parseConfigurationVersion1 root configValue =
  NodeConfigurationFromFileV1
    <$> (Identity <$> parseSection root configValue "Storage")
    <*> (Identity <$> parseSection root configValue "Consensus")
    <*> (Identity <$> parseSection root configValue "Protocol")
    <*> (Identity <$> parseSection root configValue "Network")
    <*> (Identity <$> parseSection root configValue "LocalConnections")
    <*> (Identity <$> parseSection root configValue "Testing")
    <*> (Identity <$> parseSection root configValue "Mempool")
    <*> runCodec Nothing "Tracing" configValue
