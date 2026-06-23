{-# LANGUAGE GADTs #-}

-- | The representation of the configuration file
module Cardano.Configuration.File (
  -- * Configuration file
  NodeConfigurationFromFile,
  NodeConfigurationFromFileF (..),
  parseConfigurationFiles,
  parseConfigurationFilesWith,
  UnknownKeyPolicy (..),

  -- * Defaults
  componentDefaults,

  -- * Errors
  ConfigurationParsingError (..),

  -- * Specific components configurations
  StorageConfiguration (..),
  ConsensusConfiguration (..),
  ProtocolConfiguration (..),
  NetworkConfiguration (..),
  DiffusionMode (..),
  AcceptedConnectionsLimit (..),
  LocalConnectionsConfig (..),
  TestingConfiguration (..),
  MempoolConfiguration (..),
  TracingConfiguration (..),

  -- * Resolving components
  finalizeNetwork,
  finalizeLocalConnections,
  finalizeMempool,
  finalizeTesting,
) where

import Cardano.Configuration.File.Consensus
import Cardano.Configuration.File.Mempool
import Cardano.Configuration.File.Network
import Cardano.Configuration.File.Protocol
import Cardano.Configuration.File.Storage
import Cardano.Configuration.File.Testing
import Cardano.Configuration.File.Tracing
import Cardano.Configuration.Schema (componentPropertyNames, recognisedKeys)
import Data.Maybe (catMaybes)
import Control.Exception
import Control.Monad (unless)
import Data.Aeson (FromJSON, Value (..), parseJSON)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import Data.Aeson.Types (JSONPath, JSONPathElement (..), formatError, iparseEither)
import Data.Foldable (toList)
import Data.Functor.Identity (Identity (..))
import Data.List (intercalate)
import qualified Data.Text as T
import qualified Data.Yaml as Yaml
import GHC.Generics (Generic)
import GHC.Stack
import Paths_cardano_config (getDataFileName)
import System.Directory (doesFileExist)
import System.FilePath (takeDirectory, (</>))
import System.IO (hPutStrLn, stderr)

-- | The configuration from the files, parsed with 'parseConfigurationFiles'
type NodeConfigurationFromFile = NodeConfigurationFromFileF Identity

-- | The configuration from the files, initially maybe pointing to sub-files and
-- finally fully parsed.
data NodeConfigurationFromFileF f
  = NodeConfigurationFromFileV1
  { storageConfiguration :: f (StorageConfiguration Maybe)
  , consensusConfiguration :: f (ConsensusConfiguration Maybe)
  , protocolConfiguration :: f (ProtocolConfiguration Maybe)
  , networkConfiguration :: f (NetworkConfiguration Maybe)
  , localConnectionsConfig :: f (LocalConnectionsConfig Maybe)
  , testingConfiguration :: f (TestingConfiguration Maybe)
  , mempoolConfiguration :: f (MempoolConfiguration Maybe)
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
  -- ^ The top-level configuration section being parsed (e.g. @"StorageConfig"@).
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

-- | Deep, right-biased merge of two JSON values: two objects are merged key by
-- key (a key present in both is merged recursively), and for anything else the
-- second (later) value wins. Used to layer configuration sources so that a later
-- file in a list overrides an earlier one.
mergeValues :: Value -> Value -> Value
mergeValues (Object earlier) (Object later) = Object (KM.unionWith mergeValues earlier later)
mergeValues _ later = later

-- | Resolve a single section source — a path to a sub-file (a string) or an
-- inline object — to its 'Value'.
loadSectionSource :: FilePath -> String -> Value -> IO Value
loadSectionSource root section src =
  case src of
    String path -> do
      let fp = root </> T.unpack path
      exists <- doesFileExist fp
      if exists
        then decodeValueFile (Just section) fp
        else
          throwIO $
            ConfigurationParsingError
              (Just fp)
              (Just section)
              [Key (K.fromString section)]
              "the referenced configuration file does not exist"
    Object _ -> pure src
    _ ->
      throwIO $
        ConfigurationParsingError
          Nothing
          (Just section)
          [Key (K.fromString section)]
          "expected a path to a configuration file (a string) or an inline object"

-- | The always-applied base default for a section, read from the package data
-- files (@defaults\/\<Section\>.json@), if one ships for it.
loadBaseDefault :: String -> IO (Maybe Value)
loadBaseDefault section = do
  fp <- getDataFileName ("defaults/" <> section <> ".json")
  exists <- doesFileExist fp
  if exists
    then Just <$> decodeValueFile (Just section) fp
    else pure Nothing

-- | The per-component base defaults (@defaults\/<Component>.json@), for schema
-- generation. Keyed by component name; components without a defaults file are
-- omitted. These are the same files the resolver merges as the base layer, so
-- the documented defaults match the applied ones.
componentDefaults :: IO [(T.Text, Value)]
componentDefaults =
  catMaybes
    <$> mapM
      (\name -> fmap (name,) <$> loadBaseDefault (T.unpack name))
      (map fst componentPropertyNames)

-- | The configuration layer the user supplied for a section: the top-level
-- object when the section key is absent (its keys live there), an inline object,
-- a referenced sub-file, or a list of paths\/objects deep-merged in order (a
-- later entry overrides an earlier one, e.g.
-- @[\"Network.variants\/Network.relay.json\"]@).
sectionUserLayer :: FilePath -> Value -> String -> IO Value
sectionUserLayer root configValue section =
  case configValue of
    Object o ->
      case KM.lookup (K.fromString section) o of
        Nothing -> pure configValue
        Just (Array elems) ->
          case toList elems of
            [] ->
              throwIO $
                ConfigurationParsingError
                  Nothing
                  (Just section)
                  [Key (K.fromString section)]
                  "expected a non-empty list of configuration files or objects"
            sources -> foldl1 mergeValues <$> mapM (loadSectionSource root section) sources
        Just source -> loadSectionSource root section source
    _ ->
      throwIO $
        ConfigurationParsingError Nothing Nothing [] "expected the configuration to be a JSON/YAML object"

-- | Parse a single component. The package's base default for the section is
-- always read as the bottom layer; the user's layer (see 'sectionUserLayer') is
-- deep-merged on top. A path to a missing file is an explicit error.
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
parseSection root configValue section = do
  base <- loadBaseDefault section
  user <- sectionUserLayer root configValue section
  let withBase = maybe user (`mergeValues` user) base
  runCodec Nothing section withBase

-- | Split the optional configuration envelope @{ \"Version\": N,
-- \"Configuration\": {..} }@ into the version and the configuration object. A
-- document that is not wrapped in an envelope is treated as the legacy version-1
-- format, in which the configuration keys sit at the top level (and an optional
-- flat @Version@ key may select the version).
splitEnvelope :: Value -> IO (Int, Value)
splitEnvelope value =
  case value of
    Object o
      | Just config <- KM.lookup "Configuration" o -> pure (lookupVersion o, config)
      | otherwise -> pure (lookupVersion o, value)
    _ ->
      throwIO $
        ConfigurationParsingError Nothing Nothing [] "expected the configuration to be a JSON/YAML object"
  where
    lookupVersion o = case KM.lookup "Version" o of
      Just (Number n) -> round n
      _ -> 1

-- | What to do when the configuration contains keys that none of the parsers
-- recognise (typically a typo).
data UnknownKeyPolicy
  = -- | Emit a warning to @stderr@ and carry on (the default).
    WarnUnknownKeys
  | -- | Reject the configuration with a 'ConfigurationParsingError'.
    RejectUnknownKeys
  deriving (Eq, Show)

-- | Parse the configuration file and any sub-files referenced from it.
--
-- The configuration may be given in JSON or YAML. Errors are reported as
-- 'ConfigurationParsingError', identifying the offending file, section and
-- location. Unrecognised top-level keys produce a warning; use
-- 'parseConfigurationFilesWith' to reject them instead.
parseConfigurationFiles :: HasCallStack => FilePath -> IO NodeConfigurationFromFile
parseConfigurationFiles = parseConfigurationFilesWith WarnUnknownKeys

-- | As 'parseConfigurationFiles', but with control over how unrecognised
-- top-level keys are handled.
parseConfigurationFilesWith ::
  HasCallStack => UnknownKeyPolicy -> FilePath -> IO NodeConfigurationFromFile
parseConfigurationFilesWith policy cfgFile = do
  mainValue <- decodeValueFile Nothing cfgFile
  (version, configValue) <- splitEnvelope mainValue
  checkUnknownKeys policy cfgFile configValue
  checkShadowedKeys policy cfgFile configValue
  let root = takeDirectory cfgFile
  case version of
    1 -> parseConfigurationVersion1 root configValue
    n ->
      throwIO $
        ConfigurationParsingError
          (Just cfgFile)
          Nothing
          [Key "Version"]
          ("unsupported configuration version: " <> show n)

-- | Check the top-level configuration keys against the recognised ones, warning
-- on (or, under 'RejectUnknownKeys', rejecting) any that are unrecognised.
checkUnknownKeys :: UnknownKeyPolicy -> FilePath -> Value -> IO ()
checkUnknownKeys policy cfgFile value =
  case value of
    Object o -> do
      let unknown = [k | k <- map K.toText (KM.keys o), k `notElem` recognisedKeys]
      unless (null unknown) $ do
        let msg = "unrecognised configuration key(s): " <> intercalate ", " (map T.unpack unknown)
        case policy of
          RejectUnknownKeys -> throwIO $ ConfigurationParsingError (Just cfgFile) Nothing [] msg
          WarnUnknownKeys -> hPutStrLn stderr ("Warning: " <> msg <> " (ignored)")
    _ -> pure ()

-- | Detect top-level keys shadowed by a component supplied as its own section:
-- when a section key (e.g. @Testing@) is present, that component's keys are read
-- from the section, so any sibling top-level key belonging to the same component
-- (e.g. a top-level @DijkstraGenesisFile@) is silently ignored. Such a key is
-- almost certainly a mistake, so warn (or, under 'RejectUnknownKeys', reject).
--
-- This looks only at the keys the user wrote in this object; the per-component
-- base defaults are merged separately inside 'parseSection' and never appear
-- here, so they cannot trigger it.
checkShadowedKeys :: UnknownKeyPolicy -> FilePath -> Value -> IO ()
checkShadowedKeys policy cfgFile value =
  case value of
    Object o -> do
      let present = map K.toText (KM.keys o)
          shadowed =
            [ (section, key)
            | (section, keys) <- componentPropertyNames
            , section `elem` present
            , key <- keys
            , key `elem` present
            ]
      unless (null shadowed) $ do
        let describe (section, key) = T.unpack key <> " (shadowed by the " <> T.unpack section <> " section)"
            msg =
              "top-level configuration key(s) ignored because their component is given as a separate section: "
                <> intercalate ", " (map describe shadowed)
        case policy of
          RejectUnknownKeys -> throwIO $ ConfigurationParsingError (Just cfgFile) Nothing [] msg
          WarnUnknownKeys -> hPutStrLn stderr ("Warning: " <> msg <> " (ignored)")
    _ -> pure ()

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
    <$> (Identity <$> parseSection root configValue "StorageConfig")
    <*> (Identity <$> parseSection root configValue "ConsensusConfig")
    <*> (Identity <$> parseSection root configValue "ProtocolConfig")
    <*> (Identity <$> parseSection root configValue "NetworkConfig")
    <*> (Identity <$> parseSection root configValue "LocalConnectionsConfig")
    <*> (Identity <$> parseSection root configValue "TestingConfig")
    <*> (Identity <$> parseSection root configValue "MempoolConfig")
    <*> runCodec Nothing "Tracing" configValue
