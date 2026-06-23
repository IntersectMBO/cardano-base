-- | JSON Schemas for the configuration components, derived directly from the
-- autodocodec codecs (so they cannot drift from the parsers).
--
-- Each schema records which keys are required, which are optional, and the
-- defaults applied at parse time (e.g. the @Backend@ or @EnableCSJ@ defaults).
-- Keys that are merely left unset for the node to default appear as optional
-- without a value.
--
-- The raw codec schemas are post-processed (see 'publish') to be as useful as
-- possible to validators, editors and documentation generators:
--
--   * autodocodec's @$comment@ annotations become @description@s;
--   * file-path strings (tagged via 'filePathFormatMarker') gain a
--     @"format": "path"@ annotation, so a path is distinguishable from an
--     arbitrary string;
--   * string-enumeration @oneOf@\/@anyOf@s (of bare @const@s) collapse to a
--     @{ "type": "string", "enum": [..] }@, so every such field declares a type;
--   * every schema and property gains a @title@, and every document an @$id@, so
--     tools that key off them (e.g. @jsonschema2md@) render names rather than
--     @Untitled@\/@undefined@.
--
-- Tracing is not a component of its own: it is surfaced only as the single
-- top-level @HermodTracing@ key, a path to a separate file that the node's
-- tracing system (hermod/@trace-dispatcher@) reads. Its contents are neither
-- parsed nor described here; the authoritative tracing schema lives in that
-- package.
module Cardano.Configuration.Schema (
  -- * Whole configuration
  wholeConfigSchema,
  recognisedKeys,
  componentPropertyNames,

  -- * Default values
  wholeConfigSchemaWithDefaults,
  configurationSchemasWithDefaults,

  -- * Individual components
  configurationSchemas,
  storageSchema,
  consensusSchema,
  protocolSchema,
  networkSchema,
  localConnectionsSchema,
  mempoolSchema,
  testingSchema,
) where

import Autodocodec.Schema (jsonSchemaViaCodec)
import Cardano.Configuration.Common (filePathFormatMarker)
import Cardano.Configuration.File.Consensus (ConsensusConfiguration)
import Cardano.Configuration.File.Mempool (MempoolConfiguration)
import Cardano.Configuration.File.Network (LocalConnectionsConfig, NetworkConfiguration)
import Cardano.Configuration.File.Protocol (ProtocolConfiguration)
import Cardano.Configuration.File.Storage (StorageConfiguration)
import Cardano.Configuration.File.Testing (TestingConfiguration)
import Cardano.Configuration.File.Tracing (TracingConfiguration)
import Data.Aeson (Value (..), object, toJSON, (.=))
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import Data.Foldable (toList)
import Data.List (nub)
import Data.Text (Text)
import qualified Data.Text as T

storageSchema :: Value
storageSchema = component "Storage" rawStorageSchema

consensusSchema :: Value
consensusSchema = component "Consensus" rawConsensusSchema

protocolSchema :: Value
protocolSchema = component "Protocol" rawProtocolSchema

networkSchema :: Value
networkSchema = component "Network" rawNetworkSchema

localConnectionsSchema :: Value
localConnectionsSchema = component "LocalConnections" rawLocalConnectionsSchema

mempoolSchema :: Value
mempoolSchema = component "Mempool" rawMempoolSchema

testingSchema :: Value
testingSchema = component "Testing" rawTestingSchema

-- The raw schemas as emitted by autodocodec-schema (descriptions in @$comment@,
-- no @$schema@). Used internally for merging; 'publish' makes them public.
rawStorageSchema, rawConsensusSchema, rawProtocolSchema, rawNetworkSchema :: Value
rawLocalConnectionsSchema, rawMempoolSchema, rawTestingSchema, rawTracingSchema :: Value
rawStorageSchema = toJSON (jsonSchemaViaCodec @(StorageConfiguration Maybe))
rawConsensusSchema = toJSON (jsonSchemaViaCodec @(ConsensusConfiguration Maybe))
rawProtocolSchema = toJSON (jsonSchemaViaCodec @(ProtocolConfiguration Maybe))
rawNetworkSchema = toJSON (jsonSchemaViaCodec @(NetworkConfiguration Maybe))
rawLocalConnectionsSchema = toJSON (jsonSchemaViaCodec @(LocalConnectionsConfig Maybe))
rawMempoolSchema = toJSON (jsonSchemaViaCodec @(MempoolConfiguration Maybe))
rawTestingSchema = toJSON (jsonSchemaViaCodec @(TestingConfiguration Maybe))
rawTracingSchema = toJSON (jsonSchemaViaCodec @TracingConfiguration)

-- The components that are sections of their own (given inline, as a sub-file, or
-- as a list). Tracing is deliberately absent: it is not a section, only the
-- single top-level @HermodTracing@ key (see 'hermodTracingProps').
rawComponentSchemas :: [(Text, Value)]
rawComponentSchemas =
  [ ("Storage", rawStorageSchema)
  , ("Consensus", rawConsensusSchema)
  , ("Protocol", rawProtocolSchema)
  , ("Network", rawNetworkSchema)
  , ("LocalConnections", rawLocalConnectionsSchema)
  , ("Mempool", rawMempoolSchema)
  , ("Testing", rawTestingSchema)
  ]

-- | Tracing is not a component/section of its own; it contributes exactly one
-- top-level key, @HermodTracing@ — a path to a separate file that the node's
-- tracing system reads (and which @cardano-config@ neither parses nor describes
-- further). We take that key's schema straight from the TracingConfiguration
-- codec so it stays in step with the parser.
hermodTracingProps :: KM.KeyMap Value
hermodTracingProps = properties rawTracingSchema

-- | The JSON Schema of each configuration component, keyed by name.
configurationSchemas :: [(Text, Value)]
configurationSchemas = [(name, component name s) | (name, s) <- rawComponentSchemas]

-- | The JSON Schema of the whole configuration, covering both forms:
--
--   * the /single-file/ form, in which every component reads its keys from the
--     top-level object (so all component keys appear flat at the top level); and
--   * the /split-file/ form, in which a component is instead given under its
--     section key (e.g. @Storage@) as a path to a sub-file, an inline object, or
--     a non-empty list of paths\/objects deep-merged in order.
--
-- The whole document may additionally be wrapped in a @{ Version, Configuration
-- }@ envelope. Because a mandatory key may be provided through either form, the
-- top-level schema marks nothing as required (the mandatory keys are listed in
-- its description, and the inline section forms keep their own @required@).
--
-- Note: tracing is not a section; it is just the top-level @HermodTracing@ key
-- (a path to a file the node's tracing system reads). Its contents are neither
-- parsed nor described here.
wholeConfigSchema :: Value
wholeConfigSchema =
  publish "Cardano node configuration" "config.schema.json" $
    object
      [ "$comment" .= wholeDescription
      , "type" .= ("object" :: Text)
      , "properties" .= Object (singleFileProps <> sectionRefProps <> envelopeProps)
      , "allOf" .= sectionExclusivity
      ]
  where
    -- The single-file form: every component's keys, flat at the top level, plus
    -- the lone top-level HermodTracing key.
    singleFileProps = foldr (KM.union . properties) hermodTracingProps (map snd rawComponentSchemas)
    -- The split-file form: each component also reachable under its section key.
    sectionRefProps =
      KM.fromList [(K.fromText name, sectionRef name raw) | (name, raw) <- rawComponentSchemas]
    -- Give each component one way or the other, not both: if the section key is
    -- present, none of that component's top-level keys may be (they would be
    -- shadowed by the section). Mirrors the runtime shadowed-key check.
    sectionExclusivity =
      [ object
          [ "$comment"
              .= ( "Give the "
                    <> name
                    <> " configuration either under the "
                    <> name
                    <> " section key or as its individual top-level keys, not both."
                 )
          , "if" .= object ["required" .= [name]]
          , "then"
              .= object
                ["not" .= object ["anyOf" .= [object ["required" .= [k]] | k <- keys]]]
          ]
      | (name, raw) <- rawComponentSchemas
      , let keys = map K.toText (KM.keys (properties raw))
      , not (null keys)
      ]
    -- The envelope keys.
    envelopeProps =
      KM.fromList
        [ ("Version", versionRef)
        , ("Configuration", configurationRef)
        ]

wholeDescription :: Text
wholeDescription =
  T.unwords
    [ "The cardano-node configuration."
    , "Each component's keys may be given directly at the top level (single-file form)"
    , "or, per component, under that component's section key as a path to a sub-file,"
    , "an inline object, or a non-empty list of paths/objects deep-merged in order"
    , "(split-file form); the two forms may be mixed."
    , "The whole document may also be wrapped in a { Version, Configuration } envelope."
    , "Mandatory keys (in the single-file form): ByronGenesisFile, ShelleyGenesisFile,"
    , "AlonzoGenesisFile, ConwayGenesisFile, LastKnownBlockVersion-Major and"
    , "LastKnownBlockVersion-Minor."
    ]

-- | A component's section key in the split-file form: an inline object (the
-- component schema), a path to a sub-file, or a non-empty list of either.
sectionRef :: Text -> Value -> Value
sectionRef name raw =
  object
    [ "$comment"
        .= ( "The "
              <> name
              <> " section, given inline (an object), as a path to a sub-file, or as a"
              <> " non-empty list of paths/objects deep-merged in order (later entries override earlier ones)."
           )
    , "anyOf" .= [pathRef desc, withTitle name raw, listRef]
    ]
  where
    desc = "Path to a file holding the " <> name <> " section"
    listRef =
      object
        [ "type" .= ("array" :: Text)
        , "title" .= (name <> " (list of sources)")
        , "minItems" .= (1 :: Int)
        , "items"
            .= object
              [ "title" .= (name <> " source")
              , "anyOf" .= [pathRef desc, withTitle name raw]
              ]
        ]

-- | A JSON string that is a filesystem path (tagged so 'publish' adds the
-- @path@ format).
pathRef :: Text -> Value
pathRef desc =
  object
    [ "type" .= ("string" :: Text)
    , "title" .= ("File path" :: Text)
    , "$comment" .= (desc <> "\n" <> filePathFormatMarker)
    ]

-- | Insert a @title@ into a schema object unless it already has one.
withTitle :: Text -> Value -> Value
withTitle t (Object o) = Object (KM.insertWith (\_new old -> old) "title" (String t) o)
withTitle _ v = v

versionRef :: Value
versionRef =
  object
    [ "type" .= ("integer" :: Text)
    , "minimum" .= (1 :: Int)
    , "$comment" .= ("The configuration format version (currently 1)." :: Text)
    ]

configurationRef :: Value
configurationRef =
  object
    [ "type" .= ("object" :: Text)
    , "$comment"
        .= ( "When using the { Version, Configuration } envelope, the configuration object goes here"
              <> " (the same shape as this schema)." ::
              Text
           )
    ]

-- | Every top-level configuration key the parsers recognise: the keys of all
-- components (read at the top level in the single-file form), the section keys
-- used to reference split sub-files, and the envelope keys. Used to detect
-- unrecognised (e.g. misspelled) keys.
recognisedKeys :: [Text]
recognisedKeys =
  nub $
    envelopeKeys <> sectionKeys <> tracingKeys <> concatMap snd componentPropertyNames
  where
    envelopeKeys = ["Version", "Configuration"]
    sectionKeys = map fst componentPropertyNames
    tracingKeys = map K.toText (KM.keys hermodTracingProps)

-- | The property names of each component (the keys it reads at the top level in
-- the single-file form), keyed by the component's section name. Used to detect
-- top-level keys shadowed by a section supplied separately. Every property name
-- belongs to exactly one component.
componentPropertyNames :: [(Text, [Text])]
componentPropertyNames =
  [(name, map K.toText (KM.keys (properties s))) | (name, s) <- rawComponentSchemas]

--------------------------------------------------------------------------------
-- Post-processing

-- | The JSON Schema draft these schemas target. autodocodec-schema emits
-- draft-07-compatible schemas, and the keywords we add here (@enum@, @format@,
-- @title@, @$id@) are likewise draft-07 core, so validators such as ajv accept
-- them by default.
draftURI :: Text
draftURI = "http://json-schema.org/draft-07/schema#"

-- | The @$id@ for a committed schema file, where it is published in the repo.
schemaId :: FilePath -> Text
schemaId file =
  "https://raw.githubusercontent.com/IntersectMBO/cardano-base/master/cardano-config/schemas/"
    <> T.pack file

-- | Post-process a component's raw schema into its published form.
component :: Text -> Value -> Value
component name = publish name (T.unpack name <> ".schema.json")

-- | Make a raw codec schema friendly to validators, editors and documentation
-- generators. See the module header for the full list of transformations.
publish :: Text -> FilePath -> Value -> Value
publish title idFile raw =
  case transform raw of
    Object o ->
      Object $
        KM.insert "$schema" (String draftURI) $
          KM.insert "$id" (String (schemaId idFile)) $
            KM.insertWith keepExisting "title" (String title) o
    other -> other
  where
    keepExisting _new old = old

-- | The recursive transformation applied throughout a schema tree.
transform :: Value -> Value
transform = \case
  Object o ->
    Object . titleBranches . collapseStringEnum . typeConst . extractPathFormat . titleProperties $
      KM.fromList [(rename k, transform v) | (k, v) <- KM.toList o]
  Array a -> Array (transform <$> a)
  other -> other
  where
    rename k = if k == "$comment" then "description" else k

-- | Give each member of a @properties@ map a @title@ equal to its key (unless it
-- already has one), so documentation tools name it rather than show "Untitled".
titleProperties :: KM.KeyMap Value -> KM.KeyMap Value
titleProperties o =
  case KM.lookup "properties" o of
    Just (Object props) -> KM.insert "properties" (Object (KM.mapWithKey addTitle props)) o
    _ -> o
  where
    addTitle k (Object c) | not (KM.member "title" c) = Object (KM.insert "title" (String (K.toText k)) c)
    addTitle _ v = v

-- | Lift the file-path sentinel ('filePathFormatMarker') carried in a
-- @description@ into a @"format": "path"@ annotation, stripping the sentinel.
extractPathFormat :: KM.KeyMap Value -> KM.KeyMap Value
extractPathFormat o =
  case KM.lookup "description" o of
    Just (String d)
      | let ls = T.splitOn "\n" d
      , filePathFormatMarker `elem` ls ->
          let kept = filter (/= filePathFormatMarker) ls
              withFormat = KM.insert "format" (String "path") o
           in if null kept
                then KM.delete "description" withFormat
                else KM.insert "description" (String (T.intercalate "\n" kept)) withFormat
    _ -> o

-- | Give each branch of a @oneOf@\/@anyOf@ union a @title@ (unless it already has
-- one) derived from its @const@ value or its @type@, so documentation tools name
-- the alternatives rather than show "Untitled".
titleBranches :: KM.KeyMap Value -> KM.KeyMap Value
titleBranches o = foldr titleUnion o ["anyOf", "oneOf"]
  where
    titleUnion key m = case KM.lookup key m of
      Just (Array bs) -> KM.insert key (Array (fmap addTitle bs)) m
      _ -> m
    addTitle (Object b)
      | not (KM.member "title" b)
      , Just t <- branchTitle b =
          Object (KM.insert "title" (String t) b)
    addTitle v = v
    -- Name a branch by its const value or its type; leave structural branches
    -- (e.g. a bare @{ required: [..] }@ constraint) untitled.
    branchTitle b = case KM.lookup "const" b of
      Just (String s) -> Just s
      _ -> case KM.lookup "type" b of
        Just (String t) -> Just (T.toTitle t)
        _ -> Nothing

-- | Give a bare @const@ schema the @type@ implied by its value, so even a single
-- enumerated alternative (e.g. the @"NoOverride"@ branch of a union) declares a
-- type rather than leaving it undefined.
typeConst :: KM.KeyMap Value -> KM.KeyMap Value
typeConst o =
  case KM.lookup "const" o of
    Just v | not (KM.member "type" o), Just t <- constType v -> KM.insert "type" (String t) o
    _ -> o
  where
    constType (String _) = Just "string"
    constType (Bool _) = Just "boolean"
    constType (Number _) = Just "number"
    constType _ = Nothing

-- | Collapse a @oneOf@\/@anyOf@ whose branches are all bare string @const@s into
-- @{ "type": "string", "enum": [..] }@, so the field declares a single type.
collapseStringEnum :: KM.KeyMap Value -> KM.KeyMap Value
collapseStringEnum o =
  case branches >>= traverse stringConst of
    Just consts@(_ : _) ->
      KM.insert "type" (String "string") $
        KM.insert "enum" (toJSON consts) $
          KM.delete "oneOf" (KM.delete "anyOf" o)
    _ -> o
  where
    branches = case (KM.lookup "oneOf" o, KM.lookup "anyOf" o) of
      (Just (Array a), _) -> Just (toList a)
      (_, Just (Array a)) -> Just (toList a)
      _ -> Nothing
    stringConst (Object b)
      | Just (String s) <- KM.lookup "const" b
      , all (\k -> k == "const" || k == "type") (KM.keys b) =
          Just s
    stringConst _ = Nothing

-- | The @properties@ map of a schema object, if any.
properties :: Value -> KM.KeyMap Value
properties (Object o) | Just (Object p) <- KM.lookup "properties" o = p
properties _ = KM.empty

--------------------------------------------------------------------------------
-- Default values
--
-- Defaults are not part of the codecs; they live entirely in the @defaults\/@
-- data files (the base layer the resolver merges). The schema therefore takes
-- them as input — the caller loads the per-component @defaults\/<Component>.json@
-- and passes them in — so the documented defaults are exactly the ones the
-- library applies, with a single source of truth.

-- | The whole-configuration schema with the @default@ of every key filled in
-- from the per-component defaults (keyed by component name). Components share a
-- flat top-level key space, so their defaults are merged into one overlay.
wholeConfigSchemaWithDefaults :: [(Text, Value)] -> Value
wholeConfigSchemaWithDefaults defs =
  withDefaults (foldr (deepMerge . snd) (Object KM.empty) defs) wholeConfigSchema

-- | Each component schema with its @default@s filled in from its
-- @defaults\/<Component>.json@ (when one is supplied).
configurationSchemasWithDefaults :: [(Text, Value)] -> [(Text, Value)]
configurationSchemasWithDefaults defs =
  [ (name, maybe s (\d -> withDefaults d s) (lookup name defs))
  | (name, s) <- configurationSchemas
  ]

-- | Fill in the @default@ keywords of a schema from a defaults object (a config
-- object keyed by the configuration keys). Each value is placed at
-- @properties.<key>.default@, recursing into nested objects so leaf defaults
-- land on leaf properties.
withDefaults :: Value -> Value -> Value
withDefaults defaultsObj schema = deepMerge schema (defaultsOverlay defaultsObj)

-- | Turn a defaults object into a schema overlay carrying only @default@s, to be
-- deep-merged into a schema.
defaultsOverlay :: Value -> Value
defaultsOverlay = \case
  Object o -> object ["properties" .= Object (KM.map leaf o)]
  v -> object ["default" .= v]
  where
    leaf v@(Object _) = defaultsOverlay v
    leaf v = object ["default" .= v]

-- | Deep, right-biased merge of two JSON values (objects merge key by key).
deepMerge :: Value -> Value -> Value
deepMerge (Object a) (Object b) = Object (KM.unionWith deepMerge a b)
deepMerge _ b = b
