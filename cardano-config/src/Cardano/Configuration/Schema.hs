-- | JSON Schemas for the configuration components, derived directly from the
-- autodocodec codecs (so they cannot drift from the parsers).
--
-- Each schema records which keys are required, which are optional, and the
-- defaults applied at parse time (e.g. the @Backend@ or @EnableCSJ@ defaults).
-- Keys that are merely left unset for the node to default appear as optional
-- without a value.
--
-- Tracing keys are surfaced here only as an informational placeholder (the
-- @Tracing@ component): the node resolves them through its tracing system
-- (hermod/@trace-dispatcher@), whose authoritative configuration schema lives in
-- that package. They appear so that users can see the keys exist; their contents
-- are not validated here.
module Cardano.Configuration.Schema (
  -- * Whole configuration
  wholeConfigSchema,
  recognisedKeys,

  -- * Individual components
  configurationSchemas,
  storageSchema,
  consensusSchema,
  protocolSchema,
  networkSchema,
  localConnectionsSchema,
  mempoolSchema,
  testingSchema,
  tracingSchema,
) where

import Autodocodec.Schema (jsonSchemaViaCodec)
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

storageSchema :: Value
storageSchema = polish rawStorageSchema

consensusSchema :: Value
consensusSchema = polish rawConsensusSchema

protocolSchema :: Value
protocolSchema = polish rawProtocolSchema

networkSchema :: Value
networkSchema = polish rawNetworkSchema

localConnectionsSchema :: Value
localConnectionsSchema = polish rawLocalConnectionsSchema

mempoolSchema :: Value
mempoolSchema = polish rawMempoolSchema

testingSchema :: Value
testingSchema = polish rawTestingSchema

-- | The tracing keys, surfaced as an informational placeholder. Their contents
-- are owned and validated by @trace-dispatcher@, not by @cardano-config@.
tracingSchema :: Value
tracingSchema = polish rawTracingSchema

-- The raw schemas as emitted by autodocodec-schema (descriptions in @$comment@,
-- no @$schema@). Used internally for merging; 'polish' makes them public.
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

rawComponentSchemas :: [(Text, Value)]
rawComponentSchemas =
  [ ("Storage", rawStorageSchema)
  , ("Consensus", rawConsensusSchema)
  , ("Protocol", rawProtocolSchema)
  , ("Network", rawNetworkSchema)
  , ("LocalConnections", rawLocalConnectionsSchema)
  , ("Mempool", rawMempoolSchema)
  , ("Testing", rawTestingSchema)
  , ("Tracing", rawTracingSchema)
  ]

-- | The JSON Schema of each configuration component, keyed by name.
configurationSchemas :: [(Text, Value)]
configurationSchemas = [(name, polish s) | (name, s) <- rawComponentSchemas]

-- | The JSON Schema of the whole configuration in its single-file form, built
-- by merging the component schemas (every component reads its keys from the
-- same top-level object).
--
-- Note: the tracing keys appear only as an opaque placeholder (resolved by the
-- node's tracing system; see the module header). This also does not cover the
-- alternative split-file form in which a component key (e.g. @Storage@) is
-- instead a path to a sub-file.
wholeConfigSchema :: Value
wholeConfigSchema =
  polish $
    object
      [ "$comment" .= ("The cardano-node configuration (single-file form)" :: Text)
      , "type" .= ("object" :: Text)
      , "properties" .= Object (foldr (KM.union . properties) KM.empty rawSchemas)
      , "required" .= concatMap required rawSchemas
      ]
  where
    rawSchemas = map snd rawComponentSchemas
    properties (Object o) | Just (Object p) <- KM.lookup "properties" o = p
    properties _ = KM.empty
    required (Object o) | Just (Array a) <- KM.lookup "required" o = toList a
    required _ = []

-- | Every top-level configuration key the parsers recognise: the keys of all
-- components (read at the top level in the single-file form), the section keys
-- used to reference split sub-files, and the envelope keys. Used to detect
-- unrecognised (e.g. misspelled) keys.
recognisedKeys :: [Text]
recognisedKeys =
  nub $
    envelopeKeys <> sectionKeys <> concatMap (propertyNames . snd) rawComponentSchemas
  where
    envelopeKeys = ["Version", "Configuration"]
    sectionKeys = map fst rawComponentSchemas
    propertyNames (Object o)
      | Just (Object p) <- KM.lookup "properties" o = map K.toText (KM.keys p)
    propertyNames _ = []

-- | The JSON Schema draft these schemas target. autodocodec-schema emits
-- draft-07-compatible schemas (only @oneOf@/@anyOf@/@const@/@properties@/
-- @required@/@description@), and draft-07 is what validators such as ajv accept
-- by default.
draftURI :: Text
draftURI = "http://json-schema.org/draft-07/schema#"

-- | Make a schema friendlier to validators and editors: declare the draft and
-- turn autodocodec's @$comment@ annotations into @description@s (which editors
-- surface on hover and completion).
polish :: Value -> Value
polish v = case toDescriptions v of
  Object o -> Object (KM.insert "$schema" (String draftURI) o)
  other -> other

toDescriptions :: Value -> Value
toDescriptions = \case
  Object o -> Object (KM.fromList [(rename k, toDescriptions val) | (k, val) <- KM.toList o])
  Array a -> Array (fmap toDescriptions a)
  other -> other
  where
    rename k = if k == "$comment" then "description" else k
