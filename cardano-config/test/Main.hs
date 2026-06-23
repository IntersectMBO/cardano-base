-- | Golden-ish tests: every example configuration must parse through the
-- autodocodec-derived parsers (and the full file pipeline). This is the most
-- reliable validation we have, since the parser shares its codec with the
-- schema.
--
-- The @examples/@ and @schemas/@ fixtures are resolved through
-- 'getDataFileName' (they are packaged as @data-files@), so the tests do not
-- depend on the current working directory and work under @cabal test@, Nix and
-- a source distribution alike.
module Main (main) where

import Cardano.Configuration (resolveConfiguration)
import Cardano.Configuration.CliArgs (parseCliArgs)
import Cardano.Configuration.File
import Cardano.Configuration.Schema (configurationSchemasWithDefaults, wholeConfigSchemaWithDefaults)
import Control.Exception (SomeException, evaluate, try)
import Data.Aeson (FromJSON, Value, eitherDecodeFileStrict')
import Data.Functor.Identity (runIdentity)
import Data.List (isInfixOf)
import qualified Data.Text as T
import Options.Applicative (defaultPrefs, execParserPure, getParseResult, info)
import Paths_cardano_config (getDataFileName)
import System.Exit (exitFailure)

main :: IO ()
main = do
  results <-
    sequence
      [ decodeCase
          "examples/storage.json"
          (decodeData "examples/storage.json" :: IO (Either String (StorageConfiguration Maybe)))
      , decodeCase
          "examples/consensus.json"
          (decodeData "examples/consensus.json" :: IO (Either String (ConsensusConfiguration Maybe)))
      , decodeCase
          "examples/protocol.json"
          (decodeData "examples/protocol.json" :: IO (Either String (ProtocolConfiguration Maybe)))
      , decodeCase
          "examples/network.json"
          (decodeData "examples/network.json" :: IO (Either String (NetworkConfiguration Maybe)))
      , decodeCase
          "examples/localconnections.json"
          (decodeData "examples/localconnections.json" :: IO (Either String (LocalConnectionsConfig Maybe)))
      , parseCase "examples/fullconfig.json"
      , parseCase "examples/split.json"
      , parseCase "examples/split-all.json"
      , listMergeCase
      , shadowWarnCase
      , shadowRejectCase
      , resolveCase
      ]
  schemaResults <- schemaCases
  let failed = length (filter not (results <> schemaResults))
  if failed == 0
    then putStrLn "All checks passed"
    else do
      putStrLn $ show failed <> " check(s) failed"
      exitFailure

-- | Decode a packaged data file (resolved via 'getDataFileName') through its
-- 'FromJSON' instance.
decodeData :: FromJSON a => FilePath -> IO (Either String a)
decodeData p = getDataFileName p >>= eitherDecodeFileStrict'

-- | Decode a single example via its 'FromJSON' instance, forcing the result.
decodeCase :: Show a => String -> IO (Either String a) -> IO Bool
decodeCase label act = do
  res <- act
  case res of
    Left err -> report label (Just err)
    Right v -> do
      _ <- evaluate (length (show v))
      report label Nothing

-- | Parse a full configuration file (exercising sub-files).
parseCase :: FilePath -> IO Bool
parseCase fp = do
  path <- getDataFileName fp
  res <- try (parseConfigurationFiles path >>= \c -> evaluate (length (show c)))
  report fp $ case res of
    Left (e :: SomeException) -> Just (show e)
    Right _ -> Nothing

-- | A section given as a list of sources is deep-merged in order, with later
-- entries overriding earlier ones (and the always-read base default beneath).
-- @network-b.json@ sets @TargetNumberOfActivePeers@ to 99, overriding the 10 in
-- @network-a.json@.
listMergeCase :: IO Bool
listMergeCase = do
  let label = "examples/split-list.json (list merge, later overrides)"
  path <- getDataFileName "examples/split-list.json"
  res <- try (parseConfigurationFiles path)
  case res of
    Left (e :: SomeException) -> report label (Just (show e))
    Right c ->
      let active = deadlineTargetOfActivePeers (runIdentity (networkConfiguration c))
       in if active == Just 99
            then report label Nothing
            else report label (Just ("expected TargetNumberOfActivePeers = 99, got " <> show active))

-- | A top-level key belonging to a component that is also supplied as its own
-- section (here a top-level @DijkstraGenesisFile@ alongside a @TestingConfig@
-- section) is shadowed. Under the default policy this only warns, so parsing
-- succeeds.
shadowWarnCase :: IO Bool
shadowWarnCase = do
  let label = "examples/shadow.json (shadowed top-level key warns, still parses)"
  path <- getDataFileName "examples/shadow.json"
  res <- try (parseConfigurationFiles path >>= \c -> evaluate (length (show c)))
  report label $ case res of
    Left (e :: SomeException) -> Just (show e)
    Right _ -> Nothing

-- | The same shadowed key is a hard error under 'RejectUnknownKeys', and the
-- error names the offending key.
shadowRejectCase :: IO Bool
shadowRejectCase = do
  let label = "examples/shadow.json (shadowed top-level key rejected under strict policy)"
  path <- getDataFileName "examples/shadow.json"
  res <- try (parseConfigurationFilesWith RejectUnknownKeys path)
  case res of
    Left (e :: SomeException)
      | "DijkstraGenesisFile" `isInfixOf` show e -> report label Nothing
      | otherwise -> report label (Just ("rejected, but with an unexpected error: " <> show e))
    Right _ -> report label (Just "expected rejection under RejectUnknownKeys, but parsing succeeded")

-- | Resolving a parsed configuration with default CLI arguments must succeed and
-- produce a complete (@Identity@) configuration, which exercises that the base
-- defaults populate every resolved field.
resolveCase :: IO Bool
resolveCase = do
  let label = "resolveConfiguration examples/fullconfig.json"
  path <- getDataFileName "examples/fullconfig.json"
  cfg <- parseConfigurationFiles path
  case getParseResult (execParserPure defaultPrefs (info parseCliArgs mempty) []) of
    Nothing -> report label (Just "could not build default CLI arguments")
    Just cli -> case resolveConfiguration cli cfg of
      Left err -> report label (Just (show err))
      Right nc -> evaluate (length (show nc)) >> report label Nothing

-- | The committed schemas under @schemas/@ (the whole configuration and one per
-- component) must match the schema derived from the codecs, so the documented
-- schema cannot drift from the parsers. Regenerate them with @scripts/gen-schemas.sh@.
schemaCases :: IO [Bool]
schemaCases = do
  defs <- componentDefaults
  sequence $
    schemaFile "schemas/config.schema.json" (wholeConfigSchemaWithDefaults defs)
      : [ schemaFile ("schemas/" <> T.unpack name <> ".schema.json") schema
        | (name, schema) <- configurationSchemasWithDefaults defs
        ]

-- | Assert that a committed schema file equals the given derived schema.
schemaFile :: FilePath -> Value -> IO Bool
schemaFile path expected = do
  let label = path <> " (matches codecs)"
  full <- getDataFileName path
  res <- eitherDecodeFileStrict' full :: IO (Either String Value)
  case res of
    Left err -> report label (Just ("could not read " <> path <> ": " <> err))
    Right committed
      | committed == expected -> report label Nothing
      | otherwise ->
          report label (Just (path <> " is out of date; regenerate with scripts/gen-schemas.sh"))

report :: String -> Maybe String -> IO Bool
report label = \case
  Nothing -> putStrLn ("PASS  " <> label) >> pure True
  Just err -> putStrLn ("FAIL  " <> label <> "\n      " <> err) >> pure False
