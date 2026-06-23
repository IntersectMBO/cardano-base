-- | Golden-ish tests: every example configuration must parse through the
-- autodocodec-derived parsers (and the full file pipeline). This is the most
-- reliable validation we have, since the parser shares its codec with the
-- schema.
--
-- Run from the package directory (as @cabal test@ does), so the @examples/@
-- paths resolve.
module Main (main) where

import Cardano.Configuration (resolveConfiguration)
import Cardano.Configuration.CliArgs (parseCliArgs)
import Cardano.Configuration.File
import Cardano.Configuration.Schema (configurationSchemas, wholeConfigSchema)
import Control.Exception (SomeException, evaluate, try)
import Data.Aeson (Value, eitherDecodeFileStrict')
import Data.Functor.Identity (runIdentity)
import qualified Data.Text as T
import Options.Applicative (defaultPrefs, execParserPure, getParseResult, info)
import System.Exit (exitFailure)

main :: IO ()
main = do
  results <-
    sequence
      [ decodeCase
          "examples/storage.json"
          (eitherDecodeFileStrict' "examples/storage.json" :: IO (Either String (StorageConfiguration Maybe)))
      , decodeCase
          "examples/consensus.json"
          ( eitherDecodeFileStrict' "examples/consensus.json" ::
              IO (Either String (ConsensusConfiguration Maybe))
          )
      , decodeCase
          "examples/protocol.json"
          (eitherDecodeFileStrict' "examples/protocol.json" :: IO (Either String (ProtocolConfiguration Maybe)))
      , decodeCase
          "examples/network.json"
          (eitherDecodeFileStrict' "examples/network.json" :: IO (Either String (NetworkConfiguration Maybe)))
      , decodeCase
          "examples/localconnections.json"
          ( eitherDecodeFileStrict' "examples/localconnections.json" ::
              IO (Either String (LocalConnectionsConfig Maybe))
          )
      , parseCase "examples/fullconfig.json"
      , parseCase "examples/split.json"
      , parseCase "examples/split-all.json"
      , listMergeCase
      , resolveCase
      ]
  schemaResults <- schemaCases
  let failed = length (filter not (results <> schemaResults))
  if failed == 0
    then putStrLn "All checks passed"
    else do
      putStrLn $ show failed <> " check(s) failed"
      exitFailure

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
  res <- try (parseConfigurationFiles fp >>= \c -> evaluate (length (show c)))
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
  res <- try (parseConfigurationFiles "examples/split-list.json")
  case res of
    Left (e :: SomeException) -> report label (Just (show e))
    Right c ->
      let active = deadlineTargetOfActivePeers (runIdentity (networkConfiguration c))
       in if active == Just 99
            then report label Nothing
            else report label (Just ("expected TargetNumberOfActivePeers = 99, got " <> show active))

-- | Resolving a parsed configuration with default CLI arguments must succeed and
-- produce a complete (@Identity@) configuration, which exercises that the base
-- defaults populate every resolved field.
resolveCase :: IO Bool
resolveCase = do
  let label = "resolveConfiguration examples/fullconfig.json"
  cfg <- parseConfigurationFiles "examples/fullconfig.json"
  case getParseResult (execParserPure defaultPrefs (info parseCliArgs mempty) []) of
    Nothing -> report label (Just "could not build default CLI arguments")
    Just cli -> case resolveConfiguration cli cfg of
      Left err -> report label (Just (show err))
      Right nc -> evaluate (length (show nc)) >> report label Nothing

-- | The committed schemas under @schemas/@ (the whole configuration and one per
-- component) must match the schema derived from the codecs, so the documented
-- schema cannot drift from the parsers. Regenerate them with @scripts/gen-schemas.sh@.
schemaCases :: IO [Bool]
schemaCases =
  sequence $
    schemaFile "schemas/config.schema.json" wholeConfigSchema
      : [ schemaFile ("schemas/" <> T.unpack name <> ".schema.json") schema
        | (name, schema) <- configurationSchemas
        ]

-- | Assert that a committed schema file equals the given derived schema.
schemaFile :: FilePath -> Value -> IO Bool
schemaFile path expected = do
  let label = path <> " (matches codecs)"
  res <- eitherDecodeFileStrict' path :: IO (Either String Value)
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
