-- | Golden-ish tests: every example configuration must parse through the
-- autodocodec-derived parsers (and the full file pipeline). This is the most
-- reliable validation we have, since the parser shares its codec with the
-- schema.
--
-- Run from the package directory (as @cabal test@ does), so the @examples/@
-- paths resolve.
module Main (main) where

import Cardano.Configuration.File
import Cardano.Configuration.Schema (wholeConfigSchema)
import Control.Exception (SomeException, evaluate, try)
import Data.Aeson (Value, eitherDecodeFileStrict')
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
          (eitherDecodeFileStrict' "examples/network.json" :: IO (Either String NetworkConfiguration))
      , decodeCase
          "examples/localconnections.json"
          ( eitherDecodeFileStrict' "examples/localconnections.json" ::
              IO (Either String LocalConnectionsConfig)
          )
      , parseCase "examples/fullconfig.json"
      , parseCase "examples/split.json"
      , parseCase "examples/split-all.json"
      , schemaCase
      ]
  let failed = length (filter not results)
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

-- | The committed @config.schema.json@ must match the schema derived from the
-- codecs, so the documented schema cannot drift from the parsers. Regenerate it
-- with @cabal run cardano-config-schema > config.schema.json@.
schemaCase :: IO Bool
schemaCase = do
  let label = "config.schema.json (matches codecs)"
  res <- eitherDecodeFileStrict' "config.schema.json" :: IO (Either String Value)
  case res of
    Left err -> report label (Just ("could not read config.schema.json: " <> err))
    Right committed
      | committed == wholeConfigSchema -> report label Nothing
      | otherwise ->
          report
            label
            ( Just
                "committed config.schema.json is out of date; regenerate with: cabal run cardano-config-schema > config.schema.json"
            )

report :: String -> Maybe String -> IO Bool
report label = \case
  Nothing -> putStrLn ("PASS  " <> label) >> pure True
  Just err -> putStrLn ("FAIL  " <> label <> "\n      " <> err) >> pure False
