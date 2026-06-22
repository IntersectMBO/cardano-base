-- | A small tool to dump the configuration JSON Schema.
module Main (main) where

import Cardano.Configuration.Schema (configurationSchemas, wholeConfigSchema)
import Data.Aeson (Value)
import Data.Aeson.Encode.Pretty (Config (..), defConfig, encodePretty')
import qualified Data.ByteString.Lazy.Char8 as L
import Data.List (intercalate)
import qualified Data.Text as T
import System.Environment (getArgs, getProgName)
import System.Exit (exitFailure, exitSuccess)
import System.IO (Handle, hPutStrLn, stderr, stdout)

main :: IO ()
main =
  getArgs >>= \case
    [] -> dump wholeConfigSchema
    [a] | a `elem` ["-h", "--help"] -> printHelp stdout >> exitSuccess
    ["--list"] -> mapM_ (putStrLn . T.unpack . fst) configurationSchemas
    [name] ->
      case lookup (T.pack name) configurationSchemas of
        Just s -> dump s
        Nothing -> do
          hPutStrLn stderr $ "Unknown component: " <> name <> "\n"
          printHelp stderr
          exitFailure
    _ -> do
      hPutStrLn stderr "Expected at most one argument.\n"
      printHelp stderr
      exitFailure

-- | Print usage information, including the available component names.
printHelp :: Handle -> IO ()
printHelp h = do
  prog <- getProgName
  hPutStrLn h $
    unlines
      [ "Print the cardano-node configuration JSON Schema."
      , ""
      , "Usage:"
      , "  " <> prog <> "                dump the schema for the whole configuration"
      , "  " <> prog <> " <COMPONENT>    dump the schema for a single component"
      , "  " <> prog <> " --list         list the available component names"
      , "  " <> prog <> " --help, -h     show this help"
      , ""
      , "Components:"
      , "  " <> intercalate ", " (map (T.unpack . fst) configurationSchemas)
      , ""
      , "The schema is printed to stdout as JSON. To validate a configuration file"
      , "against it, write it to a file and use a JSON Schema validator, e.g.:"
      , "  " <> prog <> " > schemas/config.schema.json"
      , "  check-jsonschema --schemafile schemas/config.schema.json my-config.json"
      ]

-- | Print a schema with sorted keys for stable output.
dump :: Value -> IO ()
dump = L.putStrLn . encodePretty' defConfig {confCompare = compare}
