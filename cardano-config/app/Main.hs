-- | The @cardano-config@ command-line tool. It exposes two subcommands:
--
--   * @cardano-config resolve@ resolves a @cardano-node@ configuration
--     (per-component defaults, the configuration file and the CLI flags),
--     merging and resolving it exactly as a node would, and prints the complete
--     result as YAML.
--
--   * @cardano-config schema@ dumps the configuration JSON Schema (for the
--     whole configuration or a single component), derived from the same codecs.
module Main (main) where

import Cardano.Configuration (parseConfigurationFiles, resolveConfiguration)
import Cardano.Configuration.CliArgs (CliArgs, configFilePath, parseCliArgs)
import Cardano.Configuration.File (componentDefaults)
import Cardano.Configuration.Render (nodeConfigurationToJSON)
import Cardano.Configuration.Schema (
  configurationSchemas,
  configurationSchemasWithDefaults,
  wholeConfigSchemaWithDefaults,
 )
import Control.Exception (SomeException, displayException, try)
import Data.Aeson (Value)
import Data.Aeson.Encode.Pretty (Config (..), defConfig, encodePretty')
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as L
import Data.List (intercalate)
import qualified Data.Text as T
import Data.Yaml.Pretty (encodePretty, setConfCompare, setConfDropNull)
import qualified Data.Yaml.Pretty as Yaml
import Options.Applicative
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

-- | The top-level command selected on the command line.
data Command
  = -- | @resolve@: resolve a configuration with the given node flags.
    Resolve CliArgs
  | -- | @schema@: dump a JSON Schema.
    Schema SchemaCmd

-- | What the @schema@ subcommand should print.
data SchemaCmd
  = -- | List the available component names.
    SchemaList
  | -- | Dump the whole-configuration schema, or a single named component.
    SchemaComponent (Maybe String)

main :: IO ()
main = execParser opts >>= run
  where
    opts =
      info
        (commandParser <**> helper)
        ( fullDesc
            <> progDesc "Parse, resolve and document the cardano-node configuration."
        )

-- | The full command-line parser: a subcommand tree.
commandParser :: Parser Command
commandParser =
  hsubparser
    ( command
        "resolve"
        ( info
            (Resolve <$> parseCliArgs)
            ( progDesc
                ( "Resolve a cardano-node configuration (defaults + configuration file + CLI flags) "
                    <> "and print the complete result as YAML."
                )
            )
        )
        <> command
          "schema"
          ( info
              (Schema <$> schemaParser)
              (progDesc "Print the cardano-node configuration JSON Schema.")
          )
    )

-- | Parser for the @schema@ subcommand options.
schemaParser :: Parser SchemaCmd
schemaParser =
  flag'
    SchemaList
    (long "list" <> help "List the available component names.")
    <|> ( SchemaComponent
            <$> optional
              ( strArgument
                  ( metavar "COMPONENT"
                      <> help "Dump the schema for a single component (default: the whole configuration)."
                  )
              )
        )

-- | Execute the selected command.
run :: Command -> IO ()
run (Resolve cli) = runResolve cli
run (Schema cmd) = runSchema cmd

-- | Resolve a configuration and print it as YAML.
runResolve :: CliArgs -> IO ()
runResolve cli = do
  result <- try (parseConfigurationFiles (configFilePath cli))
  case result of
    Left err -> die (displayException (err :: SomeException))
    Right file -> case resolveConfiguration cli file of
      Left err -> die (displayException err)
      Right nc -> BS.putStr (encodePretty yamlConfig (nodeConfigurationToJSON nc))
  where
    -- Stable, readable output: keys sorted alphabetically, unset values omitted.
    yamlConfig = setConfDropNull True (setConfCompare compare Yaml.defConfig)

-- | Print a JSON Schema, or list the component names.
runSchema :: SchemaCmd -> IO ()
runSchema SchemaList = mapM_ (putStrLn . T.unpack . fst) configurationSchemas
runSchema (SchemaComponent Nothing) = do
  defs <- componentDefaults
  dump (wholeConfigSchemaWithDefaults defs)
runSchema (SchemaComponent (Just name)) = do
  defs <- componentDefaults
  case lookup (T.pack name) (configurationSchemasWithDefaults defs) of
    Just s -> dump s
    Nothing ->
      die $
        "Unknown component: "
          <> name
          <> "\nAvailable components: "
          <> intercalate ", " (map (T.unpack . fst) configurationSchemas)

-- | Print a schema with sorted keys for stable output.
dump :: Value -> IO ()
dump = L.putStrLn . encodePretty' defConfig {confCompare = compare}

-- | Print a message to @stderr@ and exit with a failure status.
die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitFailure
