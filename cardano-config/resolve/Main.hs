-- | A small tool that resolves a @cardano-node@ configuration and prints the
-- complete result: the per-component defaults (@defaults/@), the configuration
-- file (including any @Custom@ override layer) and the CLI flags, all merged and
-- resolved exactly as a node would do it.
--
-- It takes the same CLI flags as the node (see 'parseCliArgs'); in particular
-- @--config@ selects the configuration file. The resolved configuration is
-- printed to @stdout@ and any parsing or resolution error to @stderr@.
module Main (main) where

import Cardano.Configuration (parseConfigurationFiles, resolveConfiguration)
import Cardano.Configuration.CliArgs (configFilePath, parseCliArgs)
import Control.Exception (SomeException, displayException, try)
import Options.Applicative (execParser, fullDesc, helper, info, progDesc, (<**>))
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import Text.Show.Pretty (ppShow)

main :: IO ()
main = do
  cli <- execParser opts
  result <- try (parseConfigurationFiles (configFilePath cli))
  case result of
    Left err -> die (displayException (err :: SomeException))
    Right file -> case resolveConfiguration cli file of
      Left err -> die (displayException err)
      Right nc -> putStrLn (ppShow nc)
  where
    opts =
      info
        (parseCliArgs <**> helper)
        ( fullDesc
            <> progDesc
              ( "Resolve a cardano-node configuration (defaults + configuration file, "
                  <> "including any Custom override, + CLI flags) and print the complete result."
              )
        )

-- | Print a message to @stderr@ and exit with a failure status.
die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitFailure
