module Cardano.Configuration.CliArgs (
  -- * CLI Arguments
  CliArgs (..),
  parseCliArgs,
  ShutdownOn (..),

  -- * Tracing
  TracerConnectionMethod (..),
  TracerConnection (..),

  -- * Credentials
  Credentials (..),
  KESSource (..),

  -- * Individual option parsers

  -- These are exported so that other tools (e.g. @cardano-cli@) can reuse the
  -- exact same flags, metavars and help text as @cardano-node@.
  parseConfigFile,
  parseTopologyFile,
  parseSocketPath,
  parseValidateDB,
  parseEnableRpc,
  parseRpcSocketPath,
  parseCredentials,
  parseKESSource,
  parseHostIPv4Addr,
  parseHostIPv6Addr,
  parsePort,
  parseTracerSocketMode,
  parseShutdownIPC,
  parseShutdownOn,

  -- ** Argument readers
  parseNodeAddress,
  parseHostPort,
  parseNodeHostIPv4Address,
  parseNodeHostIPv6Address,
) where

import Cardano.Configuration.Common
import Control.Monad (when)
import Data.Bifunctor (second)
import Data.IP (IPv4, IPv6)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Word (Word64)
import Network.Socket (PortNumber)
import Network.URI (URI (..), URIAuth (..), parseURIReference)
import Options.Applicative
import System.Posix.Types (Fd (..))
import Text.Read (readEither, readMaybe)

data ShutdownOn
  = ShutdownAtSlot Word64
  | ShutdownAtBlock Word64
  deriving (Show)

type Host = Text

data TracerConnectionMethod
  = TracerConnectViaPipe FilePath
  | TracerConnectViaRemote Host PortNumber
  deriving (Show)

data TracerConnection
  = TracerConnection String TracerConnectionMethod
  deriving (Show)

data KESSource
  = KESKeyFilePath FilePath
  | KESAgentSocketPath FilePath
  deriving (Eq, Show)

data Credentials = Credentials
  { byronDelegationCertificate :: Maybe FilePath
  , byronSigningKey :: Maybe FilePath
  , shelleyKES :: Maybe KESSource
  , shelleyVRFKey :: Maybe FilePath
  , shelleyOperationalCertificate :: Maybe FilePath
  , bulkCredentialsFile :: Maybe FilePath
  }
  deriving (Show)

-- | The CLI arguments, parsed with 'parseCliArgs'
data CliArgs = CliArgs
  { configFilePath :: FilePath
  , topologyFile :: FilePath
  , databasePathCLI :: Maybe NodeDatabasePaths
  , validateDatabase :: Bool
  , socketPath :: Maybe FilePath
  , credentials :: Credentials
  , startAsNonProducingNode :: Maybe Bool
  , hostAddr :: Maybe IPv4
  , hostIPv6Addr :: Maybe IPv6
  , port :: Maybe PortNumber
  , tracerSocket :: Maybe TracerConnection
  , shutdownIPC :: Maybe Fd
  , shutdownOnTarget :: Maybe ShutdownOn
  , enableRpcCLI :: Maybe Bool
  , rpcSocketPathCLI :: Maybe FilePath
  }
  deriving (Show)

parseCredentials :: Parser Credentials
parseCredentials =
  Credentials
    <$> optional parseByronDelegationCert
    <*> optional parseByronSigningKey
    <*> optional parseKESSource
    <*> optional parseVrfKeyFilePath
    <*> optional parseOperationalCertFilePath
    <*> optional parseBulkCredsFilePath

parseCliArgs :: Parser CliArgs
parseCliArgs =
  CliArgs
    <$> parseConfigFile
    <*> parseTopologyFile
    <*> parserOptionGroup "Storage:" parseNodeDatabasePaths
    <*> parserOptionGroup "Storage:" parseValidateDB
    <*> optional parseSocketPath
    <*> parserOptionGroup "Credentials:" parseCredentials
    <*> parserOptionGroup "Credentials:" parseStartAsNonProducingNode
    <*> parserOptionGroup "Host:" (optional parseHostIPv4Addr)
    <*> parserOptionGroup "Host:" (optional parseHostIPv6Addr)
    <*> parserOptionGroup "Host:" (optional parsePort)
    <*> parserOptionGroup "Tracing:" (optional parseTracerSocketMode)
    <*> parserOptionGroup "Shutdown:" (optional parseShutdownIPC)
    <*> parserOptionGroup "Shutdown:" (optional parseShutdownOn)
    <*> optional parseEnableRpc
    <*> optional parseRpcSocketPath

parseTopologyFile :: Parser FilePath
parseTopologyFile =
  strOption $
    mconcat
      [ long "topology"
      , metavar "FILEPATH"
      , help "The path to a file describing the topology"
      , completer (bashCompleter "file")
      , value "configuration/cardano/mainnet-topology.json"
      , showDefault
      ]

parseValidateDB :: Parser Bool
parseValidateDB =
  switch $
    mconcat
      [ long "validate-db"
      , help "Validate all on-disk database files"
      ]

parseSocketPath :: Parser FilePath
parseSocketPath =
  strOption $
    mconcat
      [ long "socket-path"
      , help "Path to create a socket for local clients"
      , metavar "FILEPATH"
      , completer (bashCompleter "file")
      ]

parseEnableRpc :: Parser Bool
parseEnableRpc =
  flag' True $
    mconcat
      [ long "grpc-enable"
      , help "[EXPERIMENTAL] Enable node gRPC endpoint."
      ]

parseRpcSocketPath :: Parser FilePath
parseRpcSocketPath =
  strOption $
    mconcat
      [ long "grpc-socket-path"
      , metavar "FILEPATH"
      , help "[EXPERIMENTAL] gRPC socket path. Defaults to rpc.sock in the same directory as node socket."
      , completer (bashCompleter "file")
      ]

parseConfigFile :: Parser FilePath
parseConfigFile =
  strOption $
    mconcat
      [ long "config"
      , metavar "FILEPATH"
      , help "Configuration file for the cardano-node"
      , completer (bashCompleter "file")
      , value "configuration/cardano/mainnet-config.json"
      , showDefault
      ]

parseHostIPv4Addr :: Parser IPv4
parseHostIPv4Addr =
  option
    (eitherReader parseNodeHostIPv4Address)
    $ mconcat
      [ long "host-addr"
      , metavar "IPV4"
      , help "An optional IPv4 address"
      ]

parseHostIPv6Addr :: Parser IPv6
parseHostIPv6Addr =
  option
    (eitherReader parseNodeHostIPv6Address)
    $ mconcat
      [ long "host-ipv6-addr"
      , metavar "IPV6"
      , help "An optional IPv6 address"
      ]

parseNodeHostIPv4Address :: String -> Either String IPv4
parseNodeHostIPv4Address s =
  maybe
    ( Left $
        "Failed to parse IPv4 address: "
          ++ s
          ++ ". If you want to specify an IPv6 address, use --host-ipv6-addr option."
    )
    Right
    (readMaybe s)

parseNodeHostIPv6Address :: String -> Either String IPv6
parseNodeHostIPv6Address s =
  maybe
    ( Left $
        "Failed to parse IPv6 address: "
          ++ s
          ++ ". If you want to specify an IPv4 address, use --host-addr option."
    )
    Right
    (readMaybe s)

parsePort :: Parser PortNumber
parsePort =
  option
    (fromIntegral <$> auto @Int)
    $ mconcat
      [ long "port"
      , metavar "PORT"
      , help "The port number"
      , value 0 -- Use an ephemeral port
      ]

parseByronDelegationCert :: Parser FilePath
parseByronDelegationCert =
  strOption $
    mconcat
      [ long "byron-delegation-certificate"
      , metavar "FILEPATH"
      , help "Path to the delegation certificate"
      , completer (bashCompleter "file")
      ]

parseByronSigningKey :: Parser FilePath
parseByronSigningKey =
  strOption $
    mconcat
      [ long "byron-signing-key"
      , metavar "FILEPATH"
      , help "Path to the Byron signing key"
      , completer (bashCompleter "file")
      ]

parseOperationalCertFilePath :: Parser FilePath
parseOperationalCertFilePath =
  strOption $
    mconcat
      [ long "shelley-operational-certificate"
      , metavar "FILEPATH"
      , help "Path to the delegation certificate"
      , completer (bashCompleter "file")
      ]

parseBulkCredsFilePath :: Parser FilePath
parseBulkCredsFilePath =
  strOption $
    mconcat
      [ long "bulk-credentials-file"
      , metavar "FILEPATH"
      , help "Path to the bulk pool credentials file"
      , completer (bashCompleter "file")
      ]

-- TODO: pass the current KES evolution, not the KES_0
parseKESSource :: Parser KESSource
parseKESSource =
  asum
    [ KESKeyFilePath
        <$> strOption
          ( mconcat
              [ long "shelley-kes-key"
              , metavar "FILEPATH"
              , help "Path to the KES signing key."
              , completer (bashCompleter "file")
              ]
          )
    , KESAgentSocketPath
        <$> strOption
          ( mconcat
              [ long "shelley-kes-agent-socket"
              , metavar "SOCKET_FILEPATH"
              , help "Path to the KES Agent socket"
              , completer (bashCompleter "file")
              ]
          )
    ]

parseVrfKeyFilePath :: Parser FilePath
parseVrfKeyFilePath =
  strOption $
    mconcat
      [ long "shelley-vrf-key"
      , metavar "FILEPATH"
      , help "Path to the VRF signing key"
      , completer (bashCompleter "file")
      ]

parseNodeAddress :: ReadM (Host, PortNumber)
parseNodeAddress = eitherReader parseHostPort

-- | Parse a @HOST:PORT@ pair. IPv6 addresses must be bracketed
-- (@[2001:db8::1]:3001@) to disambiguate the address colons from the
-- host/port separator; IPv4 addresses and hostnames are written bare
-- (@127.0.0.1:3001@).
--
-- This follows the URI authority syntax of RFC 3986 (§3.2.2), where an IPv6
-- literal is wrapped in brackets, which is what 'parseURIReference' implements.
-- The address inside the brackets is any representation accepted there (see
-- RFC 5952 for the recommended IPv6 text form). Note this is /not/ the SMTP
-- address-literal form of RFC 5321 (@[IPv6:...]@), which is a different syntax.
parseHostPort :: String -> Either String (Host, PortNumber)
parseHostPort s = do
  -- Parse as the authority component of a URI reference ("//host:port"), which
  -- handles bracketed IPv6, IPv4 and hostnames uniformly.
  uri <-
    maybe (Left ("parseHostPort: could not parse HOST:PORT from " ++ show s)) Right $
      parseURIReference ("//" ++ s)
  auth <- maybe (Left "parseHostPort: missing host and port.") Right (uriAuthority uri)
  let host = stripBrackets (uriRegName auth)
  when (null host) $ Left "parseHostPort: empty host."
  portStr <- case uriPort auth of
    ':' : p -> Right p
    _ -> Left "parseHostPort: missing port."
  p <-
    maybe (Left ("parseHostPort: non-numeric port " ++ show portStr)) Right (readMaybe @Integer portStr)
  if 0 <= p && p <= 65535
    then Right (Text.pack host, fromInteger p)
    else Left ("parseHostPort: port " ++ show p ++ " out of range: 0 - 65535.")
  where
    stripBrackets ('[' : rest) | not (null rest) && last rest == ']' = init rest
    stripBrackets other = other

parseTracerSocketMode :: Parser TracerConnection
parseTracerSocketMode =
  fmap (uncurry TracerConnection) $
    fmap
      (second (uncurry TracerConnectViaRemote))
      ( asum
          [ fmap ("Accept",) $
              option parseNodeAddress $
                mconcat
                  [ long "tracer-socket-network-accept"
                  , help "Accept incoming cardano-tracer connection on HOST:PORT"
                  , metavar "HOST:PORT"
                  ]
          , fmap ("Connect",) $
              option parseNodeAddress $
                mconcat
                  [ long "tracer-socket-network-connect"
                  , help "Connect to cardano-tracer listening on HOST:PORT"
                  , metavar "HOST:PORT"
                  ]
          ]
      )
      <|> fmap
        (second TracerConnectViaPipe)
        ( asum
            [ fmap ("Accept",) $
                strOption $
                  mconcat
                    [ long "tracer-socket-path-accept"
                    , help "Accept incoming cardano-tracer connection at local socket"
                    , completer (bashCompleter "file")
                    , metavar "FILEPATH"
                    ]
            , fmap ("Connect",) $
                strOption $
                  mconcat
                    [ long "tracer-socket-path-connect"
                    , help "Connect to cardano-tracer listening on a local socket"
                    , completer (bashCompleter "file")
                    , metavar "FILEPATH"
                    ]
            ]
        )

parseShutdownIPC :: Parser Fd
parseShutdownIPC =
  option
    (Fd <$> auto)
    $ mconcat
      [ long "shutdown-ipc"
      , metavar "FD"
      , help "Shut down the process when this inherited FD reaches EOF"
      , hidden
      ]

parseShutdownOn :: Parser ShutdownOn
parseShutdownOn =
  asum
    [ option (ShutdownAtSlot <$> bounded "SLOT") $
        mconcat
          [ long "shutdown-on-slot-synced"
          , metavar "SLOT"
          , help "Shut down the process after ChainDB is synced up to the specified slot"
          , hidden
          ]
    , option (ShutdownAtBlock <$> bounded "BLOCK") $
        mconcat
          [ long "shutdown-on-block-synced"
          , metavar "BLOCK"
          , help "Shut down the process after ChainDB is synced up to the specified block"
          , hidden
          ]
    ]
  where
    bounded :: forall a. (Bounded a, Integral a, Show a) => String -> ReadM a
    bounded t = eitherReader $ \s -> do
      i <- readEither @Integer s
      when (i < fromIntegral (minBound @a)) $ Left $ t <> " must not be less than " <> show (minBound @a)
      when (i > fromIntegral (maxBound @a)) $ Left $ t <> " must not greater than " <> show (maxBound @a)
      pure (fromIntegral i)
