-- | Types that are common to CLI arguments and the configuration files
module Cardano.Configuration.Common (
  NodeDatabasePaths (..),
  parseNodeDatabasePaths,
  parseStartAsNonProducingNode,

  -- * File paths
  filePathCodec,
  filePathFormatMarker,
) where

import Autodocodec
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import GHC.Generics
import Options.Applicative

--------------------------------------------------------------------------------

-- | A JSON string codec for a filesystem path. It encodes exactly like the
-- plain 'FilePath' codec, but carries a sentinel comment ('filePathFormatMarker')
-- that the schema post-processing (in "Cardano.Configuration.Schema") lifts into
-- a @"format": "path"@ annotation, so tooling and editors can tell the value is
-- a path rather than an arbitrary string.
filePathCodec :: JSONCodec FilePath
filePathCodec = codec @FilePath <?> filePathFormatMarker

-- | The sentinel comment that marks a string as a filesystem path. The schema
-- post-processing recognises it, turns it into @"format": "path"@ and strips it
-- from the description. See 'filePathCodec'.
filePathFormatMarker :: Text
filePathFormatMarker = "format:path"

--------------------------------------------------------------------------------

-- | The databases that will be used by the node
data NodeDatabasePaths
  = -- | Store everything in a single directory
    SingleDB FilePath
  | -- | Store the immutable data in one (possibly slower) directory and the
    -- volatile data in a different (possible faster) directory
    SplitDB FilePath FilePath
  deriving (Generic, Show)

-- | A single database is a JSON string (a path); a split database is a JSON
-- object. We dispatch on that shape so a malformed split-database object reports
-- its own failure rather than alongside the irrelevant "expected String" failure
-- of the single-path branch.
instance HasCodec NodeDatabasePaths where
  codec =
    matchChoiceCodec
      (dimapCodec SingleDB id filePathCodec)
      (dimapCodec (uncurry SplitDB) id splitDbCodec)
      selector
    where
      splitDbCodec =
        object "SplitDB" $
          (,)
            <$> requiredFieldWith "ImmutablePath" filePathCodec "Directory for the immutable database" .= fst
            <*> requiredFieldWith "VolatilePath" filePathCodec "Directory for the volatile database" .= snd
      selector (SingleDB fp) = Left fp
      selector (SplitDB i v) = Right (i, v)

deriving via (Autodocodec NodeDatabasePaths) instance FromJSON NodeDatabasePaths

deriving via (Autodocodec NodeDatabasePaths) instance ToJSON NodeDatabasePaths

parseNodeDatabasePaths :: Parser (Maybe NodeDatabasePaths)
parseNodeDatabasePaths =
  optional $ parseMultipleDbPaths <|> parseDbPath

parseDbPath :: Parser NodeDatabasePaths
parseDbPath =
  fmap SingleDB $
    strOption $
      mconcat
        [ long "database-path"
        , metavar "FILEPATH"
        , help "Directory where the state is stored"
        , completer (bashCompleter "file")
        ]

parseMultipleDbPaths :: Parser NodeDatabasePaths
parseMultipleDbPaths = SplitDB <$> parseImmutableDbPath <*> parseVolatileDbPath

parseVolatileDbPath :: Parser FilePath
parseVolatileDbPath =
  strOption $
    mconcat
      [ long "volatile-database-path"
      , metavar "FILEPATH"
      , help "Directory where the volatile state is stored"
      , completer (bashCompleter "file")
      ]

parseImmutableDbPath :: Parser FilePath
parseImmutableDbPath =
  strOption $
    mconcat
      [ long "immutable-database-path"
      , metavar "FILEPATH"
      , help "Directory where the immutable state is stored"
      , completer (bashCompleter "file")
      ]

-- | The value missing means "unset" not @False@, hence the @Maybe Bool@.
parseStartAsNonProducingNode :: Parser (Maybe Bool)
parseStartAsNonProducingNode =
  flag Nothing (Just True) $
    mconcat
      [ long "start-as-non-producing-node"
      , help $
          mconcat
            [ "Start the node as a non block-producing node even if "
            , "credentials are specified"
            ]
      ]
