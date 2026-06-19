-- | Types that are common to CLI arguments and the configuration files
module Cardano.Configuration.Common (
  NodeDatabasePaths (..),
  parseNodeDatabasePaths,
  parseStartAsNonProducingNode,
) where

import Autodocodec
import Data.Aeson (FromJSON, ToJSON)
import Data.Default
import GHC.Generics
import Options.Applicative

--------------------------------------------------------------------------------

-- | The databases that will be used by the node
data NodeDatabasePaths
  = -- | Store everything in a single directory
    SingleDB FilePath
  | -- | Store the immutable data in one (possibly slower) directory and the
    -- volatile data in a different (possible faster) directory
    SplitDB FilePath FilePath
  deriving (Generic, Show)

instance Default NodeDatabasePaths where
  def = SingleDB "mainnet/db"

instance HasCodec NodeDatabasePaths where
  codec =
    dimapCodec toNDP fromNDP $
      disjointEitherCodec
        (codec @FilePath)
        ( object "SplitDB" $
            (,)
              <$> requiredField "ImmutablePath" "Directory for the immutable database" .= fst
              <*> requiredField "VolatilePath" "Directory for the volatile database" .= snd
        )
    where
      toNDP = either SingleDB (\(i, v) -> SplitDB i v)
      fromNDP (SingleDB fp) = Left fp
      fromNDP (SplitDB i v) = Right (i, v)

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
