-- | Values related to testing, which are unused by a real node
module Cardano.Configuration.File.Testing (
  TestingConfiguration (..),
  finalizeTesting,
) where

import Autodocodec
import Cardano.Configuration.Basic (requireField)
import Cardano.Configuration.File.Protocol
import Data.Aeson (FromJSON, ToJSON)
import Data.Functor.Identity (Identity (..))
import Data.Word
import GHC.Generics (Generic)

-- | The testing configuration: knobs for forcing era transitions at specific
-- epochs/versions and for enabling the experimental era. Only
-- @ExperimentalHardForksEnabled@ has a default; the rest are optional by nature.
data TestingConfiguration f = TestingConfiguration
  { experimentalHardForksEnabled :: f Bool
  , testShelleyHardForkAtEpoch :: Maybe Word64
  , testShelleyHardForkAtVersion :: Maybe Word
  , testAllegraHardForkAtEpoch :: Maybe Word64
  , testAllegraHardForkAtVersion :: Maybe Word
  , testMaryHardForkAtEpoch :: Maybe Word64
  , testMaryHardForkAtVersion :: Maybe Word
  , testAlonzoHardForkAtEpoch :: Maybe Word64
  , testAlonzoHardForkAtVersion :: Maybe Word
  , testBabbageHardForkAtEpoch :: Maybe Word64
  , testBabbageHardForkAtVersion :: Maybe Word
  , testConwayHardForkAtEpoch :: Maybe Word64
  , testConwayHardForkAtVersion :: Maybe Word
  , testDijkstraHardForkAtEpoch :: Maybe Word64
  , testDijkstraHardForkAtVersion :: Maybe Word
  , experimentalGenesis :: Maybe (Hashed FilePath)
  }
  deriving (Generic)

deriving instance Show (TestingConfiguration Maybe)
deriving instance Show (TestingConfiguration Identity)

deriving via
  (Autodocodec (TestingConfiguration Maybe))
  instance
    FromJSON (TestingConfiguration Maybe)

deriving via
  (Autodocodec (TestingConfiguration Maybe))
  instance
    ToJSON (TestingConfiguration Maybe)

instance HasCodec (TestingConfiguration Maybe) where
  codec =
    object "TestingConfiguration" $
      TestingConfiguration
        <$> optionalField "ExperimentalHardForksEnabled" "Enable the experimental eras"
          .= experimentalHardForksEnabled
        <*> optionalField "TestShelleyHardForkAtEpoch" "Force the Shelley hard fork at this epoch"
          .= testShelleyHardForkAtEpoch
        <*> optionalField "TestShelleyHardForkAtVersion" "Force the Shelley hard fork at this protocol version"
          .= testShelleyHardForkAtVersion
        <*> optionalField "TestAllegraHardForkAtEpoch" "Force the Allegra hard fork at this epoch"
          .= testAllegraHardForkAtEpoch
        <*> optionalField "TestAllegraHardForkAtVersion" "Force the Allegra hard fork at this protocol version"
          .= testAllegraHardForkAtVersion
        <*> optionalField "TestMaryHardForkAtEpoch" "Force the Mary hard fork at this epoch"
          .= testMaryHardForkAtEpoch
        <*> optionalField "TestMaryHardForkAtVersion" "Force the Mary hard fork at this protocol version"
          .= testMaryHardForkAtVersion
        <*> optionalField "TestAlonzoHardForkAtEpoch" "Force the Alonzo hard fork at this epoch"
          .= testAlonzoHardForkAtEpoch
        <*> optionalField "TestAlonzoHardForkAtVersion" "Force the Alonzo hard fork at this protocol version"
          .= testAlonzoHardForkAtVersion
        <*> optionalField "TestBabbageHardForkAtEpoch" "Force the Babbage hard fork at this epoch"
          .= testBabbageHardForkAtEpoch
        <*> optionalField "TestBabbageHardForkAtVersion" "Force the Babbage hard fork at this protocol version"
          .= testBabbageHardForkAtVersion
        <*> optionalField "TestConwayHardForkAtEpoch" "Force the Conway hard fork at this epoch"
          .= testConwayHardForkAtEpoch
        <*> optionalField "TestConwayHardForkAtVersion" "Force the Conway hard fork at this protocol version"
          .= testConwayHardForkAtVersion
        <*> optionalField "TestDijkstraHardForkAtEpoch" "Force the Dijkstra hard fork at this epoch"
          .= testDijkstraHardForkAtEpoch
        <*> optionalField
          "TestDijkstraHardForkAtVersion"
          "Force the Dijkstra hard fork at this protocol version"
          .= testDijkstraHardForkAtVersion
        <*> optionalHashedFileObjectCodec "DijkstraGenesisFile" "DijkstraGenesisHash" .= experimentalGenesis

-- | Resolve a partial testing configuration, taking @ExperimentalHardForksEnabled@
-- from the (always-applied) defaults.
finalizeTesting :: TestingConfiguration Maybe -> Either String (TestingConfiguration Identity)
finalizeTesting c = do
  enabled <- requireField "ExperimentalHardForksEnabled" (experimentalHardForksEnabled c)
  pure $
    TestingConfiguration
      enabled
      (testShelleyHardForkAtEpoch c)
      (testShelleyHardForkAtVersion c)
      (testAllegraHardForkAtEpoch c)
      (testAllegraHardForkAtVersion c)
      (testMaryHardForkAtEpoch c)
      (testMaryHardForkAtVersion c)
      (testAlonzoHardForkAtEpoch c)
      (testAlonzoHardForkAtVersion c)
      (testBabbageHardForkAtEpoch c)
      (testBabbageHardForkAtVersion c)
      (testConwayHardForkAtEpoch c)
      (testConwayHardForkAtVersion c)
      (testDijkstraHardForkAtEpoch c)
      (testDijkstraHardForkAtVersion c)
      (experimentalGenesis c)
