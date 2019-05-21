import Cardano.Prelude
import Test.Cardano.Prelude

import qualified Test.Cardano.Binary.RoundTrip
import qualified Test.Cardano.Binary.SizeBounds
import qualified Test.Cardano.Binary.Serialization
import qualified Test.Cardano.Binary.Drop

-- | Main testing action
main :: IO ()
main = do 
  runTests
    [ Test.Cardano.Binary.RoundTrip.tests
    , Test.Cardano.Binary.SizeBounds.tests
    , Test.Cardano.Binary.Serialization.tests
    , Test.Cardano.Binary.Drop.tests
    ]
