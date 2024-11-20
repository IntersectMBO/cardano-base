import Test.Cardano.Prelude (runTests)
import Prelude

import qualified Test.Cardano.Binary.Failure
import qualified Test.Cardano.Binary.RoundTrip
import qualified Test.Cardano.Binary.Serialization
import qualified Test.Cardano.Binary.SizeBounds

-- | Main testing action
main :: IO ()
main = do
  runTests
    [ Test.Cardano.Binary.RoundTrip.tests
    , Test.Cardano.Binary.SizeBounds.tests
    , Test.Cardano.Binary.Serialization.tests
    , Test.Cardano.Binary.Failure.tests
    ]
