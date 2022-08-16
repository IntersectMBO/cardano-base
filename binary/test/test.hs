import Prelude
import Test.Cardano.Prelude (runTests)

import qualified Test.Cardano.Binary.RoundTrip
import qualified Test.Cardano.Binary.SizeBounds
import qualified Test.Cardano.Binary.Serialization
import qualified Test.Cardano.Binary.Drop
import qualified Test.Cardano.Binary.Failure

-- | Main testing action
main :: IO ()
main = do
  runTests
    [ Test.Cardano.Binary.RoundTrip.tests
    , Test.Cardano.Binary.SizeBounds.tests
    , Test.Cardano.Binary.Serialization.tests
    , Test.Cardano.Binary.Drop.tests
    , Test.Cardano.Binary.Failure.tests
    ]
