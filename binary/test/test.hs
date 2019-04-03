import Cardano.Prelude
import Test.Cardano.Prelude

import qualified Test.Cardano.Binary.RoundTrip
import qualified Test.Cardano.Binary.SizeBounds


-- | Main testing action
main :: IO ()
main = runTests
  [Test.Cardano.Binary.RoundTrip.tests, Test.Cardano.Binary.SizeBounds.tests]
