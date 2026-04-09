module Test.Cardano.Crypto.PackedBytes.Spec (
  spec,
) where

import Cardano.Crypto.PackedBytes
import qualified Data.ByteString as BS
import Foreign.Storable
import Test.Cardano.Base.Properties (expectStorable)
import Test.Crypto.PackedBytes
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

spec :: Spec
spec = describe "PackedBytes" $ do
  prop "Storable" $ \(AnyPackedBytes pb, offset, slack) -> do
    let
      size = sizeOf pb
      sizeStr
        | size `elem` [0, 8, 28, 32] = show size <> " bytes"
        | otherwise = "Other size"
    label sizeStr $ do
      size `shouldBe` BS.length (unpackPinnedBytes pb)
      expectStorable pb offset slack
