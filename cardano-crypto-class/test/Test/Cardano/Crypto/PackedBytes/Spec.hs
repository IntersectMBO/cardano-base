module Test.Cardano.Crypto.PackedBytes.Spec (
  spec,
) where

import Cardano.Crypto.PackedBytes
import Data.Bits
import qualified Data.ByteString as BS
import Foreign.Marshal.Alloc (allocaBytes, allocaBytesAligned)
import Foreign.Storable
import Test.Crypto.PackedBytes
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

spec :: Spec
spec = describe "PackedBytes" $ do
  prop "Storable" $ \(AnyPackedBytes pb, NonNegative offset, NonNegative slack) -> do
    let size = sizeOf pb
        sizeStr
          | size `elem` [0, 8, 28, 32] = show size <> " bytes"
          | otherwise = "Other size"
    label sizeStr $ do
      size `shouldBe` BS.length (unpackPinnedBytes pb)
      alignment pb `shouldSatisfy` (>= size)
      -- Ensure value is power of two:
      let onlyOneBitSet n = go 0
            where
              numBits = finiteBitSize n
              go i
                | i > numBits = False
                | testBit n i = clearBit n i == 0
                | otherwise = go (i + 1)
      alignment pb `shouldSatisfy` \a -> a == 0 || onlyOneBitSet a
      let roundtrip ptr = do
            pokeByteOff ptr offset pb
            pb' <- peekByteOff ptr offset
            pb' `shouldBe` pb
      allocaBytes (offset + size + slack) roundtrip
      allocaBytesAligned (offset + size + slack) (alignment pb) roundtrip
