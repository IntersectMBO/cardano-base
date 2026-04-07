-- | Module with reusable properties that can be tested for common type classes
module Test.Cardano.Base.Properties (
  expectStorable,
) where

import Control.Monad (when)
import Data.Bits
import Foreign.Marshal.Alloc (allocaBytes, allocaBytesAligned)
import Foreign.Storable
import Test.Hspec
import Test.QuickCheck

expectStorable ::
  (Storable a, Show a, Eq a) =>
  -- | Storable element to test.
  a ->
  -- | Offset to prefix the allocated buffer
  NonNegative Int ->
  -- | Slack to be padded after the element
  NonNegative Int ->
  Expectation
expectStorable x (NonNegative offset) (NonNegative slack) = do
  let size = sizeOf x
  alignment x `shouldSatisfy` (>= 0)
  -- Alignment of more that 64bytes makes no sense on modern CPUs
  alignment x `shouldSatisfy` (<= 64)
  -- Twice the size is too big
  alignment x `shouldSatisfy` (\a -> (a == 0 && size == 0) || a < 2 * size)
  -- Is power of two or zero:
  alignment x `shouldSatisfy` \a -> popCount a <= 1
  let roundtrip ptr = do
        poke ptr x
        x0 <- peek ptr
        x0 `shouldBe` x
        pokeByteOff ptr offset x
        xByteOff <- peekByteOff ptr offset
        xByteOff `shouldBe` x
        when ((offset + slack) >= size) $ do
          pokeElemOff ptr 1 x
          xElemOff <- peekElemOff ptr 1
          xElemOff `shouldBe` x
  allocaBytes (offset + size + slack) roundtrip
  allocaBytesAligned (offset + size + slack) (alignment x) roundtrip
