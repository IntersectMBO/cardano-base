{-# LANGUAGE TypeApplications #-}

module Test.Crypto.Poseidon (
  tests,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  Fr (..),
  scalarFromFr,
  scalarToInteger,
 )
import Cardano.Crypto.PinnedSizedBytes (psbCreate)
import Cardano.Crypto.Poseidon.Constants (
  PoseidonInstance (..),
  batchSize,
  circomWidth3,
  midnightWidth3,
 )
import Cardano.Crypto.Poseidon.Internal (
  FrPtr (..),
  c_poseidon_compute_number_of_constants,
  c_poseidon_parameters_valid,
  frBufferElements,
  newPoseidonTemplate,
  sizeFrElement,
  templateImage,
  withFrBuffer,
 )
import Data.Word (Word8)
import Foreign.C.Types (CInt)
import Foreign.Marshal.Array (peekArray)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Test.Hspec (Spec, describe, it, shouldBe, shouldReturn)

-- | Every registered variant, by its exported name. Must be extended
-- whenever a variant is registered: passing these tests is what entitles
-- 'Cardano.Crypto.Poseidon.Internal' to construct contexts for these
-- instances without a runtime validity check.
registeredInstances :: [(String, PoseidonInstance)]
registeredInstances =
  [ ("midnightWidth3", midnightWidth3)
  , ("circomWidth3", circomWidth3)
  ]

tests :: Spec
tests = describe "Poseidon" $ do
  describe "registered instance passes poseidon_parameters_valid" $
    mapM_ checkParameters registeredInstances
  describe "registered instance template image" $
    mapM_ checkTemplate registeredInstances

checkParameters :: (String, PoseidonInstance) -> Spec
checkParameters (name, inst) =
  it name $
    c_poseidon_parameters_valid
      (fromIntegral @Int @CInt (nbFullRounds inst))
      (fromIntegral @Int @CInt (nbPartialRounds inst))
      (fromIntegral @Int @CInt (batchSize inst))
      (fromIntegral @Int @CInt (width inst))
      `shouldBe` 1

-- | The image layout is @[ state | MDS | ARK | trailing zeros ]@ (see
-- 'templateImage'): check the total size, that the state region and the
-- trailing @width@ constants are zero, and that every loaded MDS and ARK
-- element converts back to its canonical 'Integer' from the registry.
checkTemplate :: (String, PoseidonInstance) -> Spec
checkTemplate (name, inst) = describe name $ do
  it "has the size poseidon_compute_number_of_constants implies" $
    frBufferElements image `shouldBe` w + w * w + nbConstants
  it "has a zeroed state region" $
    regionIsZero 0 w `shouldReturn` True
  it "has the width trailing zero constants" $
    regionIsZero (frBufferElements image - w) w `shouldReturn` True
  it "round-trips the MDS elements" $
    elementsAt w (w * w) `shouldReturn` concat (mds inst)
  it "round-trips the ARK elements" $
    elementsAt (w + w * w) (length (ark inst)) `shouldReturn` ark inst
  where
    image = templateImage (newPoseidonTemplate inst)
    w = width inst
    nbConstants =
      fromIntegral @CInt @Int $
        c_poseidon_compute_number_of_constants
          (fromIntegral @Int @CInt (batchSize inst))
          (fromIntegral @Int @CInt (nbPartialRounds inst))
          (fromIntegral @Int @CInt (nbFullRounds inst))
          (fromIntegral @Int @CInt w)
    regionIsZero el n =
      withFrBuffer image $ \(FrPtr p) ->
        all (== 0)
          <$> peekArray
            (n * sizeFrElement)
            (p `plusPtr` (el * sizeFrElement) :: Ptr Word8)
    elementsAt el n = mapM (elementAt . (el +)) [0 .. n - 1]
    elementAt el =
      withFrBuffer image $ \(FrPtr p) -> do
        psb <- psbCreate $ \dst ->
          copyBytes dst (p `plusPtr` (el * sizeFrElement)) sizeFrElement
        scalarFromFr (Fr psb) >>= scalarToInteger
