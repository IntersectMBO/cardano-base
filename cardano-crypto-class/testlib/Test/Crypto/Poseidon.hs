{-# LANGUAGE TypeApplications #-}

module Test.Crypto.Poseidon (
  tests,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  Fr (..),
  scalarFromFr,
  scalarPeriod,
  scalarToInteger,
 )
import Cardano.Crypto.PinnedSizedBytes (psbCreate)
import Cardano.Crypto.Poseidon (
  PoseidonError (..),
  poseidonPermutation,
 )
import Cardano.Crypto.Poseidon.Constants (
  PoseidonInstance (..),
  batchSize,
  circomWidth3,
  conjugateInstance,
  lastLaneForm,
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
import Data.List (sort)
import Data.Word (Word8)
import Foreign.C.Types (CInt)
import Foreign.Marshal.Array (peekArray)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Test.Hspec (Spec, describe, it, shouldBe, shouldNotBe, shouldReturn)

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
  describe "registered instance constants structure" $
    mapM_ checkStructure registeredInstances
  describe "registered instance template image" $
    mapM_ checkTemplate registeredInstances
  describe "poseidonPermutation" checkPermutation
  describe "known-answer vectors" checkKnownAnswers

checkParameters :: (String, PoseidonInstance) -> Spec
checkParameters (name, inst) =
  it name $
    c_poseidon_parameters_valid
      (fromIntegral @Int @CInt (nbFullRounds inst))
      (fromIntegral @Int @CInt (nbPartialRounds inst))
      (fromIntegral @Int @CInt (batchSize inst))
      (fromIntegral @Int @CInt (width inst))
      `shouldBe` 1

-- | Structural invariants of the registry data — the shape half of what
-- 'Cardano.Crypto.Poseidon.Internal.newPoseidonTemplate' relies on without
-- re-checking (checkParameters covers the parameter half). The row check
-- is per row, not via 'concat': a ragged matrix could hide a wrong row
-- split behind a correct total count.
checkStructure :: (String, PoseidonInstance) -> Spec
checkStructure (name, inst) = describe name $ do
  it "has a width x width MDS matrix" $
    map length (mds inst) `shouldBe` replicate w w
  it "has (R_F + R_P) * width ARK constants" $
    length (ark inst) `shouldBe` (nbFullRounds inst + nbPartialRounds inst) * w
  it "has only canonical field elements" $
    filter (\x -> x < 0 || x >= scalarPeriod) (concat (mds inst) ++ ark inst)
      `shouldBe` []
  it "has nonzero ARK constants" $
    filter (== 0) (ark inst) `shouldBe` []
  it "has pairwise distinct ARK constants" $
    duplicates (ark inst) `shouldBe` []
  where
    w = width inst
    duplicates xs = [x | (x, y) <- zip sorted (drop 1 sorted), x == y]
      where
        sorted = sort xs

-- | The image layout is @[ state | MDS | ARK | trailing zeros ]@ (see
-- 'templateImage'): check the total size, that the state region and the
-- trailing @width@ constants are zero, and that every loaded MDS and ARK
-- element converts back to its canonical 'Integer'. The image holds the
-- instance's 'lastLaneForm' — the C core's native lane orientation — so
-- the expectations are stated in that form.
checkTemplate :: (String, PoseidonInstance) -> Spec
checkTemplate (name, inst) = describe name $ do
  it "has the size poseidon_compute_number_of_constants implies" $
    frBufferElements image `shouldBe` w + w * w + nbConstants
  it "has a zeroed state region" $
    regionIsZero 0 w `shouldReturn` True
  it "has the width trailing zero constants" $
    regionIsZero (frBufferElements image - w) w `shouldReturn` True
  it "round-trips the MDS elements" $
    elementsAt w (w * w) `shouldReturn` concat (mds cReady)
  it "round-trips the ARK elements" $
    elementsAt (w + w * w) (length (ark cReady)) `shouldReturn` ark cReady
  where
    image = templateImage (newPoseidonTemplate inst)
    cReady = lastLaneForm inst
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

-- | Sanity properties of the public API, exercising the C permutation end
-- to end. These are not correctness vectors — the known-answer tests
-- against the CIP vectors pin the actual output values.
checkPermutation :: Spec
checkPermutation = do
  it "is deterministic" $
    poseidonPermutation 0 [1, 2, 3] `shouldBe` poseidonPermutation 0 [1, 2, 3]
  it "changes the state" $
    poseidonPermutation 0 [1, 2, 3] `shouldNotBe` Right [1, 2, 3]
  it "distinguishes inputs" $
    poseidonPermutation 0 [1, 2, 3] `shouldNotBe` poseidonPermutation 0 [1, 2, 4]
  it "distinguishes variants" $
    poseidonPermutation 0 [1, 2, 3] `shouldNotBe` poseidonPermutation 1 [1, 2, 3]
  it "reduces inputs modulo r" $
    poseidonPermutation 0 [1 + scalarPeriod, 2 - scalarPeriod, 3]
      `shouldBe` poseidonPermutation 0 [1, 2, 3]
  it "returns canonical outputs" $
    case poseidonPermutation 0 [1, 2, 3] of
      Left e -> fail (show e)
      Right output -> all (\x -> 0 <= x && x < scalarPeriod) output `shouldBe` True
  it "rejects an unknown variant index" $
    poseidonPermutation 2 [1, 2, 3] `shouldBe` Left (PoseidonUnknownVariant 2)
  it "rejects a wrong input length" $
    poseidonPermutation 0 [1, 2] `shouldBe` Left (PoseidonWrongInputLength 3 2)

-- | Known-answer vectors from the CIP, each in its instance's own
-- (upstream) lane order — for variant 1 that the binding internally runs
-- the conjugated instance and reverses the states at the boundary is not
-- observable here, which is exactly what these vectors pin. A mismatch on
-- variant 1 has two known pitfalls: an MDS conjugated as the transpose
-- @M[j][i]@ instead of the reversal @M[t-1-i][t-1-j]@, or the ARK list
-- reversed as a whole instead of per round.
checkKnownAnswers :: Spec
checkKnownAnswers = do
  it "variant 0: [1, 2, 3]" $
    poseidonPermutation 0 [1, 2, 3]
      `shouldBe` Right
        [ 42739176831222744601351189768647402530126631525647633889963058519155127388954
        , 46658607099440038490901505304394142050340509471711703355306894912210352993754
        , 23346409755515467342303752938632006079855330979846092405107661684387401837642
        ]
  it "variant 0: [1, 2, 2]" $
    poseidonPermutation 0 [1, 2, 2]
      `shouldBe` Right
        [ 33852961970927025159829408976690548924952885524395353086236132427166834970999
        , 3939714347492956910064432176192648807657130878941949775514761553730106462950
        , 1911806661785286735974042641799574786956305172400684573554104410484129105208
        ]
  -- The CIP's two-permutation hash3 vector for inputs 1, 2, 3: the second
  -- permutation absorbs the third input into the first (rate) lane. This is
  -- NOT permute-of-permute; the +3 is input absorption, not part of the
  -- permutation.
  it "variant 0: hash3 flow for inputs [1, 2, 3]" $
    ( case poseidonPermutation 0 [1, 2, 3] of
        Right [x, y, z] -> poseidonPermutation 0 [x + 3, y, z]
        other -> other
    )
      `shouldBe` Right
        [ 16323296787651812390833595953902584438731345731750798730514972659803187358587
        , 10406938084826613343012454278028743502903967432980834233438228844865271820462
        , 8002878662839612277232593634438862637457054066080438365871913314805563042751
        ]
  -- Capacity lane first (initialized to 0), inputs 1 and 2; the first
  -- output lane is the circom digest.
  it "variant 1: circom vector [0, 1, 2]" $
    poseidonPermutation 1 [0, 1, 2]
      `shouldBe` Right
        [ 28821147804331559602169231704816259064962739503761913593647409715501647586810
        , 30754388626296368040468298266549616538028692312414349123487035395142135348698
        , 2299091558249312604371495294586620648216137258024480884964079017093457283751
        ]
  it "conjugateInstance is an involution" $
    conjugateInstance (conjugateInstance circomWidth3) `shouldBe` circomWidth3
