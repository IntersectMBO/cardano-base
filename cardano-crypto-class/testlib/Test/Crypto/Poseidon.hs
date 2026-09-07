{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeApplications #-}

-- | Tests for the Poseidon instance data in "Cardano.Crypto.Poseidon.Constants".
--
-- The invariants asserted over each registered instance are the admission
-- criteria of the CIP /Poseidon Permutation Built-in for Plutus/, and the
-- known-answer vectors are that CIP's @test-vectors.json@: per instance a
-- __normative permutation vector__ (one call, input state to full output
-- state — what conformance means for the builtin) and __secondary hash
-- vectors__ (the origin ecosystem's hash reconstructed as a framing of
-- permutation calls, checked call by call against the shipped trace).
--
-- The property tests below cite two papers:
--
-- [GKRRS21]: Grassi, Khovratovich, Rechberger, Roy, Schofnegger,
-- \"Poseidon: A New Hash Function for Zero-Knowledge Proof Systems\",
-- USENIX Security 2021, <https://eprint.iacr.org/2019/458>.
--
-- [GRS20]: Grassi, Rechberger, Schofnegger, \"Proving Resistance Against
-- Infinitely Long Subspace Trails: How to Choose the Linear Layer\",
-- <https://eprint.iacr.org/2020/500>.
module Test.Crypto.Poseidon (
  tests,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  Fr,
  frFromScalar,
  scalarFromFr,
  scalarFromInteger,
  scalarPeriod,
  scalarToInteger,
 )
import Cardano.Crypto.Hash (SHA256, digest)
import Cardano.Crypto.Poseidon (
  PoseidonError (..),
  poseidonPermutation,
  poseidonPermutationInteger,
 )
import Cardano.Crypto.Poseidon.Batching (computeConstantsRegion)
import Cardano.Crypto.Poseidon.Constants (
  PartialSBoxLane (..),
  PoseidonInstance (..),
  batchSize,
  circomWidth3,
  conjugateInstance,
  midnightWidth3,
  poseidonVariants,
 )
import Cardano.Crypto.Poseidon.Internal (
  PoseidonTemplate,
  nativeForm,
  newPoseidonTemplate,
  newPoseidonTemplateWithBatchSize,
  poseidonPermute,
 )
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Data.List (subsequences)
import Data.Maybe (fromMaybe, isJust, isNothing)
import Data.Proxy (Proxy (..))
import qualified Data.Set as Set
import Foreign.C.Types (CInt (..))
import Test.Crypto.Poseidon.Field (FieldElem)
import Test.Crypto.Poseidon.Reference (referencePoseidon)
import Test.HUnit (assertBool, assertEqual, assertFailure)
import Test.Hspec (Spec, describe, it)
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (
  Gen,
  arbitrary,
  choose,
  conjoin,
  counterexample,
  elements,
  forAll,
  frequency,
  ioProperty,
  vectorOf,
  (===),
 )

-- The canonical FFI imports will live in Cardano.Crypto.Poseidon.Internal;
-- this import is declared here as well so the count invariant is asserted
-- directly against the C source of truth rather than a Haskell reimplementation
-- of its formula. The C function is pure (no side effects, no pointers), hence
-- the non-IO type; `unsafe` is appropriate because it cannot block or call
-- back into Haskell.
foreign import ccall unsafe "poseidon_compute_number_of_constants"
  c_poseidon_compute_number_of_constants ::
    -- | batch_size
    CInt ->
    -- | nb_partial_rounds
    CInt ->
    -- | nb_full_rounds
    CInt ->
    -- | width
    CInt ->
    CInt

-- | One registered variant, bundled with everything its per-variant tests
-- need: the registry index, the instance, the pinned digest of its embedded
-- constants, and the CIP's normative permutation vector.
data Variant = Variant
  { varLabel :: String
  , varIndex :: Integer
  , varInstance :: PoseidonInstance
  , varDigest :: String
  , varPermInput :: [Integer]
  , varPermOutput :: [Integer]
  }

-- | The registered variants, mirroring the CIP registry. Every entry of
-- 'poseidonVariants' must appear here (asserted below), so adding a variant
-- without vectors is a test failure.
variants :: [Variant]
variants =
  [ Variant
      { varLabel = "midnightWidth3 (variant 0)"
      , varIndex = 0
      , varInstance = midnightWidth3
      , varDigest = "8cd06b7ff6cfd8be79049d6839e2c8cb596fbc33ae7d62a10f415c229acee505"
      , varPermInput = [1, 2, 3]
      , varPermOutput =
          [ 42739176831222744601351189768647402530126631525647633889963058519155127388954
          , 46658607099440038490901505304394142050340509471711703355306894912210352993754
          , 23346409755515467342303752938632006079855330979846092405107661684387401837642
          ]
      }
  , Variant
      { varLabel = "circomWidth3 (variant 1)"
      , varIndex = 1
      , varInstance = circomWidth3
      , varDigest = "55ada01ef31b021e3c0b5a19f7e2788983c6a63cefd57840cb1d70020f2346f7"
      , varPermInput = [0, 1, 2]
      , varPermOutput =
          [ 28821147804331559602169231704816259064962739503761913593647409715501647586810
          , 30754388626296368040468298266549616538028692312414349123487035395142135348698
          , 2299091558249312604371495294586620648216137258024480884964079017093457283751
          ]
      }
  ]

-- | All Poseidon tests: constants invariants, Internal-level binding tests
-- (normative vectors, differential property against the reference
-- implementation, rejections), batching, the public API tests, and the
-- CIP's secondary hash-framing vectors.
tests :: Spec
tests =
  describe "Crypto.Poseidon" $ do
    describe "Constants" $ do
      it "the test-suite variant list covers exactly the registered indices" $ do
        -- Guards the coupling between this file and the registry: a variant
        -- registered without vectors here, or vice versa, fails.
        mapM_
          ( \v ->
              assertEqual ("index " ++ show (varIndex v)) (Just (varInstance v)) (poseidonVariants (varIndex v))
          )
          variants
        assertBool "index 2 unregistered" (isNothing (poseidonVariants 2))
      mapM_ variantConstantsTests variants
      it "conjugateInstance is an involution and mirrors the S-box lane" $
        mapM_
          ( \v -> do
              let inst = varInstance v
                  conj = conjugateInstance inst
              assertBool
                (varLabel v ++ ": lane mirrored")
                (partialSBoxLane conj /= partialSBoxLane inst)
              assertEqual (varLabel v ++ ": involution") inst (conjugateInstance conj)
          )
          variants
      it "nativeForm always has the S-box on the last lane" $
        mapM_
          ( \v ->
              assertEqual
                (varLabel v)
                SBoxLast
                (partialSBoxLane (nativeForm (varInstance v)))
          )
          variants
    describe "Internal" $ do
      it "builds a template for every registered instance" $
        mapM_
          (\v -> assertBool (varLabel v) (isJust (newPoseidonTemplate (varInstance v))))
          variants
      it "rejects invalid instances" $ do
        -- Each of these exercises a distinct validation layer documented in
        -- Cardano.Crypto.Poseidon.Internal: the first three are rejected by
        -- the C constructor (poseidon_ctxt_new), the last two by the
        -- Haskell-side shape and constant-count assertions.
        let rejects inst label = assertBool label (isNothing (newPoseidonTemplate inst))
        rejects midnightWidth3 {width = 1} "width 1"
        rejects midnightWidth3 {nbFullRounds = 7} "odd R_F"
        rejects midnightWidth3 {nbFullRounds = -2} "negative R_F"
        rejects midnightWidth3 {mds = [[1]]} "MDS shape mismatch"
        rejects midnightWidth3 {ark = drop 1 (ark midnightWidth3)} "constant count mismatch"
      it "rejects input states of the wrong length (no implicit padding)" $ do
        tmpl <- expectJust "template" (newPoseidonTemplate midnightWidth3)
        someFr <- integersToFrs [1, 2, 3, 4]
        mapM_
          ( \n ->
              assertBool
                ("input length " ++ show n)
                (isNothing (poseidonPermute tmpl (take n someFr)))
          )
          [0, 2, 4]
      mapM_ variantInternalTests variants
      it "is deterministic across independent executions" $ do
        -- The two inputs are built by two separate IO actions, so they are
        -- distinct heap objects with equal contents and the two
        -- poseidonPermute applications are distinct expressions. This
        -- matters: with a single shared `input`, both calls would be
        -- syntactically identical pure expressions that CSE may legally
        -- collapse into one, and the test would compare a value with
        -- itself. Built this way, the C permutation demonstrably runs
        -- twice (fresh scratch context each time), which is what
        -- determinism-across-calls is actually about: no hidden state, no
        -- uninitialized-memory influence.
        tmpl <- expectJust "template" (newPoseidonTemplate midnightWidth3)
        input1 <- integersToFrs [5, 6, 7]
        input2 <- integersToFrs [5, 6, 7]
        out1 <- expectJust "permute 1" (poseidonPermute tmpl input1)
        out2 <- expectJust "permute 2" (poseidonPermute tmpl input2)
        r1 <- frsToIntegers out1
        r2 <- frsToIntegers out2
        assertEqual "two independent executions" r1 r2
    describe "Batching" $ mapM_ variantBatchingTests variants
    describe "Public API" $ do
      mapM_ variantPublicApiTests variants
      it "rejects unregistered variant indices" $ do
        let rejected i =
              assertEqual
                ("variant " ++ show i)
                (Left (PoseidonUnknownVariant i))
                (poseidonPermutationInteger i [0, 0, 0])
        mapM_ rejected [2, -1, 2 ^ (64 :: Int)]
      it "rejects wrong input lengths (width - 1, width + 1, empty), never pads" $ do
        let w = width midnightWidth3
            rejected xs =
              assertEqual
                ("length " ++ show (length xs))
                (Left (PoseidonWrongInputLength w (length xs)))
                (poseidonPermutationInteger 0 xs)
        rejected [1, 2]
        rejected [1, 2, 3, 4]
        rejected []
        -- and through the Fr API
        frs <- integersToFrs [1, 2]
        assertEqual
          "Fr API, length 2"
          (Left (PoseidonWrongInputLength w 2))
          (fmap (const ()) (poseidonPermutation 0 frs))
      it "reduces Integer inputs modulo r (negative and >= r values)" $
        -- The documented reduction semantics: -1 ~ r-1, r ~ 0, r+1 ~ 1.
        -- The two argument lists differ syntactically, so the two calls
        -- cannot be collapsed by CSE.
        assertEqual
          "[-1, r, r+1] permutes like [r-1, 0, 1]"
          (poseidonPermutationInteger 0 [scalarPeriod - 1, 0, 1])
          (poseidonPermutationInteger 0 [-1, scalarPeriod, scalarPeriod + 1])
      it "is deterministic through the public API" $ do
        -- Same construction as the Internal-level determinism test: two
        -- independently converted (equal-valued) inputs, so the two calls
        -- are distinct expressions and both really execute.
        input1 <- integersToFrs [8, 9, 10]
        input2 <- integersToFrs [8, 9, 10]
        out1 <- expectRight (poseidonPermutation 0 input1) >>= frsToIntegers
        out2 <- expectRight (poseidonPermutation 0 input2) >>= frsToIntegers
        assertEqual "two independent executions" out1 out2
      prop "Integer <-> Fr marshalling round-trips modulo r" $
        -- Sanity for the conversion path everything above relies on:
        -- scalarFromInteger >>= frFromScalar, read back via scalarFromFr
        -- >>= scalarToInteger, must be exactly (`mod` r) — including
        -- values >= r and negative values.
        forAll genAnyInteger $ \n -> ioProperty $ do
          fr <- scalarFromInteger n >>= frFromScalar
          n' <- scalarFromFr fr >>= scalarToInteger
          pure (n' === n `mod` scalarPeriod)
    describe "Hash framings (secondary CIP vectors, non-normative)" $ do
      -- The CIP's secondary vectors: the origin ecosystem's hash built as a
      -- framing of permutation calls through the public API, checked call
      -- by call against the shipped trace — a worked example of one use of
      -- each index, not a registered mode. The hashes below live in the
      -- test suite only: the library deliberately exports no hash (see
      -- /A permutation, not a hash/ in "Cardano.Crypto.Poseidon").
      it "midnight 2-input hash: init (0, 0, 2), one call, digest = first lane" $ do
        -- Note the capacity tag is the arity, 2, and the digest is NOT any
        -- element of the permutation [1,2,3] vector: the tag differs.
        let state0 = [1, 2, 2]
        out <- expectRight (poseidonPermutationInteger 0 state0)
        assertEqual
          "trace call 1 output state"
          [ 33852961970927025159829408976690548924952885524395353086236132427166834970999
          , 3939714347492956910064432176192648807657130878941949775514761553730106462950
          , 1911806661785286735974042641799574786956305172400684573554104410484129105208
          ]
          out
        assertEqual
          "digest"
          33852961970927025159829408976690548924952885524395353086236132427166834970999
          (head out)
      it "midnight 3-input hash: init (0, 0, 3), two calls, digest = first lane" $ do
        -- Two rate-2 absorption chunks, one permutation call each; the
        -- first call is exactly the normative permutation vector of
        -- variant 0, whose output state is an intermediate value here.
        out1 <- expectRight (poseidonPermutationInteger 0 [1, 2, 3])
        assertEqual "trace call 1 output state" (varPermOutput (head variants)) out1
        case out1 of
          [x, y, z] -> do
            out2 <- expectRight (poseidonPermutationInteger 0 [x + 3, y, z])
            assertEqual
              "trace call 2 output state"
              [ 16323296787651812390833595953902584438731345731750798730514972659803187358587
              , 10406938084826613343012454278028743502903967432980834233438228844865271820462
              , 8002878662839612277232593634438862637457054066080438365871913314805563042751
              ]
              out2
            assertEqual
              "digest"
              16323296787651812390833595953902584438731345731750798730514972659803187358587
              (head out2)
          _ -> assertFailure "call 1 did not return a width-3 state"
      it "circom 2-input hash: single call on (0, in1, in2), digest = first lane" $ do
        -- The upstream repository's own shipped test vector: the digest is
        -- the first element of variant 1's normative permutation vector.
        out <- expectRight (poseidonPermutationInteger 1 [0, 1, 2])
        assertEqual
          "digest"
          28821147804331559602169231704816259064962739503761913593647409715501647586810
          (head out)

-- | The constants-level tests of one registered variant: the CIP admission
-- criteria over the embedded data, plus the pinned digest.
variantConstantsTests :: Variant -> Spec
variantConstantsTests v =
  describe (varLabel v) $ do
    constantsInvariants (varInstance v)
    it "embedded constants match their pinned digest (order-sensitive)" $
      -- Freezes the exact values *and* their order: the permutation
      -- consumes constants strictly sequentially, so a reordered,
      -- duplicated, dropped or extra value is as fatal as a wrong one,
      -- and none of the algebraic properties below would necessarily
      -- catch it. Any edit to the embedding must consciously update
      -- this digest.
      assertEqual
        "SHA256 (show (width, mds, ark))"
        (varDigest v)
        (constantsDigest (varInstance v))

-- | The Internal-level tests of one registered variant: the CIP's normative
-- permutation vector through the template path, and the differential
-- property against the pure reference implementation.
variantInternalTests :: Variant -> Spec
variantInternalTests v =
  describe (varLabel v) $ do
    it "matches the CIP normative permutation vector" $ do
      -- One call, input state to full output state, in the instance's own
      -- lane order — what conformance to the CIP means. This exercises the
      -- whole binding: buffer layout, Montgomery conversion, batch-size
      -- choice, zero padding and (for variant 1) the lane normalization
      -- would each corrupt the output if wrong. (The Public API tests
      -- re-assert this vector through the registry path.)
      tmpl <- expectJust "template" (newPoseidonTemplate (varInstance v))
      input <- integersToFrs (varPermInput v)
      output <- expectJust "permute" (poseidonPermute tmpl input)
      outputIntegers <- frsToIntegers output
      assertEqual "output state" (varPermOutput v) outputIntegers
    prop "agrees with the pure reference implementation on random states" $
      -- Differential test against Test.Crypto.Poseidon.Reference, a naive
      -- spec-faithful Poseidon over the FieldElem oracle that shares
      -- nothing with the C (no blst, no batching, no zero-padding, and no
      -- lane normalization: an SBoxFirst instance is evaluated directly on
      -- its own constants). The normative vector pins a single input; this
      -- covers random states across the whole field, including the
      -- boundary values the generator injects deliberately, and — for
      -- variant 1 — checks the state-reversal conjugation on every case.
      forAll (genState (varInstance v)) $ \xs -> ioProperty $ do
        input <- integersToFrs xs
        output <- expectJust "permute" (poseidonPermute (variantTemplate v) input)
        outIntegers <- frsToIntegers output
        pure $
          map fromInteger outIntegers === referencePoseidon (varInstance v) (map fromInteger xs)

-- | The batching tests of one registered variant, all over its
-- lane-normalized ('nativeForm') form — the only form the constants
-- composition is defined on.
variantBatchingTests :: Variant -> Spec
variantBatchingTests v =
  describe (varLabel v) $ do
    it "the unbatched region is exactly the native raw ARK list" $
      -- The identity that makes the production path a special case of the
      -- general constants-region computation: with batch size R_P + 1
      -- there are no batches and the region's four sections reassemble the
      -- raw ARK list of the native form.
      assertEqual
        "constantsRegion (R_P + 1)"
        (ark native)
        (computeConstantsRegion (batchSize native) native)
    it "region length + width matches poseidon_compute_number_of_constants" $
      -- The composition must produce exactly the number of constants the
      -- C consumes for every batch size, not just the unbatched one.
      mapM_
        ( \k ->
            assertEqual
              ("batch size " ++ show k)
              ( c_poseidon_compute_number_of_constants
                  (fromIntegral k)
                  (fromIntegral (nbPartialRounds native))
                  (fromIntegral (nbFullRounds native))
                  (fromIntegral (width native))
              )
              (fromIntegral (length (computeConstantsRegion k native) + width native))
        )
        (exercisedBatchSizes (varInstance v))
    prop "batched and unbatched configurations agree on random states" $
      -- The load-bearing batching test: the unbatched path (raw ARK
      -- constants) is the oracle; every batched configuration must compute
      -- the identical permutation. Exercises degenerate batches (k = 1),
      -- small batches, a batch size that leaves unbatched leftover rounds
      -- (k = 7: R_P mod 7 /= 0 for both registered instances), and one
      -- giant batch (k = R_P).
      forAll (genState (varInstance v)) $ \xs -> ioProperty $ do
        input <- integersToFrs xs
        oracle <- expectJust "unbatched" (poseidonPermute (variantTemplate v) input)
        oracleIntegers <- frsToIntegers oracle
        results <-
          mapM
            ( \k -> do
                tmpl <-
                  expectJust
                    ("batched template k=" ++ show k)
                    (newPoseidonTemplateWithBatchSize k (varInstance v))
                out <- expectJust ("batched k=" ++ show k) (poseidonPermute tmpl input)
                (,) k <$> frsToIntegers out
            )
            (exercisedBatchSizes (varInstance v))
        pure $
          conjoin
            [ counterexample ("batch size " ++ show k) (out === oracleIntegers)
            | (k, out) <- results
            ]
  where
    native = nativeForm (varInstance v)

-- | The public-API tests of one registered variant: the CIP's normative
-- permutation vector through the registry path, both boundaries.
variantPublicApiTests :: Variant -> Spec
variantPublicApiTests v =
  describe (varLabel v) $ do
    it "matches the CIP normative permutation vector (Integer API)" $
      -- The same vector as the Internal-level test, now through the whole
      -- public stack: registry lookup, cached template, Integer reduction
      -- and canonical read-back.
      assertEqual
        "output state"
        (Right (varPermOutput v))
        (poseidonPermutationInteger (varIndex v) (varPermInput v))
    it "matches the CIP normative permutation vector (Fr API)" $ do
      input <- integersToFrs (varPermInput v)
      output <- expectRight (poseidonPermutation (varIndex v) input)
      outputIntegers <- frsToIntegers output
      assertEqual "output state" (varPermOutput v) outputIntegers
    prop "Integer wrapper agrees with the Fr API on in-range values" $
      -- Two independent paths through conversion and permutation; the
      -- Integer wrapper must be observably nothing more than
      -- conversion + Fr API + conversion.
      forAll (genState (varInstance v)) $ \xs -> ioProperty $ do
        frs <- integersToFrs xs
        viaFr <- expectRight (poseidonPermutation (varIndex v) frs) >>= frsToIntegers
        pure (poseidonPermutationInteger (varIndex v) xs === Right viaFr)

-- | The batch sizes the batched-vs-unbatched property exercises for an
-- instance: degenerate, small, one leaving leftover unbatched rounds, and
-- one covering all partial rounds in a single batch.
exercisedBatchSizes :: PoseidonInstance -> [Int]
exercisedBatchSizes inst = [1, 2, 3, 7, nbPartialRounds inst]

-- | The unbatched template of a variant, built once and shared by the
-- property tests.
variantTemplate :: Variant -> PoseidonTemplate
variantTemplate v =
  fromMaybe
    (error (varLabel v ++ ": template failed"))
    (newPoseidonTemplate (varInstance v))

-- | A random state for an instance: width elements of F_r, with the
-- boundary values 0, 1 and r-1 deliberately over-represented.
genState :: PoseidonInstance -> Gen [Integer]
genState inst = vectorOf (width inst) genFieldInteger
  where
    genFieldInteger =
      frequency
        [ (1, elements [0, 1, scalarPeriod - 1])
        , (9, choose (0, scalarPeriod - 1))
        ]

-- | Integers for the marshalling round-trip: small values (positive and
-- negative), in-range field elements, values >= r, large negatives, and
-- the exact boundaries.
genAnyInteger :: Gen Integer
genAnyInteger =
  frequency
    [ (2, arbitrary)
    , (4, choose (0, scalarPeriod - 1))
    , (2, choose (scalarPeriod, 2 * scalarPeriod))
    , (1, negate <$> choose (0, 2 * scalarPeriod))
    , (1, elements [0, 1, -1, scalarPeriod - 1, scalarPeriod, scalarPeriod + 1])
    ]

-- | Fail the test on 'Left' instead of an incomplete pattern match.
expectRight :: Show e => Either e a -> IO a
expectRight = either (assertFailure . show) pure

-- | Fail the test on 'Nothing' instead of an incomplete pattern match.
expectJust :: String -> Maybe a -> IO a
expectJust label = maybe (assertFailure label) pure

-- | Integer -> Fr via the canonical conversion path.
integersToFrs :: [Integer] -> IO [Fr]
integersToFrs = mapM (\n -> scalarFromInteger n >>= frFromScalar)

-- | Fr -> Integer via the canonical conversion path.
frsToIntegers :: [Fr] -> IO [Integer]
frsToIntegers = mapM (\f -> scalarFromFr f >>= scalarToInteger)

-- | SHA256 over the 'show'n @(width, mds, ark)@ of an instance. 'show' on
-- 'Integer' lists is an unambiguous, order-preserving serialization.
constantsDigest :: PoseidonInstance -> String
constantsDigest inst =
  BS8.unpack
    . Base16.encode
    . digest (Proxy @SHA256)
    . BS8.pack
    $ show (width inst, mds inst, ark inst)

-- | The invariants of an instance, asserted as formulas rather than
-- literals so they keep holding for any instance added to the registry
-- later. These are the CIP's mechanically checkable admission criteria
-- (its @check-constants.py@ asserts the same properties over the shipped
-- constants files).
constantsInvariants :: PoseidonInstance -> Spec
constantsInvariants inst = do
  it "MDS is a width × width matrix" $ do
    assertEqual "number of rows" (width inst) (length (mds inst))
    assertBool "every row has width entries" (all ((== width inst) . length) (mds inst))
  it "ARK has (R_F + R_P) * width entries" $
    assertEqual
      "length ark"
      ((nbFullRounds inst + nbPartialRounds inst) * width inst)
      (length (ark inst))
  it "batchSize disables batched partial rounds" $
    assertEqual "R_P `div` batchSize" 0 (nbPartialRounds inst `div` batchSize inst)
  it "ARK plus width trailing zeros matches poseidon_compute_number_of_constants" $ do
    -- This is the load-bearing agreement between the constants we embed and
    -- the number of constants the C permutation actually consumes: the raw
    -- ARK constants plus the `width` trailing zero constants provided by the
    -- zero-initialized context buffer (see Cardano.Crypto.Poseidon.Internal,
    -- "Zero padding").
    let expected =
          c_poseidon_compute_number_of_constants
            (fromIntegral (batchSize inst))
            (fromIntegral (nbPartialRounds inst))
            (fromIntegral (nbFullRounds inst))
            (fromIntegral (width inst))
    assertEqual "length ark + width" expected (fromIntegral (length (ark inst) + width inst))
  it "all constants are canonical field elements (0 <= x < r)" $
    assertBool
      "mds ++ ark all in [0, r)"
      (all (\x -> x >= 0 && x < scalarPeriod) (concat (mds inst) ++ ark inst))
  it "ARK constants are pairwise distinct and nonzero" $ do
    -- Not a mathematical requirement of Poseidon, but a property of these
    -- NUMS-style generated constants; a duplicated, dropped or zeroed value
    -- in the embedding would be a transcription error, and a zero constant
    -- would silently skip an ARK addition.
    assertEqual "distinct ark" (length (ark inst)) (Set.size (Set.fromList (ark inst)))
    assertBool "nonzero ark" (0 `notElem` ark inst)
  it "MDS is genuinely MDS: every square minor is nonzero mod r" $
    -- The defining property (branch number t + 1) behind the wide-trail
    -- security argument; [GKRRS21] footnote 7: "a matrix M is MDS iff every
    -- submatrix of M is non-singular". Subsumes invertibility (the order-w
    -- minor is the determinant).
    assertBool "all minors nonzero" (allSquareMinorsNonZero (mdsF inst))
  it "no M-invariant subspace keeps the partial-round S-box inactive (subspace-trail check)" $
    -- [GKRRS21] section 2.3 / [GRS20]: no infinitely long subspace trail
    -- may avoid the partial-round S-box, i.e. the only M-invariant
    -- subspace contained in { x : x_sboxlane = 0 } is the trivial one.
    -- That holds iff the observability matrix with rows e_l M^j
    -- (j = 0 .. t-1, l the S-box lane) has full rank t — for a square
    -- matrix, a nonzero determinant. This is the CIP's admission
    -- criterion; the stronger condition that no power M^i has any
    -- eigenvalue in F_r is sufficient but NOT necessary, and both
    -- registered width-3 instances fail it while satisfying this one.
    assertBool
      "observability matrix e_l M^j has full rank"
      (determinant (observabilityMatrix inst) /= 0)

---- Field arithmetic for the checks above lives in
---- Test.Crypto.Poseidon.Field ('FieldElem', an Integer-based independent
---- oracle for F_r, with Num/Fractional instances so expressions read like
---- ordinary math). Everything below is small linear algebra over it; only
---- used to check static properties of the embedded constants, so clarity
---- beats speed throughout.

-- | The instance's MDS matrix as field elements.
mdsF :: PoseidonInstance -> [[FieldElem]]
mdsF = map (map fromInteger) . mds

-- | The rows @e_l M^j@ for @j = 0 .. t-1@, where @l@ is the instance's
-- partial-round S-box lane and @e_l@ the corresponding standard basis
-- (row) vector. Full rank of this matrix is exactly the subspace-trail
-- criterion asserted above.
observabilityMatrix :: PoseidonInstance -> [[FieldElem]]
observabilityMatrix inst = take w (iterate rowTimesM e_l)
  where
    m = mdsF inst
    w = width inst
    lane = case partialSBoxLane inst of
      SBoxFirst -> 0
      SBoxLast -> w - 1
    e_l = [if j == lane then 1 else 0 | j <- [0 .. w - 1]]
    rowTimesM v = [sum (zipWith (*) v col) | col <- columns]
    columns = [[row !! j | row <- m] | j <- [0 .. w - 1]]

-- | Determinant by Laplace expansion along the first row. Exponential in the
-- matrix size, which is fine for the tiny widths in the registry.
determinant :: [[FieldElem]] -> FieldElem
determinant [] = 1
determinant m =
  sum
    [ sign j * (head m !! j) * determinant (map (dropColumn j) (tail m))
    | j <- [0 .. length m - 1]
    ]
  where
    sign j = if even (j :: Int) then 1 else -1
    dropColumn j row = take j row ++ drop (j + 1) row

-- | Every square submatrix (all row subsets x all equally-sized column
-- subsets) has a nonzero determinant.
allSquareMinorsNonZero :: [[FieldElem]] -> Bool
allSquareMinorsNonZero m =
  and
    [ determinant [[(m !! i) !! j | j <- cols] | i <- rows] /= 0
    | k <- [1 .. w]
    , rows <- subsetsOfSize k
    , cols <- subsetsOfSize k
    ]
  where
    w = length m
    subsetsOfSize k = filter ((== k) . length) (subsequences [0 .. w - 1])
