{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeApplications #-}

-- | Tests for the Poseidon instance data in "Cardano.Crypto.Poseidon.Constants".
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
import Cardano.Crypto.Poseidon.Constants (
  PoseidonInstance (..),
  batchSize,
  poseidonVariants,
  width3_128bit,
 )
import Cardano.Crypto.Poseidon.Internal (
  PoseidonTemplate,
  newPoseidonTemplate,
  poseidonPermute,
 )
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Data.List (subsequences, transpose)
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

-- | All Poseidon tests: constants invariants, Internal-level binding tests
-- (acceptance vector, differential property against the reference
-- implementation, rejections), and the public API tests.
tests :: Spec
tests =
  describe "Crypto.Poseidon" $ do
    describe "Constants" $ do
      describe "width3_128bit (variant 0)" $ do
        it "is registered at index 0" $
          assertEqual "poseidonVariants 0" (Just width3_128bit) (poseidonVariants 0)
        constantsInvariants width3_128bit
        it "embedded constants match their pinned digest (order-sensitive)" $
          -- Freezes the exact values *and* their order: the permutation
          -- consumes constants strictly sequentially, so a reordered,
          -- duplicated, dropped or extra value is as fatal as a wrong one,
          -- and none of the algebraic properties below would necessarily
          -- catch it. Any edit to the embedding must consciously update
          -- this digest.
          assertEqual
            "SHA256 (show (width, mds, ark))"
            "1289be84a2c6c1f5e4c2057c53677323ba3e223e8b3313817f388245a8fb9fae"
            (constantsDigest width3_128bit)
    describe "Internal" $ do
      it "builds a template for width3_128bit" $
        assertBool "newPoseidonTemplate width3_128bit" (isJust (newPoseidonTemplate width3_128bit))
      it "rejects invalid instances" $ do
        -- Each of these exercises a distinct validation layer documented in
        -- Cardano.Crypto.Poseidon.Internal: the first three are rejected by
        -- the C constructor (poseidon_ctxt_new), the last two by the
        -- Haskell-side shape and constant-count assertions.
        let rejects inst label = assertBool label (isNothing (newPoseidonTemplate inst))
        rejects width3_128bit {width = 1} "width 1"
        rejects width3_128bit {nbFullRounds = 7} "odd R_F"
        rejects width3_128bit {nbFullRounds = -2} "negative R_F"
        rejects width3_128bit {mds = [[1]]} "MDS shape mismatch"
        rejects width3_128bit {ark = drop 1 (ark width3_128bit)} "constant count mismatch"
      it "rejects input states of the wrong length (no implicit padding)" $ do
        tmpl <- expectJust "template" (newPoseidonTemplate width3_128bit)
        someFr <- integersToFrs [1, 2, 3, 4]
        mapM_
          ( \n ->
              assertBool
                ("input length " ++ show n)
                (isNothing (poseidonPermute tmpl (take n someFr)))
          )
          [0, 2, 4]
      it "matches the Nomadic Labs acceptance vector" $ do
        -- The reference vector for this instance, from the upstream test
        -- suite (ocaml-bls12-381-hash). Input: capacity slot zero, then the
        -- two inputs; asserted on the full output state. This exercises the
        -- whole binding: buffer layout, Montgomery conversion, batch-size
        -- choice and zero padding would each corrupt the output if wrong.
        -- (Chunk 5 re-asserts this vector through the public API.)
        tmpl <- expectJust "template" (newPoseidonTemplate width3_128bit)
        input <- integersToFrs acceptanceInput
        output <- expectJust "permute" (poseidonPermute tmpl input)
        outputIntegers <- frsToIntegers output
        assertEqual "output state" acceptanceOutput outputIntegers
      prop "agrees with the pure reference implementation on random states" $
        -- Differential test against Test.Crypto.Poseidon.Reference, a naive
        -- spec-faithful Poseidon over the FieldElem oracle that shares
        -- nothing with the C (no blst, no batching, no zero-padding trick).
        -- The acceptance vector pins a single input; this covers random
        -- states across the whole field, including the boundary values the
        -- generator injects deliberately, and re-checks the zero-padding
        -- claim on every case (the reference's last round simply has no
        -- ARK).
        forAll genState $ \xs -> ioProperty $ do
          input <- integersToFrs xs
          output <- expectJust "permute" (poseidonPermute width3Template input)
          outIntegers <- frsToIntegers output
          pure $
            map fromInteger outIntegers === referencePoseidon width3_128bit (map fromInteger xs)
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
        tmpl <- expectJust "template" (newPoseidonTemplate width3_128bit)
        input1 <- integersToFrs [5, 6, 7]
        input2 <- integersToFrs [5, 6, 7]
        out1 <- expectJust "permute 1" (poseidonPermute tmpl input1)
        out2 <- expectJust "permute 2" (poseidonPermute tmpl input2)
        r1 <- frsToIntegers out1
        r2 <- frsToIntegers out2
        assertEqual "two independent executions" r1 r2
    describe "Public API" $ do
      it "matches the Nomadic Labs acceptance vector (Integer API, variant 0)" $
        -- The same reference vector as the Internal-level test, now through
        -- the whole public stack: registry lookup, cached template,
        -- Integer reduction and canonical read-back.
        assertEqual
          "output state"
          (Right acceptanceOutput)
          (poseidonPermutationInteger 0 acceptanceInput)
      it "matches the acceptance vector through the Fr API" $ do
        input <- integersToFrs acceptanceInput
        output <- expectRight (poseidonPermutation 0 input)
        outputIntegers <- frsToIntegers output
        assertEqual "output state" acceptanceOutput outputIntegers
      it "rejects unregistered variant indices" $ do
        let rejected i =
              assertEqual
                ("variant " ++ show i)
                (Left (PoseidonUnknownVariant i))
                (poseidonPermutationInteger i [0, 0, 0])
        mapM_ rejected [1, -1, 2 ^ (64 :: Int)]
      it "rejects wrong input lengths (width - 1, width + 1, empty), never pads" $ do
        let w = width width3_128bit
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
      prop "Integer wrapper agrees with the Fr API on in-range values" $
        -- Two independent paths through conversion and permutation; the
        -- Integer wrapper must be observably nothing more than
        -- conversion + Fr API + conversion.
        forAll genState $ \xs -> ioProperty $ do
          frs <- integersToFrs xs
          viaFr <- expectRight (poseidonPermutation 0 frs) >>= frsToIntegers
          pure (poseidonPermutationInteger 0 xs === Right viaFr)
      prop "Integer <-> Fr marshalling round-trips modulo r" $
        -- Sanity for the conversion path everything above relies on:
        -- scalarFromInteger >>= frFromScalar, read back via scalarFromFr
        -- >>= scalarToInteger, must be exactly (`mod` r) — including
        -- values >= r and negative values.
        forAll genAnyInteger $ \n -> ioProperty $ do
          fr <- scalarFromInteger n >>= frFromScalar
          n' <- scalarFromFr fr >>= scalarToInteger
          pure (n' === n `mod` scalarPeriod)

-- | The variant-0 template, built once and shared by the property tests.
width3Template :: PoseidonTemplate
width3Template = fromMaybe (error "width3_128bit template failed") (newPoseidonTemplate width3_128bit)

-- | A random state for variant 0: width elements of F_r, with the boundary
-- values 0, 1 and r-1 deliberately over-represented.
genState :: Gen [Integer]
genState = vectorOf (width width3_128bit) genFieldInteger
  where
    genFieldInteger =
      frequency
        [ (1, elements [0, 1, scalarPeriod - 1])
        , (9, choose (0, scalarPeriod - 1))
        ]

-- | The Nomadic Labs reference vector for variant 0 (from the upstream
-- ocaml-bls12-381-hash test suite): input state (capacity slot zero, then
-- the two inputs) and the expected full output state.
acceptanceInput, acceptanceOutput :: [Integer]
acceptanceInput =
  [ 0
  , 19540886853600136773806888540031779652697522926951761090609474934921975120659
  , 27368034540955591518185075247638312229509481411752400387472688330662143761856
  ]
acceptanceOutput =
  [ 17943489144262435388134690770306545365190731633977654215868012824127324198151
  , 2231754119684576552235072561055622129225837122807214026821170668631716242147
  , 29261523742327067247029179638981197564247814302680832614540814949720900275190
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

-- | The count invariants of an instance, asserted as formulas rather than
-- literals so they keep holding for any instance added to the registry later.
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
  it "no power M^i (i <= 4 * width) has an eigenvalue in F_r (subspace-trail check)" $
    -- [GKRRS21] section 2.3, "Avoiding Insecure Matrices": the MDS matrix
    -- must not admit (infinitely long) invariant or iterative subspace
    -- trails over the partial rounds; the authors check M, M^2, ..., M^l
    -- with search period l = 4t using the algorithms of [GRS20]
    -- (eprint 2020/500). An eigenvalue of M^i in F_r is a one-dimensional
    -- invariant subspace of M^i, so we assert the characteristic polynomial
    -- of every such power has no root in F_r. For width 3 this makes the
    -- characteristic polynomial of M irreducible, which rules out invariant
    -- subspaces of any dimension (a 2-dimensional invariant subspace would
    -- force a linear factor for the quotient), i.e. for width 3 this is the
    -- full sufficient condition of [GRS20]. CAUTION: for width > 3,
    -- rootlessness no longer implies irreducibility (e.g. a quintic can
    -- factor 2 + 3 with no roots), so this test would weaken to a necessary
    -- condition; registering a wider variant must come with a full
    -- factorization check per [GRS20].
    assertBool
      "charpoly of M^1 .. M^(4t) rootless in F_r"
      ( let m = mdsF inst
         in not (any (hasRootInFr . charPoly) (take (4 * width inst) (iterate (matMul m) m)))
      )

---- Field arithmetic for the checks above lives in
---- Test.Crypto.Poseidon.Field ('FieldElem', an Integer-based independent
---- oracle for F_r, with Num/Fractional instances so expressions read like
---- ordinary math). Everything below is small linear algebra over it; only
---- used to check static properties of the embedded constants, so clarity
---- beats speed throughout.

-- | The instance's MDS matrix as field elements.
mdsF :: PoseidonInstance -> [[FieldElem]]
mdsF = map (map fromInteger) . mds

matMul :: [[FieldElem]] -> [[FieldElem]] -> [[FieldElem]]
matMul a b = [[sum (zipWith (*) row col) | col <- transpose b] | row <- a]

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

-- | Coefficients of the characteristic polynomial det(xI - M), lowest degree
-- first, monic. Faddeev-LeVerrier; the divisions are by 1..w, invertible
-- since r is a large prime.
charPoly :: [[FieldElem]] -> [FieldElem]
charPoly a = go 1 zeroMatrix [1]
  where
    w = length a
    zeroMatrix = replicate w (replicate w 0)
    identityScaled c = [[if i == j then c else 0 | j <- [0 .. w - 1]] | i <- [0 .. w - 1]]
    trace m = sum [(m !! i) !! i | i <- [0 .. w - 1]]
    matAdd = zipWith (zipWith (+))
    go k mPrev cs
      | k > w = cs
      | otherwise =
          let mK = matAdd (matMul a mPrev) (identityScaled (head cs))
              cK = negate (trace (matMul a mK) / fromIntegral k)
           in go (k + 1) mK (cK : cs)

---- Minimal polynomial arithmetic over F_r, enough to decide whether a monic
---- polynomial has a root in F_r: f has a root iff gcd(x^r - x, f) has
---- positive degree (the roots of x^r - x are exactly the elements of F_r).
---- Polynomials are coefficient lists, lowest degree first.

-- | Multiply two already-reduced polynomials and reduce modulo the monic f.
polyMulMod :: [FieldElem] -> [FieldElem] -> [FieldElem] -> [FieldElem]
polyMulMod f p q = reduce full
  where
    d = length f - 1
    full =
      [ sum [p !! i * q !! (k - i) | i <- [max 0 (k - (length q - 1)) .. min k (length p - 1)]]
      | k <- [0 .. length p + length q - 2]
      ]
    reduce cs
      | length cs <= d = cs ++ replicate (d - length cs) 0
      | otherwise =
          let top = last cs
              rest = init cs
              offset = length rest - d
              rest' =
                [ if i >= offset then c - top * f !! (i - offset) else c
                | (i, c) <- zip [0 ..] rest
                ]
           in reduce rest'

-- | x^r modulo the monic polynomial f, by square-and-multiply on r's bits.
xPowRMod :: [FieldElem] -> [FieldElem]
xPowRMod f = go [1] xPoly scalarPeriod
  where
    d = length f - 1
    xPoly = take d ([0, 1] ++ repeat 0)
    go acc _ 0 = acc
    go acc b e
      | odd e = go (polyMulMod f acc b) (polyMulMod f b b) (e `div` 2)
      | otherwise = go acc (polyMulMod f b b) (e `div` 2)

polyDegree :: [FieldElem] -> Int
polyDegree p = go (length p - 1)
  where
    go i
      | i < 0 = -1
      | p !! i /= 0 = i
      | otherwise = go (i - 1)

polyGcdDegree :: [FieldElem] -> [FieldElem] -> Int
polyGcdDegree a b
  | polyDegree b < 0 = polyDegree a
  | polyDegree a < polyDegree b = polyGcdDegree b a
  | otherwise = polyGcdDegree b (polyRem a b)
  where
    polyRem p q =
      let dq = polyDegree q
          inv = recip (q !! dq)
          step u
            | polyDegree u < dq = u
            | otherwise =
                let du = polyDegree u
                    c = u !! du * inv
                 in step
                      [ if i >= du - dq && i <= du then x - c * q !! (i - (du - dq)) else x
                      | (i, x) <- zip [0 ..] u
                      ]
       in step p

-- | Does the monic polynomial f have a root in F_r?
hasRootInFr :: [FieldElem] -> Bool
hasRootInFr f = polyGcdDegree f xrMinusX > 0
  where
    xr = xPowRMod f
    -- x^r - x, already reduced mod f
    xrMinusX = case xr of
      (c0 : c1 : rest) -> c0 : (c1 - 1) : rest
      _ -> error "hasRootInFr: degree < 2 polynomial"
