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

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (scalarPeriod)
import Cardano.Crypto.Hash (SHA256, digest)
import Cardano.Crypto.Poseidon.Constants (
  PoseidonInstance (..),
  batchSize,
  poseidonVariants,
  width3_128bit,
 )
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import Data.List (subsequences, transpose)
import Data.Proxy (Proxy (..))
import qualified Data.Set as Set
import Foreign.C.Types (CInt (..))
import Test.HUnit (assertBool, assertEqual)
import Test.Hspec (Spec, describe, it)

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
    assertBool "all minors nonzero" (allSquareMinorsNonZero (mds inst))
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
      ( not
          ( any
              (hasRootInFr . charPoly)
              (take (4 * width inst) (iterate (matMul (mds inst)) (mds inst)))
          )
      )

---- Arithmetic over the BLS12-381 scalar field F_r (r = 'scalarPeriod') on
---- plain 'Integer's. Only used to check static properties of the embedded
---- constants, so clarity beats speed throughout.

modR :: Integer -> Integer
modR x = x `mod` scalarPeriod

-- | Modular exponentiation by squaring.
powModR :: Integer -> Integer -> Integer
powModR b e
  | e == 0 = 1
  | even e = powModR (modR (b * b)) (e `div` 2)
  | otherwise = modR (b * powModR b (e - 1))

-- | Multiplicative inverse via Fermat little theorem (r is prime).
invModR :: Integer -> Integer
invModR x = powModR x (scalarPeriod - 2)

matMul :: [[Integer]] -> [[Integer]] -> [[Integer]]
matMul a b =
  [[modR (sum (zipWith (*) row col)) | col <- transpose b] | row <- a]

-- | Determinant by Laplace expansion along the first row. Exponential in the
-- matrix size, which is fine for the tiny widths in the registry.
determinant :: [[Integer]] -> Integer
determinant [] = 1
determinant m =
  modR . sum $
    [ sign j * (head m !! j) * determinant (map (dropColumn j) (tail m))
    | j <- [0 .. length m - 1]
    ]
  where
    sign j = if even (j :: Int) then 1 else -1
    dropColumn j row = take j row ++ drop (j + 1) row

-- | Every square submatrix (all row subsets x all equally-sized column
-- subsets) has a nonzero determinant.
allSquareMinorsNonZero :: [[Integer]] -> Bool
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
charPoly :: [[Integer]] -> [Integer]
charPoly a = go 1 zero [1]
  where
    w = length a
    zero = replicate w (replicate w 0)
    identityScaled c = [[if i == j then c else 0 | j <- [0 .. w - 1]] | i <- [0 .. w - 1]]
    trace m = modR (sum [(m !! i) !! i | i <- [0 .. w - 1]])
    matAdd = zipWith (zipWith (\x y -> modR (x + y)))
    go k mPrev cs
      | k > w = cs
      | otherwise =
          let mK = matAdd (matMul a mPrev) (identityScaled (head cs))
              cK = modR (negate (trace (matMul a mK) * invModR (fromIntegral k)))
           in go (k + 1) mK (cK : cs)

---- Minimal polynomial arithmetic over F_r, enough to decide whether a monic
---- polynomial has a root in F_r: f has a root iff gcd(x^r - x, f) has
---- positive degree (the roots of x^r - x are exactly the elements of F_r).
---- Polynomials are coefficient lists, lowest degree first.

-- | Multiply two already-reduced polynomials and reduce modulo the monic f.
polyMulMod :: [Integer] -> [Integer] -> [Integer] -> [Integer]
polyMulMod f p q = reduce full
  where
    d = length f - 1
    full =
      [ modR (sum [p !! i * q !! (k - i) | i <- [max 0 (k - (length q - 1)) .. min k (length p - 1)]])
      | k <- [0 .. length p + length q - 2]
      ]
    reduce cs
      | length cs <= d = cs ++ replicate (d - length cs) 0
      | otherwise =
          let top = last cs
              rest = init cs
              offset = length rest - d
              rest' =
                [ if i >= offset then modR (c - top * f !! (i - offset)) else c
                | (i, c) <- zip [0 ..] rest
                ]
           in reduce rest'

-- | x^r modulo the monic polynomial f, by square-and-multiply on r's bits.
xPowRMod :: [Integer] -> [Integer]
xPowRMod f = go [1] xPoly scalarPeriod
  where
    d = length f - 1
    xPoly = take d ([0, 1] ++ repeat 0)
    go acc _ 0 = acc
    go acc b e
      | odd e = go (polyMulMod f acc b) (polyMulMod f b b) (e `div` 2)
      | otherwise = go acc (polyMulMod f b b) (e `div` 2)

polyDegree :: [Integer] -> Int
polyDegree p = go (length p - 1)
  where
    go i
      | i < 0 = -1
      | p !! i /= 0 = i
      | otherwise = go (i - 1)

polyGcdDegree :: [Integer] -> [Integer] -> Int
polyGcdDegree a b
  | polyDegree b < 0 = polyDegree a
  | polyDegree a < polyDegree b = polyGcdDegree b a
  | otherwise = polyGcdDegree b (polyRem a b)
  where
    polyRem p q =
      let dq = polyDegree q
          inv = invModR (q !! dq)
          step u
            | polyDegree u < dq = u
            | otherwise =
                let du = polyDegree u
                    c = modR (u !! du * inv)
                 in step
                      [ if i >= du - dq && i <= du then modR (x - c * q !! (i - (du - dq))) else x
                      | (i, x) <- zip [0 ..] u
                      ]
       in step p

-- | Does the monic polynomial f have a root in F_r?
hasRootInFr :: [Integer] -> Bool
hasRootInFr f = polyGcdDegree f xrMinusX > 0
  where
    xr = xPowRMod f
    -- x^r - x, already reduced mod f
    xrMinusX = case xr of
      (c0 : c1 : rest) -> c0 : modR (c1 - 1) : rest
      _ -> error "hasRootInFr: degree < 2 polynomial"
