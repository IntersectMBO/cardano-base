-- | A reference implementation of the BLS12-381 scalar field F_r on plain
-- 'Integer's, used by the Poseidon constant tests ("Test.Crypto.Poseidon")
-- as an /independent oracle/.
--
-- Deliberately __not__ backed by blst's @blst_fr_*@ arithmetic: the point
-- of those property tests is to check the embedded constants with
-- arithmetic that shares nothing with the library under test. Binding
-- @blst_fr_add@\/@blst_fr_mul@ for this would verify blst-adjacent data
-- with blst itself and grow the FFI surface for a test-only benefit. GHC
-- 'Integer' arithmetic is the boring, trustworthy oracle.
--
-- The 'Num' and 'Fractional' instances make field expressions read like
-- ordinary math — @a * b + c@, @recip x@, @x \/ y@ — and integer literals
-- are reduced modulo r, so @-1@ is the field's additive inverse of one.
-- Only used in tests, so clarity beats speed throughout.
module Test.Crypto.Poseidon.Field (
  FieldElem,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (scalarPeriod)
import Data.Ratio (denominator, numerator)

-- | An element of F_r, always kept in canonical form (@0 <= x < r@).
-- Construct with 'fromInteger' (i.e. integer literals); compare with '(==)'.
newtype FieldElem = FieldElem Integer
  deriving (Eq, Show)

instance Num FieldElem where
  FieldElem a + FieldElem b = FieldElem ((a + b) `mod` scalarPeriod)
  FieldElem a - FieldElem b = FieldElem ((a - b) `mod` scalarPeriod)
  FieldElem a * FieldElem b = FieldElem ((a * b) `mod` scalarPeriod)
  negate (FieldElem a) = FieldElem (negate a `mod` scalarPeriod)
  fromInteger n = FieldElem (n `mod` scalarPeriod)

  -- The canonical representative is already non-negative, and a field has
  -- no meaningful sign; these exist only to complete the class.
  abs = id
  signum (FieldElem 0) = FieldElem 0
  signum _ = FieldElem 1

instance Fractional FieldElem where
  -- Fermat inversion: a^(r-2) = a^(-1) for prime r and a /= 0.
  recip (FieldElem 0) = error "FieldElem: division by zero"
  recip (FieldElem a) = FieldElem (powMod a (scalarPeriod - 2))
  fromRational q = fromInteger (numerator q) / fromInteger (denominator q)

-- | Modular exponentiation by squaring, modulo r.
powMod :: Integer -> Integer -> Integer
powMod b e
  | e == 0 = 1
  | even e = powMod (b * b `mod` scalarPeriod) (e `div` 2)
  | otherwise = b * powMod b (e - 1) `mod` scalarPeriod
