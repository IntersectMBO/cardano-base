-- | A naive, clarity-first reference implementation of the Poseidon
-- permutation over 'FieldElem', used by "Test.Crypto.Poseidon" as a
-- differential-testing oracle against the C binding.
--
-- This implements the algorithm as specified ([GKRRS21], eprint 2019\/458):
-- rounds of add-round-key \/ S-box \/ MDS multiply, with the S-box applied
-- to every element in the @R_F@ outer full rounds and to the last element
-- only in the @R_P@ middle partial rounds. It deliberately shares nothing
-- with the C implementation — no blst arithmetic, no batching, and no
-- zero-padding trick: here the final round simply /has no/ trailing
-- round-key addition. Agreement with the C output on random states
-- therefore independently checks the binding end to end, including the
-- claim that the C's @w@ trailing padding constants are zero.
--
-- Speed is a non-goal; the C binding exists precisely because this is slow.
module Test.Crypto.Poseidon.Reference (
  referencePoseidon,
) where

import Cardano.Crypto.Poseidon.Constants (PoseidonInstance (..))
import Test.Crypto.Poseidon.Field (FieldElem)

data RoundKind = Full | Partial

-- | The Poseidon permutation on a full state of exactly @width@ elements.
-- Errors on a wrong-length input — this is a test oracle, not an API.
referencePoseidon :: PoseidonInstance -> [FieldElem] -> [FieldElem]
referencePoseidon inst input
  | length input /= w = error "referencePoseidon: input length /= width"
  | otherwise =
      -- The permutation: add the first round's constants up front, then
      -- fold each round over the state. Every round is paired with the
      -- constants it *ends* with (the next round's ARK) — see laterArks.
      foldl applyRound (addRoundKey (head arkChunks) input) (zip roundKinds laterArks)
  where
    w = width inst
    rf = nbFullRounds inst
    rp = nbPartialRounds inst
    mdsMatrix = map (map fromInteger) (mds inst)

    -- The flat ARK list holds (rf + rp) * w constants in consumption
    -- order; regrouped here into one w-element chunk per round.
    arkChunks = chunksOf w (map fromInteger (ark inst))

    -- The HADES round schedule: the R_F full rounds are split half before
    -- and half after the R_P partial rounds, so the permutation is
    -- symmetric around the cheap middle section.
    roundKinds =
      replicate (rf `div` 2) Full
        ++ replicate rp Partial
        ++ replicate (rf `div` 2) Full

    -- The first ARK chunk is added before the rounds; every round then ends
    -- by adding the NEXT round's constants, and the final round adds
    -- nothing at all. (The C achieves the same by padding with w zero
    -- constants; see Cardano.Crypto.Poseidon.Internal, "Zero padding" —
    -- agreement of this oracle with the C output checks that claim.)
    laterArks = map Just (drop 1 arkChunks) ++ [Nothing]

    -- One round: S-box, then MDS mixing, then (except in the final round)
    -- the trailing ARK. In a partial round the S-box hits only the LAST
    -- state element — which element is a per-implementation convention;
    -- this matches cbits/poseidon.c (poseidon_apply_sbox with full = 0),
    -- and the constants were generated for that convention.
    applyRound st (kind, mCs) =
      let sboxed = case kind of
            Full -> map sbox st
            Partial -> init st ++ [sbox (last st)]
          mixed = mdsMultiply sboxed
       in maybe mixed (addRoundKey mixed) mCs

    -- The state as a column vector multiplied by the MDS matrix:
    -- mixed[i] = sum_j MDS[i][j] * state[j], rows read left to right
    -- exactly as the row-major C layout does.
    mdsMultiply st = [sum (zipWith (*) row st) | row <- mdsMatrix]

    -- Elementwise addition of one w-element constants chunk to the state.
    addRoundKey = zipWith (+)

    -- x^5: the smallest power > 1 that permutes F_r. x^k is a bijection
    -- iff gcd(k, r-1) = 1; here 2, 3 and 4 all share a factor with r-1
    -- (in particular 3 divides r-1, which rules out the classic x^3
    -- S-box on this field), while gcd(5, r-1) = 1. GHC's (^) is repeated
    -- squaring in terms of FieldElem's (*), so every intermediate product
    -- is reduced modulo r; x^5 evaluates as ((x^2)^2) * x, the same
    -- operation sequence the C uses (blst_fr_sqr, sqr, mul).
    sbox x = x ^ (5 :: Int)

    -- Data.List.Split is not a testlib dependency, so a local chunksOf:
    -- splits into consecutive n-element groups (ark length is an exact
    -- multiple of w, asserted by the count tests).
    chunksOf n xs = case splitAt n xs of
      (c, []) -> [c]
      (c, rest) -> c : chunksOf n rest
