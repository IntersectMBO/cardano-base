-- | Preprocessing of round constants for the batched partial-round
-- optimization (the \"linear trick\" of
-- <https://eprint.iacr.org/2022/462 eprint 2022\/462>, §4.2).
--
-- The C permutation can flatten groups of @batch_size@ partial rounds into
-- one pass, but then consumes /composed/ coefficients — the setup-time
-- product of the batch's interleaved MDS multiplications and ARK additions
-- — instead of the raw ARK constants. The C never computes these
-- coefficients; in the upstream project that preprocessing lives on the
-- OCaml side. This module is a port of @compute_updated_constants@ and
-- @compute_updated_constants_one_batch@ from
-- <https://gitlab.com/nomadic-labs/cryptography/ocaml-bls12-381-hash>
-- (@src\/poseidon_utils.ml@), restated over plain affine forms: the
-- upstream represents the batch state symbolically as polynomials in which
-- every \"variable\" is a distinct monomial and no products of variables
-- ever occur (all operations are linear), so an affine form — coefficients
-- over a fixed variable basis plus a constant term — is the same
-- computation without the polynomial machinery.
--
-- The composition encodes the C core's convention that the partial-round
-- S-box acts on the __last__ state element, so it must only ever be run on
-- an instance in the C-native form — see the precondition on
-- 'computeConstantsRegion'.
--
-- == The constants region, by section
--
-- For batch size @k@, 'computeConstantsRegion' produces the whole region in
-- the exact order @poseidon_apply_permutation@ consumes it:
--
-- 1. @rf\/2 · w + w@ __raw__ constants: the initial ARK, the trailing ARKs
--    of the first-half full rounds — the last of which is, in the C's
--    phrasing, the /first partial round's/ ARK (rounds end with the next
--    round's constants);
-- 2. per batch of @k@ partial rounds, the __composed__ coefficients (see
--    below), consuming @k·w@ raw ARK values per batch;
-- 3. @(rp \`mod\` k) · w@ __raw__ constants for the leftover partial rounds
--    that do not fill a batch;
-- 4. @(rf\/2 − 1) · w@ __raw__ constants for the closing full rounds — the
--    final round's ARK does not exist and is covered by the zero padding
--    the context constructor provides (see
--    "Cardano.Crypto.Poseidon.Internal", /Zero padding/), which is also
--    why it is __not__ part of this region.
--
-- With @k = rp + 1@ (the unbatched configuration of
-- 'Cardano.Crypto.Poseidon.Constants.batchSize') there are no batches and
-- the four sections are consecutive slices of the raw ARK list — the
-- region is the raw ARK list itself. The test suite asserts this identity.
-- The unbatched configuration is the production path
-- ('Cardano.Crypto.Poseidon.Internal.newPoseidonTemplate') and the
-- reference oracle; batched configurations are the future optimization,
-- exercised by the test suite via
-- 'Cardano.Crypto.Poseidon.Internal.newPoseidonTemplateWithBatchSize' and
-- asserted to compute the identical permutation.
--
-- == One batch
--
-- A batch flattens @k@ partial rounds. Name the state at batch entry
-- @x_0, …, x_{w-1}@; the entry S-box turns the last element into
-- @x_{w-1}^α@, and each of the @k-1@ temporaries @tmp_i@ is the
-- pre-S-box value feeding the next round. Over the variable basis
--
-- @
-- [ x_0, …, x_{w-2}, x_{w-1}^α, tmp_0^α, …, tmp_{k-2}^α ]
-- @
--
-- every intermediate value is an affine form, because rounds only apply
-- the (constant) MDS matrix and add (constant) ARK chunks. The emitted
-- coefficients are, in consumption order:
--
-- * for each temporary @tmp_i@ (i = 0 … k−2): its coefficients over the
--   @w + i@ variables known so far, then its additive constant —
--   @w + i + 1@ values;
-- * then for each of the @w@ output elements: its coefficients over all
--   @w + k - 1@ variables, then its additive constant — @w + k@ values.
--
-- That is @(k−1)(w+1) + (k−1)(k−2)\/2 + w(w+k)@ values per batch, exactly
-- what @poseidon_compute_number_of_constants@ budgets and what the loops
-- in @poseidon_apply_batched_partial_round@ read back.
module Cardano.Crypto.Poseidon.Batching (
  computeConstantsRegion,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (scalarPeriod)
import Cardano.Crypto.Poseidon.Constants (PartialSBoxLane (..), PoseidonInstance (..))

-- | The full round-constants region for the given batch size, in the exact
-- order the C permutation consumes it, /without/ the trailing @w@ zero
-- padding (the zero-initialized context buffer provides that).
--
-- Preconditions (violations are programming errors, not input errors):
--
-- * @batchSize >= 1@ — the same bound the C constructor enforces;
-- * the instance is in the C-native form
--   (@'partialSBoxLane' == 'SBoxLast'@): the batch composition models the
--   C core's last-lane S-box, so an 'SBoxFirst' instance must be
--   lane-normalized first ('Cardano.Crypto.Poseidon.Internal.nativeForm')
--   — composing its raw constants directly would produce a region that is
--   silently wrong for that instance's permutation.
computeConstantsRegion :: Int -> PoseidonInstance -> [Integer]
computeConstantsRegion k inst
  | k < 1 = error "computeConstantsRegion: batch size must be >= 1"
  | partialSBoxLane inst /= SBoxLast =
      error "computeConstantsRegion: instance must be in the C-native (last-lane S-box) form"
  | otherwise =
      concat
        [ arcStart
        , concatMap (composeBatch w k (mds inst)) kColsPerBatch
        , unbatchedArc
        , arcFullRoundEnd
        ]
  where
    w = width inst
    rf = nbFullRounds inst
    rp = nbPartialRounds inst
    arc = ark inst
    slice offset n = take n (drop offset arc)

    -- Section boundaries, mirroring compute_updated_constants upstream.
    arcOffset = (rf * w) `div` 2 + w
    nbBatch = rp `div` k
    arcPerBatch = k * w
    unbatchedOffset = arcOffset + nbBatch * arcPerBatch
    unbatchedSize = (rp `mod` k) * w

    arcStart = slice 0 arcOffset
    kColsPerBatch =
      [ chunksOf w (slice (arcOffset + i * arcPerBatch) arcPerBatch)
      | i <- [0 .. nbBatch - 1]
      ]
    unbatchedArc = slice unbatchedOffset unbatchedSize
    arcFullRoundEnd = slice (unbatchedOffset + unbatchedSize) (((rf `div` 2) - 1) * w)

-- | An affine form over the batch's variable basis: a fixed-length
-- coefficient vector (length @w + k - 1@; variables not yet introduced
-- have coefficient zero and are never touched before their introduction)
-- plus a constant term. All arithmetic is modulo r.
data AffineForm = AffineForm
  { afCoeffs :: ![Integer]
  , afConstant :: !Integer
  }

-- | The composed constants of one batch of @k@ partial rounds, in
-- consumption order; @kCols@ are the @k@ ARK chunks (of @w@ raw constants
-- each) the batch absorbs. Port of @compute_updated_constants_one_batch@.
composeBatch :: Int -> Int -> [[Integer]] -> [[Integer]] -> [Integer]
composeBatch w k mdsRows kCols =
  concat temporaryRows ++ concat finalRows
  where
    nVars = w + k - 1

    addR a b = (a + b) `mod` scalarPeriod
    mulR a b = (a * b) `mod` scalarPeriod

    -- The i-th basis variable as an affine form.
    basisVar i = AffineForm [if j == i then 1 else 0 | j <- [0 .. nVars - 1]] 0

    -- The state at batch entry (after the entry S-box): the first w basis
    -- variables, the last of which stands for x_{w-1}^alpha.
    entryState = map basisVar [0 .. w - 1]

    addForms (AffineForm cs1 c1) (AffineForm cs2 c2) =
      AffineForm (zipWith addR cs1 cs2) (addR c1 c2)
    scaleForm s (AffineForm cs c) = AffineForm (map (mulR s) cs) (mulR s c)

    -- One partial round's linear part: MDS multiply the state of affine
    -- forms, then add the round's ARK chunk to the constant terms.
    linearRound arkChunk st =
      zipWith
        (\c form -> form {afConstant = addR c (afConstant form)})
        arkChunk
        [foldl1 addForms (zipWith scaleForm row st) | row <- mdsRows]

    -- Walk the k-1 temporaries: after each linear round the last state
    -- element is the value the next round S-boxes; emit its coefficients
    -- over the w+i variables introduced so far plus its constant, then
    -- replace it with the fresh post-S-box variable tmp_i^alpha.
    step (st, rows) i =
      let st' = linearRound (kCols !! i) st
          tmpForm = st' !! (w - 1)
          row = take (w + i) (afCoeffs tmpForm) ++ [afConstant tmpForm]
          st'' = take (w - 1) st' ++ [basisVar (w + i)]
       in (st'', rows ++ [row])

    (stateBeforeFinal, temporaryRows) = foldl step (entryState, []) [0 .. k - 2]

    -- The final linear round reconstructs the w output elements; emit each
    -- element's coefficients over all variables plus its constant.
    finalRows =
      [ afCoeffs form ++ [afConstant form]
      | form <- linearRound (kCols !! (k - 1)) stateBeforeFinal
      ]

-- | Split into consecutive n-element chunks; the slice lengths fed in are
-- exact multiples of w, so no ragged final chunk arises.
chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (c, rest) = splitAt n xs in c : chunksOf n rest
