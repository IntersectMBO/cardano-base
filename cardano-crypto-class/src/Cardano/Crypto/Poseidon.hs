-- | The Poseidon permutation over the BLS12-381 scalar field.
--
-- This is the public face of the binding and the intended backing
-- implementation of the Plutus builtin @bls12_381_poseidonPermutation@
-- proposed by the CIP /Poseidon Permutation Built-in for Plutus/;
-- everything a caller might expect and not find here (input padding, a
-- digest-shaped output, a hash function) is a deliberate omission,
-- explained below. The C contract and the binding mechanics live in
-- "Cardano.Crypto.Poseidon.Internal" (including an overview of the
-- permutation itself); the instance data and the variant registry in
-- "Cardano.Crypto.Poseidon.Constants".
--
-- == Variant registry
--
-- A parameter set is selected by an 'Integer' index so that new instances
-- (other widths, other constants) can be added later without changing
-- existing behavior. The registered instances mirror the CIP's registry:
--
-- * index 0 — the midnight-zk instance (plonkish\/halo2 ecosystem): width
--   3, @R_P = 60@, partial-round S-box on the last lane;
-- * index 1 — the circom BLS12-381 port's width-3 instance (circomlib-style
--   R1CS ecosystem): width 3, @R_P = 56@, partial-round S-box on the
--   __first__ lane. Input and output states are in the instance's own
--   (upstream) lane order; that the binding realizes it internally through
--   a state-reversal conjugation is not observable.
--
-- The registry contract — indices are append-only, an index's meaning is
-- never changed or reused, an observably identical but faster
-- implementation is not a new variant, an index identifies a permutation
-- and never a hash — is documented at
-- 'Cardano.Crypto.Poseidon.Constants.poseidonVariants'.
--
-- == A permutation, not a hash
--
-- The API is the /permutation/, not a hash: it returns the full
-- @width@-element output state of a public bijection with no security
-- properties of its own. Every hash-like property a caller obtains —
-- one-wayness, compression, binding — comes exclusively from the /framing/
-- built around the permutation (capacity placement and initialization,
-- absorption order, which lanes are read off), never from the permutation
-- itself; in particular the full output state is never a commitment, since
-- the permutation is invertible. Framings are the caller's explicit,
-- auditable choice; the CIP documents each registered instance's ecosystem
-- framing (non-normatively, with known-answer vectors reproduced in this
-- package's test suite). The two deployed examples:
--
-- The midnight-zk 3-input hash (variant 0; capacity lane last, initialized
-- to the input count, rate-2 chunks, digest = first lane):
--
-- @
-- hash3 in1 in2 in3 =
--   let Right [x, y, z]    = 'poseidonPermutationInteger' 0 [in1, in2, 3]
--       Right [x', y', z'] = 'poseidonPermutationInteger' 0 [x + in3, y, z]
--   in x'
-- @
--
-- The circom 2-input hash (variant 1; capacity lane first, fixed to zero,
-- a single permutation call, digest = first lane):
--
-- @
-- hash2 in1 in2 = head \<$\> 'poseidonPermutationInteger' 1 [0, in1, in2]
-- @
--
-- == No implicit padding
--
-- 'poseidonPermutation' rejects input whose length differs from the
-- variant's width — it never zero-pads. Zero-padding is not injective: it
-- would make @[a]@ and @[a, 0]@ produce the identical state and therefore
-- the identical output, a built-in hash collision — the same ambiguity
-- class behind known Merkle-tree second-preimage attacks. Padding and
-- domain separation are the caller's explicit, auditable decision.
--
-- == Integer boundary (reduction semantics)
--
-- Plutus builtins work over 'Integer', not 'Fr', so
-- 'poseidonPermutationInteger' mirrors how plutus-core adapts the existing
-- BLS12-381 builtins (e.g. @scalarMul@) over
-- "Cardano.Crypto.EllipticCurve.BLS12_381": every input is reduced modulo
-- the scalar field order r via the same conversion
-- (@scalarFromInteger@, which computes @n \`mod\` r@ with Haskell's 'mod',
-- so inputs @>= r@ wrap around and negative inputs land in @[0, r)@ —
-- e.g. @-1@ becomes @r - 1@). Outputs are canonical representatives in
-- @[0, r)@. Callers that consider out-of-range inputs an error must check
-- before calling; the reduction is deliberately total, matching the
-- builtin precedent.
--
-- == Purity and errors
--
-- Both functions are pure; the per-variant context template is a top-level
-- CAF built on first use and shared for the program lifetime (see /Purity
-- and the template scheme/ in "Cardano.Crypto.Poseidon.Internal" for why
-- sharing it between concurrent callers is safe). Failures are reported as
-- 'Either' with a descriptive 'PoseidonError' rather than 'Maybe': the two
-- failure modes are caller errors with different fixes, and the eventual
-- builtin adapter should be able to say which precondition failed.
module Cardano.Crypto.Poseidon (
  PoseidonError (..),
  poseidonPermutation,
  poseidonPermutationInteger,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  Fr,
  frFromScalar,
  scalarFromFr,
  scalarFromInteger,
  scalarToInteger,
 )
import Cardano.Crypto.Poseidon.Constants (PoseidonInstance (..), circomWidth3, midnightWidth3)
import Cardano.Crypto.Poseidon.Internal (
  PoseidonTemplate,
  newPoseidonTemplate,
  poseidonPermute,
  templateInstance,
 )
import System.IO.Unsafe (unsafePerformIO)

-- | Why a call was rejected. Both cases are caller errors; conditions the
-- caller cannot cause or fix (allocation failure, broken registry data) are
-- 'error's instead, because they indicate a library bug or an unrecoverable
-- environment failure, not a bad argument.
data PoseidonError
  = -- | The variant index is not registered; see
    -- 'Cardano.Crypto.Poseidon.Constants.poseidonVariants' for the
    -- registry (and its append-only contract).
    PoseidonUnknownVariant !Integer
  | -- | @'PoseidonWrongInputLength' expected actual@: the input state must
    -- have exactly the variant's width. It is never padded — see /No
    -- implicit padding/ in the module header for why.
    PoseidonWrongInputLength !Int !Int
  deriving (Eq, Show)

-- | Apply the Poseidon permutation of the given registry variant to a full
-- input state of exactly @width@ elements, returning the full output state.
-- States are in the variant's own lane order, the order the CIP's normative
-- test vectors are stated in.
--
-- Returns 'Left' on an unregistered variant index or a wrong input length;
-- see the module header for the design rationale of both. Pure: this is a
-- composition of the pure template lookup and
-- 'Cardano.Crypto.Poseidon.Internal.poseidonPermute'.
poseidonPermutation :: Integer -> [Fr] -> Either PoseidonError [Fr]
poseidonPermutation variantIndex input =
  case variantTemplate variantIndex of
    Nothing -> Left (PoseidonUnknownVariant variantIndex)
    Just tmpl
      | inputLength /= w -> Left (PoseidonWrongInputLength w inputLength)
      | otherwise ->
          case poseidonPermute tmpl input of
            Just output -> Right output
            -- poseidonPermute returns Nothing only for a wrong input
            -- length (excluded above) or scratch-context allocation
            -- failure, which is not a caller error and not recoverable.
            Nothing -> error "poseidonPermutation: scratch context allocation failed"
      where
        w = width (templateInstance tmpl)
        inputLength = length input

-- | 'poseidonPermutation' over 'Integer's, the boundary a Plutus builtin
-- adapter works with. Inputs are reduced modulo r, outputs are canonical
-- representatives in @[0, r)@ — the exact semantics are spelled out under
-- /Integer boundary/ in the module header.
--
-- Pure for the same reasons as the 'Fr' API: the conversions in both
-- directions are deterministic and touch only freshly allocated private
-- buffers ('unsafePerformIO' with @NOINLINE@, following
-- "Cardano.Crypto.Poseidon.Internal").
poseidonPermutationInteger :: Integer -> [Integer] -> Either PoseidonError [Integer]
poseidonPermutationInteger variantIndex input =
  unsafePerformIO $ do
    frs <- mapM (\n -> scalarFromInteger n >>= frFromScalar) input
    case poseidonPermutation variantIndex frs of
      Left e -> pure (Left e)
      Right output -> Right <$> mapM (\f -> scalarFromFr f >>= scalarToInteger) output
{-# NOINLINE poseidonPermutationInteger #-}

-- | The cached context template of a registered variant.
--
-- Every index registered in
-- 'Cardano.Crypto.Poseidon.Constants.poseidonVariants' must have a
-- matching case here pointing at a dedicated top-level CAF, so the
-- expensive template construction (an Integer-to-Montgomery conversion per
-- constant — 213 for variant 0, 201 for variant 1) happens once per
-- program run, not once per call. The two tables cannot drift silently: a
-- variant registered there but missing here makes 'poseidonPermutation'
-- report 'PoseidonUnknownVariant', which the per-variant acceptance tests
-- catch.
variantTemplate :: Integer -> Maybe PoseidonTemplate
variantTemplate 0 = Just midnightWidth3Template
variantTemplate 1 = Just circomWidth3Template
variantTemplate _ = Nothing

-- | Template CAF for variant 0. Falling out of 'newPoseidonTemplate' with
-- 'Nothing' here is impossible for intact registry data (its shape and
-- count invariants are enforced by the test suite), so it is reported as a
-- library bug rather than threaded to callers as an error they cannot act
-- on.
midnightWidth3Template :: PoseidonTemplate
midnightWidth3Template =
  case newPoseidonTemplate midnightWidth3 of
    Just tmpl -> tmpl
    Nothing -> error "Cardano.Crypto.Poseidon: midnightWidth3 failed template validation (library bug)"
{-# NOINLINE midnightWidth3Template #-}

-- | Template CAF for variant 1; the same impossibility argument as for
-- variant 0 applies.
circomWidth3Template :: PoseidonTemplate
circomWidth3Template =
  case newPoseidonTemplate circomWidth3 of
    Just tmpl -> tmpl
    Nothing -> error "Cardano.Crypto.Poseidon: circomWidth3 failed template validation (library bug)"
{-# NOINLINE circomWidth3Template #-}
