-- | The Poseidon permutation over the BLS12-381 scalar field, intended to
-- back the proposed Plutus builtin @bls12_381_poseidonPermutation@.
--
-- This is the bare /permutation/: a public bijection over @width@-element
-- states with no security properties of its own. It is not a hash. Hash
-- properties (one-wayness, compression, binding) only arise from the
-- framing a caller builds around it: capacity placement and
-- initialization, absorption order, which output lanes are read.
--
-- A parameter set is selected by an 'Integer' index into an append-only
-- registry ('Cardano.Crypto.Poseidon.Constants.poseidonVariants'); an
-- index, once assigned, never changes meaning. Registered variants:
--
-- * 0 — midnight-zk instance: width 3, @R_F = 8@, @R_P = 60@,
--   partial-round S-box on the last lane;
-- * 1 — circom BLS12-381 port: width 3, @R_F = 8@, @R_P = 56@,
--   partial-round S-box on the first lane.
--
-- Both variants also use different constants for the MDS matrix and ARC
-- constants, see 'Cardano.Crypto.Poseidon.Constants'.
module Cardano.Crypto.Poseidon (
  PoseidonError (..),
  poseidonPermutation,
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
import Control.Monad ((>=>))
import System.IO.Unsafe (unsafePerformIO)

-- | Why a call was rejected. Both cases are caller errors.
data PoseidonError
  = -- | The variant index is not registered.
    PoseidonUnknownVariant !Integer
  | -- | @'PoseidonWrongInputLength' expected actual@: the input must have
    -- exactly the variant's width.
    PoseidonWrongInputLength !Int !Int
  deriving (Eq, Show)

-- | Apply the Poseidon permutation of the given registry variant to an
-- input state of exactly @width@ elements, returning the full output
-- state. States are in the variant's own (upstream) lane order. Inputs are
-- reduced modulo the scalar field order @r@ (so @-1@ becomes @r - 1@);
-- outputs are canonical representatives in @[0, r)@.
poseidonPermutation :: Integer -> [Integer] -> Either PoseidonError [Integer]
poseidonPermutation variantIndex input =
  unsafePerformIO $ do
    frs <- mapM (scalarFromInteger >=> frFromScalar) input
    case poseidonPermutation' variantIndex frs of
      Left e -> pure (Left e)
      Right output -> Right <$> mapM (scalarFromFr >=> scalarToInteger) output
{-# NOINLINE poseidonPermutation #-}

-- | 'poseidonPermutation' over 'Fr' states, the form the permutation
-- actually runs on.
poseidonPermutation' :: Integer -> [Fr] -> Either PoseidonError [Fr]
poseidonPermutation' variantIndex input =
  case variantTemplate variantIndex of
    Nothing -> Left (PoseidonUnknownVariant variantIndex)
    Just tmpl ->
      case poseidonPermute tmpl input of
        Just output -> Right output
        Nothing ->
          Left (PoseidonWrongInputLength (width (templateInstance tmpl)) (length input))

-- | The cached context template of a registered variant. Each case points
-- at a dedicated top-level CAF — a /constant applicative form/, i.e. an
-- argument-less top-level binding, which GHC evaluates at most once (on
-- first use) and then retains for the program's lifetime, every later use
-- sharing the value. This is what makes constants conversion a once-per-run
-- cost instead of a per-call one; the @NOINLINE@ pragmas keep GHC from
-- inlining the bindings and rebuilding the template at use sites. Every
-- index in 'Cardano.Crypto.Poseidon.Constants.poseidonVariants' needs a
-- case here.
variantTemplate :: Integer -> Maybe PoseidonTemplate
variantTemplate 0 = Just midnightWidth3Template
variantTemplate 1 = Just circomWidth3Template
variantTemplate _ = Nothing

-- | Template CAF for variant 0.
midnightWidth3Template :: PoseidonTemplate
midnightWidth3Template = newPoseidonTemplate midnightWidth3
{-# NOINLINE midnightWidth3Template #-}

-- | Template CAF for variant 1.
circomWidth3Template :: PoseidonTemplate
circomWidth3Template = newPoseidonTemplate circomWidth3
{-# NOINLINE circomWidth3Template #-}
