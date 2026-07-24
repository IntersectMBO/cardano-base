{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeApplications #-}

-- | Low-level bindings to the vendored Poseidon permutation.
--
-- The C implementation (@cbits\/poseidon.c@, taken from Nomadic Labs'
-- @ocaml-bls12-381-hash@) implements __only the Poseidon permutation__ over
-- the BLS12-381 scalar field: no sponge construction, no hashing API, no
-- memory allocation and __no input validation whatsoever__. This module owns
-- all of that. Everything below is part of the C contract and is
-- load-bearing for correctness; each fact is enforced or consumed at a
-- specific place in this module and in @cbits\/poseidon_util.c@.
--
-- == The permutation in a nutshell
--
-- Poseidon (Grassi et al., <https://eprint.iacr.org/2019/458 eprint
-- 2019\/458>) is a substitution–permutation network working directly on
-- @w@ field elements of the BLS12-381 scalar field. Each round applies
-- three operations:
--
-- * __ARK__ (add round key): add one fresh constant to every state element;
-- * __S-box__: raise state elements to the 5th power (@x⁵@ is a bijection
--   on F_r because @gcd(5, r-1) = 1@, and is cheap to express in
--   arithmetic circuits — the point of the design);
-- * __MDS__: multiply the state vector by the fixed @w×w@ MDS matrix,
--   mixing all elements.
--
-- The HADES trick that makes Poseidon cheap: only the outer @R_F@ rounds
-- are /full/ rounds applying the S-box to every element; the @R_P@ /partial/
-- rounds in the middle apply it to the __last__ state element only. The
-- outer full rounds provide the statistical security margin, the many cheap
-- partial rounds the algebraic degree:
--
-- @
--          input state (w elements)
--                 |
--                ARK          one constant per element, added up front
--                 |
--         +-------v-------+
--         |  full round   |   × R_F\/2:  S-box on ALL w elements,
--         +-------|-------+              then MDS, then ARK
--                 |
--         +-------v-------+
--         | partial round |   × R_P:    S-box on the LAST element only,
--         +-------|-------+              then MDS, then ARK
--                 |
--         +-------v-------+
--         |  full round   |   × R_F\/2:  S-box on ALL w elements,
--         +-------|-------+              then MDS, then ARK
--                 |
--          output state (w elements)
-- @
--
-- Note the C implementation's phrasing, mirrored in the diagram: the ARK is
-- hoisted /before/ the loop and each round then ends with the /next/
-- round's ARK. The final round's trailing ARK does not exist in the
-- algorithm — the implementation adds @w@ /zero/ constants instead of
-- branching, which is where the /Zero padding/ requirement below comes
-- from.
--
-- == Buffer layout
--
-- @poseidon_ctxt_t.state@ points to a __single contiguous array__ of
-- @blst_fr@ elements laid out as
--
-- @
-- [ state: w elements | MDS matrix: w×w elements, row-major | round constants: N elements ]
-- @
--
-- The MDS matrix comes immediately after the state
-- (@poseidon_get_mds_from_context@ returns @state + w@) and the round
-- constants immediately after the MDS
-- (@poseidon_get_round_constants_from_context@ returns @state + w + w²@).
-- Getting this order wrong produces silently wrong digests. The layout is
-- encoded exactly once, in @poseidon_ctxt_new@ (@cbits\/poseidon_util.c@);
-- Haskell code never computes region offsets itself, it asks the C accessors.
--
-- == Montgomery form
--
-- @blst_fr@ is 32 bytes (4 × @uint64@) in __Montgomery representation__, not
-- a plain little-endian integer. Every value written into the buffer — state
-- inputs, MDS entries, round constants — must go through the existing
-- conversion path in "Cardano.Crypto.EllipticCurve.BLS12_381.Internal"
-- (@scalarFromInteger@ then @frFromScalar@); outputs must be read back via
-- @scalarFromFr@ \/ @scalarToInteger@. Writing raw integer limbs would not
-- crash — it would produce wrong digests. 'Fr' values themselves are already
-- in Montgomery form, so moving them in and out of the buffer is a plain
-- 32-byte copy ('writeFr', 'readFr').
--
-- == Constant consumption
--
-- The permutation (@poseidon_apply_permutation@) consumes the constants
-- region strictly sequentially: one ARK (add-round-key) of @w@ constants up
-- front, then @R_F\/2@ full rounds (x⁵ S-box on every element, MDS multiply,
-- ARK), then the partial rounds (S-box on the __last__ state element only),
-- then @R_F\/2@ more full rounds. The exact number of constants consumed is
-- returned by @poseidon_compute_number_of_constants@; 'newPoseidonTemplate'
-- asserts that the constants it supplies match this count instead of
-- trusting a hardcoded number.
--
-- == Zero padding
--
-- The final constant addition consumes @w@ constants that must be __zero__:
-- the algorithm has no ARK in the last round, and the C implementation pads
-- with zero constants instead of branching.
-- @poseidon_compute_number_of_constants@ already includes these @w@ trailing
-- zeros in its count. The constants region is therefore the raw ARK
-- constants followed by @w@ zero field elements; @poseidon_ctxt_new@
-- zero-allocates the buffer (@calloc@), 'newPoseidonTemplate' writes only
-- the @length ark@ leading constants, and the trailing @w@ zeros hold
-- without relying on uninitialized memory.
--
-- == Batched partial rounds — deliberately disabled
--
-- The C supports an optimization (the \"linear trick\" of
-- <https://eprint.iacr.org/2022/462 eprint 2022\/462>, §4.2) that flattens
-- groups of @batch_size@ partial rounds. The constants for batched sections
-- are /composed/ coefficients derived from the MDS and the ARK constants —
-- __not__ the raw ARK constants. Supplying raw ARK constants while a batch
-- is active (@batch_size <= R_P@) produces garbage output, and — because a
-- batched configuration needs /more/ constants than the raw count — a heap
-- out-of-bounds read.
--
-- This binding therefore sets @batch_size = R_P + 1@ (see
-- 'Cardano.Crypto.Poseidon.Constants.batchSize'), so that
-- @R_P \`div\` batch_size == 0@ and every partial round takes the plain
-- (unbatched) path, which consumes exactly the raw ARK constants. This has
-- been verified empirically: the unbatched configuration reproduces the
-- reference test vector, the batched configuration with raw constants does
-- not. A future optimization may implement the constant composition and
-- lower @batch_size@; until then, treat any @batch_size <= R_P@ as a bug.
-- The constant-count assertion in 'newPoseidonTemplate' enforces this: with
-- an active batch, @poseidon_compute_number_of_constants@ returns more than
-- @length ark + w@ and template construction fails rather than reading out
-- of bounds.
--
-- == Parameter validation
--
-- The C validates nothing, so @poseidon_ctxt_new@ (our helper in
-- @cbits\/poseidon_util.c@) rejects, returning @NULL@:
--
-- * @batch_size < 1@ — division by zero and a negative-length VLA in the C
--   (undefined behavior);
-- * odd @R_F@ — the permutation runs @R_F \`div\` 2@ full rounds twice, i.e.
--   one round fewer than the constant count assumes (silently wrong digest);
-- * @w < 2@ — no capacity\/rate split, degenerate instance;
-- * negative counts, and parameters above a documented overflow guard.
--
-- 'newPoseidonTemplate' additionally validates what only the Haskell side
-- can see: the MDS shape (@w@ rows of @w@ entries) and the constant count
-- (fact above).
--
-- == ABI handling
--
-- @poseidon_ctxt_t@ is a pointer followed by four @int@s. Its layout is
-- __never__ replicated as hand-written byte offsets in Haskell; contexts are
-- created and freed only via the C helpers @poseidon_ctxt_new@ \/
-- @poseidon_ctxt_free@, and fields are read via the @poseidon_get_*@
-- accessors. @cbits\/poseidon_util.c@ carries a @static_assert@ tying
-- @sizeof(blst_fr)@ to the @CARDANO_BLST_FR_SIZE@ constant used by the
-- Haskell marshalling, following the @cbits\/blst_util.c@ pattern.
--
-- == Purity and the template scheme
--
-- @poseidon_apply_permutation@ mutates the state region in place, so a
-- context must never be shared between concurrent callers. This module
-- builds one immutable, fully populated 'PoseidonTemplate' per instance
-- (MDS and constants written once, state region zero) and gives every
-- 'poseidonPermute' call its own freshly allocated scratch context, into
-- which the template's buffer is copied before the input state is written.
-- The template is only ever read after construction, and the scratch
-- context is private to the call, so concurrent calls are safe.
--
-- The alternative — building a context from the 'PoseidonInstance' on every
-- call — would repeat the @length ark + w²@ Integer-to-Montgomery
-- conversions each time; the template turns that into a single ~6.6 KB
-- @memcpy@ per call for the width-3 instance (207 × 32 bytes), plus the
-- unavoidable @w@ input copies. Indicative measurement (dev machine,
-- width-3 instance): a template-based 'poseidonPermute' call takes ~23 µs
-- end to end (dominated by the permutation's ~1000 field multiplications in
-- C), while template construction measured ~3.3 ms in GHCi — an interpreted
-- upper bound, but even discounted generously the 201 conversions dwarf the
-- per-call copy.
--
-- Both entry points ('newPoseidonTemplate', 'poseidonPermute') are exposed
-- as __pure functions__ via @unsafePerformIO@, following the precedent of
-- "Cardano.Crypto.EllipticCurve.BLS12_381.Internal" (e.g. its 'Eq'
-- instances). The justification, per function: the result depends only on
-- the arguments (the C permutation is deterministic), and every effect is
-- confined to memory the call itself allocates and either frees or hands to
-- a 'ForeignPtr' — nothing observable escapes. Both carry @NOINLINE@ so the
-- simplifier cannot duplicate the @unsafePerformIO@ thunks; the worst case
-- of lost sharing is re-running a deterministic computation on private
-- memory, never a correctness issue. The raw pointer helpers ('writeFr' and
-- friends) remain in 'IO' — they mutate caller-supplied memory and are not
-- referentially transparent.
module Cardano.Crypto.Poseidon.Internal (
  -- * Template-based permutation
  PoseidonTemplate,
  templateInstance,
  newPoseidonTemplate,
  poseidonPermute,

  -- * Fr buffer marshalling
  writeFr,
  readFr,
  writeIntegerAsFr,

  -- * Raw FFI
  PoseidonCtxtPtr (..),
  c_poseidon_ctxt_new,
  c_poseidon_ctxt_free,
  c_poseidon_ctxt_free_finalizer,
  c_poseidon_apply_permutation,
  c_poseidon_get_state_from_context,
  c_poseidon_get_state_size_from_context,
  c_poseidon_get_mds_from_context,
  c_poseidon_get_round_constants_from_context,
  c_poseidon_compute_number_of_constants,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  Fr (..),
  frFromScalar,
  scalarFromInteger,
  sizeFr,
 )
import Cardano.Crypto.PinnedSizedBytes (psbCreate, psbUseAsCPtr)
import Cardano.Crypto.Poseidon.Constants (PoseidonInstance (..), batchSize)
import Control.Exception (bracket)
import Control.Monad (zipWithM_)
import Data.Void (Void)
import Data.Word (Word8)
import Foreign.C.Types (CInt (..))
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (FunPtr, Ptr, nullPtr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

#include "blst_util.h"

-- | An opaque Poseidon context (@poseidon_ctxt_t *@). Only ever obtained
-- from @poseidon_ctxt_new@; never dereferenced from Haskell (see /ABI
-- handling/ in the module header).
newtype PoseidonCtxtPtr = PoseidonCtxtPtr (Ptr Void)

---- Raw FFI imports.
----
---- All imports are `ccall unsafe`: the permutation runs in microseconds,
---- none of these functions block, allocate via the Haskell RTS, or call
---- back into Haskell, so the (cheaper) unsafe convention is appropriate;
---- the RTS capability is held for a bounded, tiny amount of time.

-- | Validated, zero-initializing constructor from @cbits\/poseidon_util.c@;
-- returns NULL on invalid parameters or allocation failure.
foreign import ccall unsafe "poseidon_ctxt_new"
  c_poseidon_ctxt_new ::
    -- | nb_full_rounds
    CInt ->
    -- | nb_partial_rounds
    CInt ->
    -- | batch_size
    CInt ->
    -- | width
    CInt ->
    IO PoseidonCtxtPtr

-- | Free a context and its buffer; NULL is a no-op.
foreign import ccall unsafe "poseidon_ctxt_free"
  c_poseidon_ctxt_free :: PoseidonCtxtPtr -> IO ()

-- | The same destructor as a static function pointer, for use as a
-- 'ForeignPtr' finalizer ('newPoseidonTemplate'). NULL-safe by contract of
-- @poseidon_ctxt_free@.
foreign import ccall "&poseidon_ctxt_free"
  c_poseidon_ctxt_free_finalizer :: FunPtr (Ptr Void -> IO ())

-- | Run the permutation, mutating the state region in place.
foreign import ccall unsafe "poseidon_apply_permutation"
  c_poseidon_apply_permutation :: PoseidonCtxtPtr -> IO ()

-- | Pointer to the state region (start of the whole buffer).
foreign import ccall unsafe "poseidon_get_state_from_context"
  c_poseidon_get_state_from_context :: PoseidonCtxtPtr -> IO (Ptr Word8)

-- | The width w.
foreign import ccall unsafe "poseidon_get_state_size_from_context"
  c_poseidon_get_state_size_from_context :: PoseidonCtxtPtr -> IO CInt

-- | Pointer to the MDS region (@state + w@).
foreign import ccall unsafe "poseidon_get_mds_from_context"
  c_poseidon_get_mds_from_context :: PoseidonCtxtPtr -> IO (Ptr Word8)

-- | Pointer to the constants region (@state + w + w²@).
foreign import ccall unsafe "poseidon_get_round_constants_from_context"
  c_poseidon_get_round_constants_from_context :: PoseidonCtxtPtr -> IO (Ptr Word8)

-- | Pure (no side effects in the C) count of the constants the permutation
-- will consume for the given configuration. Argument order follows the C
-- declaration, which differs from @poseidon_ctxt_new@ — see @poseidon.h@.
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

---- Fr buffer marshalling.

-- | Copy an 'Fr' into a @blst_fr@ slot of a context buffer. 'Fr' already
-- holds the 32-byte Montgomery representation (see /Montgomery form/ in the
-- module header), so a raw byte copy is exactly right — this is the same
-- move @cloneFr@ makes.
writeFr :: Ptr Word8 -> Fr -> IO ()
writeFr dst (Fr psb) = psbUseAsCPtr psb $ \src -> copyBytes dst src sizeFr

-- | Read a @blst_fr@ slot of a context buffer back into a fresh 'Fr'.
readFr :: Ptr Word8 -> IO Fr
readFr src = Fr <$> psbCreate @CARDANO_BLST_FR_SIZE (\dst -> copyBytes dst src sizeFr)

-- | Write an 'Integer' into a @blst_fr@ slot via the existing conversion
-- path (@scalarFromInteger@ then @frFromScalar@), i.e. through the
-- Montgomery conversion — never as raw limbs. @scalarFromInteger@ reduces
-- its argument modulo r; for the embedded constants (asserted canonical in
-- the test suite) this is the identity.
writeIntegerAsFr :: Ptr Word8 -> Integer -> IO ()
writeIntegerAsFr dst n = do
  s <- scalarFromInteger n
  fr <- frFromScalar s
  writeFr dst fr

---- Template construction and permutation.

-- | An immutable, fully populated context for one 'PoseidonInstance': MDS
-- and round constants written, state region zero. Built once per instance
-- and only ever /read/ afterwards ('poseidonPermute' copies it into a
-- private scratch context), so it may be shared freely between threads.
-- The trade-off against per-call construction is discussed under /Purity
-- and the template scheme/ in the module header.
data PoseidonTemplate = PoseidonTemplate
  { templateInstance :: !PoseidonInstance
  -- ^ The instance this template was built from.
  , templateBufferBytes :: !Int
  -- ^ Size in bytes of the whole context buffer,
  -- @(w + w² + N) * sizeFr@; cached for the per-call copy.
  , templateForeignPtr :: !(ForeignPtr Void)
  -- ^ The underlying @poseidon_ctxt_t *@, freed by @poseidon_ctxt_free@
  -- when the template is garbage collected.
  }

-- | Build the immutable template for an instance. Returns 'Nothing' if
--
-- * the MDS is not @w@ rows of @w@ entries (checked here — the C cannot
--   see the Haskell lists);
-- * the constant count is wrong: @poseidon_compute_number_of_constants@
--   must equal @length ark + w@ (the raw constants plus the trailing zero
--   padding). This is the assertion demanded by the C contract — a
--   mismatch means the permutation would read constants out of bounds (in
--   particular, any configuration with active batching fails here);
-- * the C-level parameter validation in @poseidon_ctxt_new@ rejects the
--   configuration (see /Parameter validation/ in the module header), or
--   allocation fails.
--
-- Pure despite the allocation inside: the result is a function of the
-- instance alone, and the built context is only ever reachable through the
-- returned template — see /Purity and the template scheme/ in the module
-- header for the full @unsafePerformIO@ justification.
newPoseidonTemplate :: PoseidonInstance -> Maybe PoseidonTemplate
newPoseidonTemplate inst
  | length (mds inst) /= w || any ((/= w) . length) (mds inst) = Nothing
  | length (ark inst) + w /= fromIntegral nConstants = Nothing
  | otherwise = unsafePerformIO $ do
      PoseidonCtxtPtr raw <-
        c_poseidon_ctxt_new
          (fromIntegral (nbFullRounds inst))
          (fromIntegral (nbPartialRounds inst))
          (fromIntegral (batchSize inst))
          (fromIntegral w)
      if raw == nullPtr
        then pure Nothing
        else do
          -- Attach the finalizer before filling the buffer so the context
          -- cannot leak if a conversion below throws.
          fp <- newForeignPtr c_poseidon_ctxt_free_finalizer raw
          withForeignPtr fp $ \p -> do
            let ctxt = PoseidonCtxtPtr p
            -- The MDS rows are flattened row-major here, and only here:
            -- this is the single site referred to by the 'mds' field
            -- documentation in "Cardano.Crypto.Poseidon.Constants".
            mdsPtr <- c_poseidon_get_mds_from_context ctxt
            zipWithM_
              (\i x -> writeIntegerAsFr (mdsPtr `plusPtr` (i * sizeFr)) x)
              [0 ..]
              (concat (mds inst))
            -- Only the length ark leading constants are written; the w
            -- trailing zero constants are provided by the calloc'd buffer
            -- (see /Zero padding/ in the module header).
            arkPtr <- c_poseidon_get_round_constants_from_context ctxt
            zipWithM_
              (\i x -> writeIntegerAsFr (arkPtr `plusPtr` (i * sizeFr)) x)
              [0 ..]
              (ark inst)
          pure $
            Just
              PoseidonTemplate
                { templateInstance = inst
                , templateBufferBytes = (w + w * w + fromIntegral nConstants) * sizeFr
                , templateForeignPtr = fp
                }
  where
    w = width inst
    nConstants =
      c_poseidon_compute_number_of_constants
        (fromIntegral (batchSize inst))
        (fromIntegral (nbPartialRounds inst))
        (fromIntegral (nbFullRounds inst))
        (fromIntegral w)
{-# NOINLINE newPoseidonTemplate #-}

-- | Apply the Poseidon permutation to a full state of exactly @width@
-- elements, returning the full output state. Returns 'Nothing' if the
-- input length differs from the instance width — never pads (the rationale
-- lives with the public API in "Cardano.Crypto.Poseidon") — or on
-- allocation failure.
--
-- Each call allocates a private scratch context, copies the template's
-- entire buffer into it (constants, MDS, and the zero state region),
-- overwrites the state region with the input, permutes in place, and reads
-- the state back. The template is never written to, and the scratch context
-- never escapes the call — which is also why this is pure: the output
-- depends only on the template and the input state (the C permutation is
-- deterministic), and no effect is observable from outside. See /Purity and
-- the template scheme/ in the module header.
poseidonPermute :: PoseidonTemplate -> [Fr] -> Maybe [Fr]
poseidonPermute t inputState
  | length inputState /= w = Nothing
  | otherwise = unsafePerformIO $
      -- bracket + NULL-safe free: the scratch context is released on any
      -- exit path, including exceptions from the copies below.
      bracket acquire c_poseidon_ctxt_free $ \scratch@(PoseidonCtxtPtr raw) ->
        if raw == nullPtr
          then pure Nothing
          else withForeignPtr (templateForeignPtr t) $ \tmplRaw -> do
            src <- c_poseidon_get_state_from_context (PoseidonCtxtPtr tmplRaw)
            dst <- c_poseidon_get_state_from_context scratch
            copyBytes dst src (templateBufferBytes t)
            zipWithM_ (\i fr -> writeFr (dst `plusPtr` (i * sizeFr)) fr) [0 ..] inputState
            c_poseidon_apply_permutation scratch
            Just <$> mapM (\i -> readFr (dst `plusPtr` (i * sizeFr))) [0 .. w - 1]
  where
    inst = templateInstance t
    w = width inst
    acquire =
      c_poseidon_ctxt_new
        (fromIntegral (nbFullRounds inst))
        (fromIntegral (nbPartialRounds inst))
        (fromIntegral (batchSize inst))
        (fromIntegral w)
{-# NOINLINE poseidonPermute #-}
