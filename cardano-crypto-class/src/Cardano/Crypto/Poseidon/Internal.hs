{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}

-- | Binding internals for the Poseidon permutation: the raw FFI to the
-- vendored C code (@cbits/poseidon.h@) and its binding helpers
-- (@cbits/poseidon_util.h@), and the context-template machinery the public
-- "Cardano.Crypto.Poseidon" API is built on. Import this module directly
-- only for the unsafe internals (e.g. in tests).
--
-- The foreign imports are a direct, unchecked view of the C ABI; every
-- precondition in @cbits/poseidon_util.h@ is this module's obligation. In
-- particular: parameters go through @poseidon_parameters_valid@ before any
-- other call, context fields are only reached through the @poseidon_get_*@
-- accessors, and @blst_fr@ elements are sized with 'sizeFrElement', never a
-- literal.
--
-- == Batched partial rounds
--
-- The C core supports batching partial rounds (a linear-algebra
-- optimization), but batched rounds consume /composed/ constants derived
-- from the MDS and ARK, not the raw ARK list. This binding deliberately
-- runs without the optimization: contexts are configured with
-- @batch_size = R_P + 1@ ('Cardano.Crypto.Poseidon.Constants.batchSize'),
-- which makes @R_P \`div\` batch_size == 0@ so no batched round ever
-- executes and the raw constants are consumed directly. Composing constants
-- for real batching is a future, observably identical optimization (not a
-- new registry variant).
--
-- == Zero padding
--
-- The permutation's final constant addition consumes @width@ round
-- constants beyond the ARK list; they must be zero. Zero-initialized buffer
-- allocation provides them without a separate write, so the constant-loading
-- code writes exactly the ARK list and must leave the tail untouched (see
-- @poseidon_ctxt_init@ in @cbits/poseidon_util.h@).
--
-- == Purity and the template scheme
--
-- A 'PoseidonTemplate' is an immutable, fully initialized context image
-- (struct + element buffer) built once per instance. 'poseidonPermute'
-- never mutates a template: each call copies the image into fresh private
-- memory, writes the input state, and runs the permutation there — which is
-- what makes the public API pure and a shared template safe for concurrent
-- callers.
module Cardano.Crypto.Poseidon.Internal (
  -- * Unsafe types
  PoseidonCtxtPtr (..),
  FrPtr (..),

  -- * Sizes
  sizeFrElement,

  -- * Direct C bindings
  c_poseidon_ctxt_sizeof,
  c_poseidon_parameters_valid,
  c_poseidon_ctxt_init,
  c_poseidon_compute_number_of_constants,
  c_poseidon_apply_permutation,
  c_poseidon_get_state_from_context,
  c_poseidon_get_state_size_from_context,
  c_poseidon_get_mds_from_context,
  c_poseidon_get_round_constants_from_context,

  -- * Element buffers
  FrBuffer,
  frBufferElements,
  newFrBuffer,
  withFrBuffer,

  -- * Context templates
  PoseidonTemplate,
  templateInstance,
  templateImage,
  newPoseidonTemplate,
  poseidonPermute,
) where

#include "blst_util.h"

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (Fr (..), frFromScalar, scalarFromInteger)
import Cardano.Crypto.PinnedSizedBytes (psbUseAsCPtr)
import Cardano.Crypto.Poseidon.Constants (PoseidonInstance (..), batchSize)
import Control.Monad (zipWithM_)
import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes, withForeignPtr)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import System.IO.Unsafe (unsafePerformIO)

-- | Pointer to a C @poseidon_ctxt_t@. Opaque: its size comes from
-- 'c_poseidon_ctxt_sizeof' (never a hardcoded value — it is an ABI fact the
-- C side owns) and its fields are only reached through the
-- @c_poseidon_get_*@ accessors.
newtype PoseidonCtxtPtr = PoseidonCtxtPtr (Ptr Word8)

-- | Pointer to (an array of) @blst_fr@ field elements, each 'sizeFrElement'
-- bytes, in blst's internal (Montgomery) representation.
newtype FrPtr = FrPtr (Ptr Word8)

-- | Size in bytes of one @blst_fr@ element, from @cbits/blst_util.h@
-- (checked against the real ABI by a @static_assert@ in
-- @cbits/poseidon_util.c@).
sizeFrElement :: Int
sizeFrElement = CARDANO_BLST_FR_SIZE

-- | The number of bytes of a @poseidon_ctxt_t@, for the caller to allocate.
foreign import ccall "poseidon_ctxt_sizeof"
  c_poseidon_ctxt_sizeof :: CSize

-- | @c_poseidon_parameters_valid nb_full_rounds nb_partial_rounds
-- batch_size width@: 1 if the configuration is safe to run, 0 otherwise.
-- Must accept the parameters before 'c_poseidon_ctxt_init' is called or the
-- element buffer is sized. This is a safety predicate, not a strength
-- check; see @cbits/poseidon_util.h@.
foreign import ccall "poseidon_parameters_valid"
  c_poseidon_parameters_valid :: CInt -> CInt -> CInt -> CInt -> CInt

-- | @c_poseidon_ctxt_init ctxt buffer nb_full_rounds nb_partial_rounds
-- batch_size width@: record a caller-allocated, __zero-initialized__
-- element buffer and the parameters in a caller-allocated context struct.
-- Checks nothing; the caller's obligations (parameters validated, both
-- allocations large enough, buffer outliving the context) are listed at the
-- declaration in @cbits/poseidon_util.h@.
foreign import ccall "poseidon_ctxt_init"
  c_poseidon_ctxt_init ::
    PoseidonCtxtPtr -> FrPtr -> CInt -> CInt -> CInt -> CInt -> IO ()

-- | @c_poseidon_compute_number_of_constants batch_size nb_partial_rounds
-- nb_full_rounds width@: how many round constants the permutation consumes
-- (the trailing @width@ zeros included). Only overflow-safe for parameters
-- accepted by 'c_poseidon_parameters_valid'.
--
-- BEWARE: the argument order differs from the two helpers above
-- (@batch_size@ first, @nb_full_rounds@ third). All four parameters are
-- ints, so a swapped call compiles silently and yields a wrong-but-plausible
-- count.
foreign import ccall "poseidon_compute_number_of_constants"
  c_poseidon_compute_number_of_constants :: CInt -> CInt -> CInt -> CInt -> CInt

-- | Run the permutation in place on the context's state.
foreign import ccall "poseidon_apply_permutation"
  c_poseidon_apply_permutation :: PoseidonCtxtPtr -> IO ()

-- | The @width@-element state region of the context's buffer.
foreign import ccall "poseidon_get_state_from_context"
  c_poseidon_get_state_from_context :: PoseidonCtxtPtr -> IO FrPtr

-- | The configured width.
foreign import ccall "poseidon_get_state_size_from_context"
  c_poseidon_get_state_size_from_context :: PoseidonCtxtPtr -> IO CInt

-- | The @width * width@-element MDS region (row-major) of the context's
-- buffer.
foreign import ccall "poseidon_get_mds_from_context"
  c_poseidon_get_mds_from_context :: PoseidonCtxtPtr -> IO FrPtr

-- | The round-constants region of the context's buffer
-- ('c_poseidon_compute_number_of_constants' elements).
foreign import ccall "poseidon_get_round_constants_from_context"
  c_poseidon_get_round_constants_from_context :: PoseidonCtxtPtr -> IO FrPtr

-- | A buffer of @blst_fr@ elements, the memory a @poseidon_ctxt_t@ works
-- on. Pinned (C holds pointers into it during calls) and RTS-managed: it
-- is freed by the GC, and allocation failure is a heap-overflow exception,
-- never NULL. GHC aligns pinned allocations to 16 bytes, more than the
-- 8 bytes @blst_fr@'s limbs require.
--
-- For buffers that /outlive a call/ (the template image); transient
-- working memory should instead be @allocaBytes@ + continuation, following
-- the multi-scalar-multiplication buffers in
-- "Cardano.Crypto.EllipticCurve.BLS12_381.Internal" (@withPointArray@ and
-- the Pippenger scratch in @blsMSM@).
data FrBuffer = FrBuffer
  { frBufferElements :: !Int
  -- ^ Capacity in elements of 'sizeFrElement' bytes.
  , frBufferForeignPtr :: !(ForeignPtr Word8)
  }

-- | Allocate a zero-initialized buffer of @n@ elements.
newFrBuffer :: Int -> IO FrBuffer
newFrBuffer n = do
  fp <- mallocForeignPtrBytes bytes
  withForeignPtr fp $ \p -> fillBytes p 0 bytes
  pure FrBuffer {frBufferElements = n, frBufferForeignPtr = fp}
  where
    bytes = n * sizeFrElement

-- | Use the buffer's memory; the pointer must not escape the action.
withFrBuffer :: FrBuffer -> (FrPtr -> IO a) -> IO a
withFrBuffer buf go = withForeignPtr (frBufferForeignPtr buf) (go . FrPtr)

-- | An immutable, fully initialized context image for one instance; see
-- /Purity and the template scheme/ in the module header.
data PoseidonTemplate = PoseidonTemplate
  { templateInstance :: !PoseidonInstance
  -- ^ The instance this template was built from.
  , templateImage :: !FrBuffer
  -- ^ The context's element buffer, laid out as poseidon.c expects:
  -- @[ state (zero) | MDS, row-major | ARK | trailing zero constants ]@,
  -- each element in Montgomery form. Never written after construction:
  -- every permutation call copies it into private memory.
  }

-- | Build the context template for an instance: allocate the
-- zero-initialized buffer and load the MDS and ARK constants (canonical
-- 'Integer's to Montgomery-form @blst_fr@) through the C accessors.
--
-- Precondition: the instance is registry-vetted — its parameters pass
-- 'c_poseidon_parameters_valid' and its constants have the shape the
-- fields of 'PoseidonInstance' document. Nothing is re-checked here: the
-- test suite enforces both for every registered instance, and each write
-- below is bounded by its region's capacity, so a malformed instance can
-- only produce a wrong image, never an out-of-bounds write.
--
-- Pure: the construction touches only freshly allocated private memory and
-- is deterministic in the instance.
newPoseidonTemplate :: PoseidonInstance -> PoseidonTemplate
newPoseidonTemplate inst =
  unsafePerformIO $ do
    image <- newFrBuffer (w + w * w + nbConstants)
    withFrBuffer image $ \bufPtr ->
      allocaBytes (fromIntegral @CSize @Int c_poseidon_ctxt_sizeof) $ \ctxtRaw -> do
        let ctxt = PoseidonCtxtPtr ctxtRaw
        c_poseidon_ctxt_init
          ctxt
          bufPtr
          (fromIntegral @Int @CInt (nbFullRounds inst))
          (fromIntegral @Int @CInt (nbPartialRounds inst))
          (fromIntegral @Int @CInt (batchSize inst))
          (fromIntegral @Int @CInt w)
        FrPtr mdsPtr <- c_poseidon_get_mds_from_context ctxt
        FrPtr arkPtr <- c_poseidon_get_round_constants_from_context ctxt
        pokeElements mdsPtr (w * w) (concat (mds inst))
        pokeElements arkPtr nbConstants (ark inst)
    pure PoseidonTemplate {templateInstance = inst, templateImage = image}
  where
    w = width inst
    nbConstants =
      fromIntegral @CInt @Int $
        c_poseidon_compute_number_of_constants
          (fromIntegral @Int @CInt (batchSize inst))
          (fromIntegral @Int @CInt (nbPartialRounds inst))
          (fromIntegral @Int @CInt (nbFullRounds inst))
          (fromIntegral @Int @CInt w)
    -- Write each canonical constant as a Montgomery-form blst_fr at
    -- consecutive offsets from the region start the C accessor returned,
    -- never more than the region's capacity in elements.
    pokeElements dst cap = zipWithM_ pokeElement [0 .. cap - 1]
      where
        pokeElement i n = do
          Fr psb <- scalarFromInteger n >>= frFromScalar
          psbUseAsCPtr psb $ \src ->
            copyBytes (dst `plusPtr` (i * sizeFrElement)) src sizeFrElement
{-# NOINLINE newPoseidonTemplate #-}

-- | Apply the permutation to a full input state of exactly @width@
-- elements, in a private copy of the template (see /Purity and the template
-- scheme/). 'Nothing' on a wrong input length.
poseidonPermute :: PoseidonTemplate -> [Fr] -> Maybe [Fr]
poseidonPermute = error "TODO(poseidon): poseidonPermute not implemented"
