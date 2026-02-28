# cardano-crypto-praos

Concrete VRF implementation for Cardano's Ouroboros Praos consensus protocol.

[![Hackage](https://img.shields.io/hackage/v/cardano-crypto-praos)](https://hackage.haskell.org/package/cardano-crypto-praos)

## Overview

`cardano-crypto-praos` provides the production VRF (Verifiable Random
Function) used in the Ouroboros Praos consensus protocol that powers Cardano
mainnet. It binds the abstract `VRFAlgorithm` interface from
`cardano-crypto-class` to a concrete implementation backed by
[libsodium](https://libsodium.org/).

This package also provides:

- `PraosBatchCompat` — a variant optimised for batched proof verification
  (used during chain sync)
- `Cardano.Crypto.RandomBytes` — cryptographically secure random byte
  generation via libsodium

> **Prerequisite:** Building this package requires the Cardano-patched
> `libsodium` with VRF support. See [`INSTALL.md`](../INSTALL.md).

## Developer Onboarding

If you are working on the consensus layer or slot leadership, you will interact with this package.
1. **Understand `VRFAlgorithm`:** Read the [Verifiable Random Functions (VRF) section in `cardano-crypto-class`](../cardano-crypto-class/README.md#verifiable-random-functions-vrf) to understand the base interface.
2. **Choose the Right Variant:** Use `PraosVRF` for normal leadership checks and `PraosBatchCompatVRF` during massive block validation sweeps (e.g., node synchronization).
3. **Use Safe Randomness:** Always use `Cardano.Crypto.RandomBytes` for generating seeds instead of `System.Random`.

## Integration with `cardano-slotting`

VRF inputs frequently involve time constraints. In Ouroboros Praos, the VRF input is heavily tied to the `SlotNo` provided by the `cardano-slotting` package. Ensure that the bytes formatted as VRF input exactly follow the protocol specification regarding slot concatenation.

## Installation

```cabal
build-depends: cardano-crypto-praos >= 2.2
```

## VRF Algorithms

### `PraosVRF`

The standard Praos VRF. Used by all nodes on Cardano mainnet and testnet to
determine slot leadership.

```haskell
import Cardano.Crypto.VRF.Praos

-- Key types (all phantom-typed wrappers over libsodium types):
-- SignKeyVRF PraosVRF   -- private key (32 bytes)
-- VerKeyVRF  PraosVRF   -- public key  (32 bytes)
-- OutputVRF  PraosVRF   -- VRF output  (64 bytes)
-- CertVRF    PraosVRF   -- VRF proof   (80 bytes)
```

### `PraosBatchCompatVRF`

A VRF variant that supports batch verification. When a node syncs the chain
from scratch, it must verify VRF proofs for thousands of blocks. Batch
verification amortises the per-proof overhead significantly.

```haskell
import Cardano.Crypto.VRF.PraosBatchCompat
-- Same interface as PraosVRF, but CertVRF is structured for batching.
```

## Usage Examples

### Key generation

```haskell
import Cardano.Crypto.VRF.Praos
import Cardano.Crypto.Seed     (mkSeedFromBytes)
import Cardano.Crypto.RandomBytes (randombytes)

generateVRFKeyPair
  :: IO (SignKeyVRF PraosVRF, VerKeyVRF PraosVRF)
generateVRFKeyPair = do
  seedBytes <- randombytes 32
  let seed = mkSeedFromBytes seedBytes
      sk   = genKeyVRF @PraosVRF seed
      vk   = deriveVerKeyVRF sk
  pure (sk, vk)
```

### Evaluating the VRF (slot leadership)

In Ouroboros Praos, the VRF is evaluated at every slot to determine whether
the pool is the slot leader. The input is the concatenation of the epoch
randomness nonce and the slot number.

```haskell
import Cardano.Crypto.VRF.Praos
import Cardano.Binary            (serialize')
import Cardano.Slotting.Slot     (SlotNo (..))

-- Build the VRF input for a given nonce and slot
mkVRFInput :: ByteString -> SlotNo -> ByteString
mkVRFInput nonce (SlotNo slot) =
  nonce <> serialize' slot

-- Evaluate: returns (output, proof)
evaluateVRF
  :: SignKeyVRF PraosVRF
  -> ByteString    -- epoch nonce
  -> SlotNo
  -> (OutputVRF PraosVRF, CertVRF PraosVRF)
evaluateVRF sk nonce slot =
  evalVRF sk (mkVRFInput nonce slot)

-- Slot leadership check
-- stakeFraction is the pool's active stake / total active stake
isSlotLeader
  :: OutputVRF PraosVRF
  -> Double       -- stake fraction in [0, 1]
  -> Bool
isSlotLeader output stakeFraction =
  let -- Leadership threshold (simplified; real formula uses ln)
      threshold  = maxBound @Word64 - floor (fromIntegral (maxBound @Word64) * (1 - stakeFraction))
      outputWord = vrfOutputAsWord64 output
  in  outputWord < threshold
```

### Verifying a VRF proof

Other nodes verify the block producer's VRF claim:

```haskell
import Cardano.Crypto.VRF.Praos

verifyBlockVRF
  :: VerKeyVRF PraosVRF
  -> ByteString                        -- VRF input
  -> (OutputVRF PraosVRF, CertVRF PraosVRF)
  -> Either String ()
verifyBlockVRF vk input outputAndProof =
  verifyVRF vk input outputAndProof
  -- Right () => proof is valid; output matches the claimed output
  -- Left err => proof is invalid; reject the block
```

### Batch verification

During initial chain sync, use `PraosBatchCompatVRF` to verify many proofs
at once:

```haskell
import Cardano.Crypto.VRF.PraosBatchCompat

-- Collect proofs from multiple blocks
type VRFEvidence = (VerKeyVRF PraosBatchCompatVRF, ByteString, OutputVRF PraosBatchCompatVRF, CertVRF PraosBatchCompatVRF)

-- Verify a batch
-- More efficient than calling verifyVRF individually for each block
verifyBatch :: [VRFEvidence] -> Either String ()
verifyBatch evidence =
  -- Real batch verification is handled internally by libsodium;
  -- the API is the same as single-proof verification
  mapM_ (\(vk, inp, out, cert) -> verifyVRF vk inp (out, cert)) evidence
```

## Random Bytes

`Cardano.Crypto.RandomBytes` provides cryptographically secure random
bytes using libsodium's `randombytes_buf`. Use this — not `System.Random` —
whenever randomness is needed in cryptographic contexts.

```haskell
import Cardano.Crypto.RandomBytes

-- Generate n cryptographically secure random bytes
generateSeed :: IO ByteString
generateSeed = randombytes 32  -- 256 bits of entropy

-- Example: generate a new VRF key from fresh randomness
freshVRFKey :: IO (SignKeyVRF PraosVRF)
freshVRFKey = do
  bytes <- randombytes 32
  let seed = mkSeedFromBytes bytes
  pure $ genKeyVRF @PraosVRF seed
```

## Integration with `cardano-crypto-class`

`PraosVRF` and `PraosBatchCompatVRF` both satisfy the `VRFAlgorithm`
typeclass from `cardano-crypto-class`. Code written against the abstract
interface works with both:

```haskell
import Cardano.Crypto.VRF.Class  (VRFAlgorithm (..))

-- This function works for any VRF algorithm:
evalAndVerify
  :: VRFAlgorithm v
  => SignKeyVRF v
  -> VerKeyVRF v
  -> ByteString
  -> Bool
evalAndVerify sk vk input =
  let (out, cert) = evalVRF sk input
  in  case verifyVRF vk input (out, cert) of
        Right () -> True
        Left  _  -> False
```

## Running Tests

```bash
cabal test cardano-crypto-praos:tests
```
