# cardano-crypto-class

Abstract cryptographic interfaces for the Cardano ecosystem: hashing,
digital signatures (DSIGN), key-evolving signatures (KES), and verifiable
random functions (VRF).

[![Hackage](https://img.shields.io/hackage/v/cardano-crypto-class)](https://hackage.haskell.org/package/cardano-crypto-class)

## Overview

`cardano-crypto-class` defines **what** Cardano cryptography looks like, not
**how** it is implemented. Every cryptographic operation — hashing a block
header, signing a transaction, evolving a KES key, evaluating a VRF — is
expressed as a typeclass. Concrete implementations (libsodium, BLST, pure
Haskell mocks) satisfy those typeclasses.

This separation means:

- Application code is algorithm-agnostic and future-proof.
- Tests can use fast, insecure `Mock` implementations without touching real
  cryptographic primitives.
- Swapping algorithms (e.g. upgrading Ed25519 to a post-quantum scheme)
  requires changing only the implementation package, not any call sites.

## Developer Onboarding

If you are new to Cardano's cryptographic foundations:
1. **Understand the Interfaces:** Start with `HashAlgorithm` and `DSIGNAlgorithm`. They are the most commonly used out-of-the-box.
2. **Phantom Types:** Pay close attention to how `Hash h a` wraps the algorithm (`h`) and the data type (`a`). This pattern prevents confusing different hashed objects (e.g., `TxBody` vs `BlockHeader`).
3. **Mock Implementations:** When writing your own unit tests, default to the `Mock` variants (e.g., `MockDSIGN`) so you do not suffer the performance hit of real crypto in test suites.

## Integration Guides

This package heavily integrates with other items in `cardano-base`:
* **`cardano-binary`:** `HashAlgorithm` offers `hashWithSerialiser` to simplify computing hashes over any type that implements `ToCBOR`.
* **Concrete Implementations:** If you need the actual VRF used in Praos, look to `cardano-crypto-praos`.

## Installation

```cabal
build-depends: cardano-crypto-class >= 2.3
```

## Hashing

### The `HashAlgorithm` typeclass

```haskell
class HashAlgorithm h where
  hashAlgorithmName :: proxy h -> String  -- e.g. "blake2b_256"
  digestSize        :: proxy h -> Word    -- output size in bytes
  digest            :: proxy h -> ByteString -> ByteString
```

### The `Hash h a` type

`Hash h a` is a phantom-typed hash value. The `h` parameter is the algorithm;
`a` is the type of the value that was hashed. Phantom types prevent mixing up
hashes of different things at compile time.

```haskell
-- These are distinct types — you cannot confuse them:
type BlockHash = Hash Blake2b_256 BlockHeader
type TxHash    = Hash Blake2b_256 TxBody
```

### Available algorithms

| Module | Algorithm | Output size | Use in Cardano |
|--------|-----------|-------------|----------------|
| `Cardano.Crypto.Hash.Blake2b` | Blake2b-256 | 32 bytes | Dominant — block/tx IDs |
| `Cardano.Crypto.Hash.Blake2b` | Blake2b-224 | 28 bytes | Payment credential hashes |
| `Cardano.Crypto.Hash.SHA256` | SHA-256 | 32 bytes | Byron era |
| `Cardano.Crypto.Hash.SHA512` | SHA-512 | 64 bytes | Key derivation |
| `Cardano.Crypto.Hash.SHA3_256` | SHA3-256 | 32 bytes | Plutus builtins |
| `Cardano.Crypto.Hash.Keccak256` | Keccak-256 | 32 bytes | Ethereum interop |
| `Cardano.Crypto.Hash.RIPEMD160` | RIPEMD-160 | 20 bytes | Bitcoin address compat |
| `Cardano.Crypto.Hash.Short` | Blake2b-256 truncated | Configurable | Compact maps |

### Hashing examples

```haskell
import Cardano.Crypto.Hash
import Data.ByteString (ByteString)

-- Hash raw bytes
hashBytes :: Hash Blake2b_256 ByteString
hashBytes = hashWith id "hello world"

-- Hash any ToCBOR value
hashValue :: ToCBOR a => a -> Hash Blake2b_256 a
hashValue = hashWithSerialiser toCBOR

-- Convert to/from raw bytes
toRaw :: Hash Blake2b_256 a -> ByteString
toRaw = hashToBytes           -- always 32 bytes

fromRaw :: ByteString -> Maybe (Hash Blake2b_256 a)
fromRaw = hashFromBytes       -- Nothing if wrong length

-- Display as hex
showHash :: Hash Blake2b_256 a -> String
showHash = show               -- "\"a948904f2f0f...\"" (quoted hex)
```

## Digital Signatures (DSIGN)

### The `DSIGNAlgorithm` typeclass

```haskell
class ( ... ) => DSIGNAlgorithm v where
  type VerKeyDSIGN  v   -- public verification key
  type SignKeyDSIGN  v   -- private signing key
  type SigDSIGN     v   -- signature

  genKeyDSIGN   :: Seed -> SignKeyDSIGN v
  deriveVerKeyDSIGN :: SignKeyDSIGN v -> VerKeyDSIGN v
  signDSIGN     :: SignKeyDSIGN v -> ByteString -> SigDSIGN v
  verifyDSIGN   :: VerKeyDSIGN v  -> ByteString -> SigDSIGN v
                -> Either String ()
```

### Available algorithms

| Module suffix | Algorithm | Cardano use |
|--------------|-----------|-------------|
| `Ed25519` | Ed25519 | Default in Shelley+ |
| `Ed448` | Ed448 | Higher security margin |
| `EcdsaSecp256k1` | ECDSA/secp256k1 | Plutus V2 builtins |
| `SchnorrSecp256k1` | Schnorr/secp256k1 | Plutus V2 builtins |
| `BLS12381` | BLS12-381 | Threshold sigs, Peras |
| `Mock` | Insecure mock | Tests only |
| `NeverUsed` | Panics at runtime | Type-level only |

### Signing example

```haskell
import Cardano.Crypto.DSIGN
import Cardano.Crypto.Seed   (mkSeedFromBytes)

-- Generate a key pair
generateKeyPair :: IO (SignKeyDSIGN Ed25519DSIGN, VerKeyDSIGN Ed25519DSIGN)
generateKeyPair = do
  seed <- mkSeedFromBytes <$> getRandomBytes 32
  let sk = genKeyDSIGN @Ed25519DSIGN seed
      vk = deriveVerKeyDSIGN sk
  pure (sk, vk)

-- Sign a message
signMessage
  :: SignKeyDSIGN Ed25519DSIGN
  -> ByteString
  -> SigDSIGN Ed25519DSIGN
signMessage sk msg = signDSIGN sk msg

-- Verify a signature
verifyMessage
  :: VerKeyDSIGN Ed25519DSIGN
  -> ByteString
  -> SigDSIGN Ed25519DSIGN
  -> Bool
verifyMessage vk msg sig =
  case verifyDSIGN vk msg sig of
    Right () -> True
    Left _   -> False

-- Full example
example :: IO ()
example = do
  (sk, vk) <- generateKeyPair
  let msg = "sign this transaction"
      sig = signMessage sk msg
  putStrLn $ if verifyMessage vk msg sig
    then "Signature valid"
    else "Signature invalid"
```

## Key-Evolving Signatures (KES)

KES is unique to Cardano. A KES key is valid for a fixed number of time
periods. After each period it **evolves** — the old key is securely destroyed
and cannot be recovered. This gives **forward security**: a compromised current
key cannot be used to forge signatures for past periods.

Block-producing nodes must rotate their KES keys before they expire
(approximately every 90 days / 129 epochs on mainnet).

### The `KESAlgorithm` typeclass

```haskell
class KESAlgorithm v where
  type VerKeyKES  v
  type SignKeyKES v
  type SigKES     v

  -- Total number of periods this key is valid for.
  totalPeriodsKES :: proxy v -> Word

  -- Evolve the key to the next period.
  -- Returns Nothing when the key has reached its final period.
  updateKES :: SignKeyKES v -> Word -> Maybe (SignKeyKES v)

  signKES
    :: SignKeyKES v
    -> Word       -- current period
    -> ByteString
    -> SigKES v

  verifyKES
    :: VerKeyKES v
    -> Word       -- period the signature was made in
    -> ByteString
    -> SigKES v
    -> Either String ()
```

### KES usage example

```haskell
import Cardano.Crypto.KES

-- Evolve a KES key through several periods and sign in each
evolveAndSign
  :: SignKeyKES (Sum6KES Ed25519DSIGN Blake2b_256)
  -> ByteString
  -> IO ()
evolveAndSign initialKey msg = go initialKey 0
  where
    go key period = do
      let sig = signKES key period msg
      putStrLn $ "Period " <> show period <> ": signed"
      case updateKES key (period + 1) of
        Nothing     -> putStrLn "Key expired after final period"
        Just newKey -> go newKey (period + 1)
```

> **Security note:** After calling `updateKES`, you must ensure the old
> `SignKeyKES` value is securely erased from memory. Use `MLockedBytes`
> (from `Cardano.Crypto.Libsodium`) for key storage in production.

### KES implementations

| Type | Periods | Description |
|------|---------|-------------|
| `SingleKES d` | 1 | Base case, one period |
| `SumKES n d h` | 2^n | Sum construction (standard) |
| `CompactSumKES n d h` | 2^n | Memory-optimised sum |
| `SimpleKES d` | configurable | Simple (for testing) |
| `MockKES` | unlimited | Insecure mock for tests |

## Verifiable Random Functions (VRF)

VRF is the cryptographic engine behind Cardano's Ouroboros Praos slot
leadership election. A VRF produces a pseudo-random output from a private
key and a public input, together with a **proof** that the output is correct.

Stake pool operators evaluate the VRF at each slot. If their output (weighted
by their stake fraction) falls below the leadership threshold, they produce a
block for that slot.

### The `VRFAlgorithm` typeclass

```haskell
class VRFAlgorithm v where
  type VerKeyVRF  v
  type SignKeyVRF v
  type OutputVRF  v
  type CertVRF    v

  -- Evaluate the VRF, returning output + proof.
  evalVRF
    :: SignKeyVRF v
    -> ByteString      -- input (e.g. epoch nonce + slot number)
    -> (OutputVRF v, CertVRF v)

  -- Verify a VRF output/proof pair.
  verifyVRF
    :: VerKeyVRF v
    -> ByteString
    -> (OutputVRF v, CertVRF v)
    -> Either String ()

  -- Extract the raw output bytes.
  outputBytes :: OutputVRF v -> ByteString
```

### VRF example

```haskell
import Cardano.Crypto.VRF

-- Slot leadership check (simplified)
isSlotLeader
  :: SignKeyVRF SimpleVRF
  -> VerKeyVRF  SimpleVRF
  -> ByteString                  -- VRF input (nonce + slot encoding)
  -> Double                      -- pool's stake fraction (0..1)
  -> Bool
isSlotLeader sk vk input stakeFraction =
  let (output, proof) = evalVRF sk input
      -- Leadership threshold: stakeFraction determines window size
      threshold = floor (2^(64::Int) * stakeFraction) :: Word64
      outputVal = read (show (outputBytes output)) :: Word64
  in  case verifyVRF vk input (output, proof) of
        Left  _  -> False     -- proof invalid — cannot be leader
        Right () -> outputVal < threshold
```

## Secure Memory (`MLockedBytes`)

Private keys should never be swapped to disk. `Cardano.Crypto.Libsodium`
provides `MLockedBytes` — a `ByteString`-like type backed by memory-locked
(`mlock`'d) allocation:

```haskell
import Cardano.Crypto.Libsodium.MLockedBytes

-- Allocate memory-locked bytes (will not be swapped)
withMLockedBytes
  :: Int                        -- size in bytes
  -> (MLockedBytes n -> IO a)
  -> IO a

-- Explicitly overwrite and free
-- (called automatically when MLockedBytes goes out of scope)
mlockedBytesFinalize :: MLockedBytes n -> IO ()
```

## Using Mock Implementations in Tests

Every algorithm has a `Mock` variant that is fast and deterministic but
**completely insecure**. Never use mocks outside of tests.

```haskell
import Cardano.Crypto.DSIGN.Mock
import Cardano.Crypto.KES.Mock
import Cardano.Crypto.VRF.Mock

-- In tests, use type aliases to swap real for mock:
type TestDSIGN = MockDSIGN
type TestKES   = MockKES
type TestVRF   = MockVRF

-- All the same API, but instantaneous key generation
mockSk :: SignKeyDSIGN MockDSIGN
mockSk = SignKeyMockDSIGN 42   -- deterministic from a Word64 seed
```

## Running Tests and Benchmarks

```bash
# Unit tests
cabal test cardano-crypto-class:tests

# Benchmarks
cabal bench cardano-crypto-class:benchmarks
```
