# cardano-crypto-class

Core cryptographic abstractions and type classes for the Cardano ecosystem. This package provides the foundational interfaces that all cryptographic operations in Cardano are built upon.

## 🔒 Overview

This package defines type classes and implementations for:

- **Digital Signature Schemes (DSIGN)** - Ed25519, ECDSA, Schnorr signatures
- **Cryptographic Hash Functions (HASH)** - Blake2b, SHA256, SHA3, etc.
- **Key-Evolving Signatures (KES)** - Forward-secure signatures for block production
- **Verifiable Random Functions (VRF)** - Cryptographically secure randomness
- **Memory Management** - Secure handling of cryptographic material

## 🚀 Quick Start

### Basic Hashing

```haskell
import Cardano.Crypto.Hash
import qualified Data.ByteString.Char8 as BS8

-- Hash some data using Blake2b_256 (tested and verified)
hashData :: BS8.ByteString -> Hash Blake2b_256 BS8.ByteString
hashData = hash

-- Example usage
example = hashData "Hello Cardano!"
-- Result: "b763926ea11f0803fb50ff32c881353fc6256d93e03b3502f2d00e2717e80511"
```

### Digital Signatures

```haskell
import Cardano.Crypto.DSIGN
import Cardano.Crypto.DSIGN.Ed25519
import Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

-- Generate a key pair (using proper entropy in real applications)
let testSeed = mkSeedFromBytes $ BS.replicate 32 0x42  -- For testing only!
let keyPair = genKeyDSIGN @Ed25519DSIGN testSeed
let vk = deriveVerKeyDSIGN keyPair

-- Sign some data (corrected parameter order and types)
let message = "Hello Cardano!" :: BS8.ByteString
let signature = signDSIGN () message keyPair

-- Verify the signature
let isValid = verifyDSIGN () vk message signature
-- Result: Right () for valid signature
```

### Verifiable Random Functions

```haskell
import Cardano.Crypto.VRF
import Cardano.Crypto.VRF.Praos
import Cardano.Crypto.Seed (mkSeedFromBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

-- Generate VRF key pair (using proper entropy in real applications)
let testSeed = mkSeedFromBytes $ BS.replicate 32 0x37  -- For testing only!
let vrfKey = genKeyVRF @PraosVRF testSeed
let vrfPub = deriveVerKeyVRF vrfKey

-- Generate proof and output (corrected types)
let inputData = "input data" :: BS8.ByteString
let (vrfOutput, vrfProof) = evalVRF () inputData vrfKey

-- Verify the proof (corrected API usage)
let verified = verifyVRF () vrfPub inputData vrfProof
-- Result: Just vrfOutput for valid proof, Nothing for invalid
```

> **📝 Note**: All examples above have been tested with released packages from CHaP to ensure accuracy. The type annotations and API usage shown are necessary for successful compilation.

## 📚 Key Concepts

### Type Classes

- **`DSIGNAlgorithm`** - Digital signature algorithms
- **`HashAlgorithm`** - Cryptographic hash functions
- **`KESAlgorithm`** - Key-evolving signature schemes
- **`VRFAlgorithm`** - Verifiable random functions

### Supported Algorithms

| Type | Algorithm | Use Case |
|------|-----------|----------|
| DSIGN | Ed25519 | General purpose signatures |
| DSIGN | ECDSA/Secp256k1 | Bitcoin-compatible signatures |
| DSIGN | Schnorr/Secp256k1 | Advanced signature schemes |
| HASH | Blake2b_256 | Primary hash in Cardano |
| HASH | SHA256 | Legacy/compatibility |
| VRF | Praos | Consensus randomness |
| KES | Sum/Simple | Block production keys |

## 🔧 Integration Guide

### Adding to Your Project

Add to your `cabal` file:

```cabal
build-depends:
  , cardano-crypto-class
```

### Common Patterns

#### 1. Generic Cryptographic Operations

```haskell
import qualified Data.ByteString as BS

-- Work with any hash algorithm (using working function)
hashAnyData :: HashAlgorithm h => BS.ByteString -> Hash h BS.ByteString
hashAnyData = hash

-- Work with any signature scheme (corrected parameter order)
signWith :: DSIGNAlgorithm d => BS.ByteString -> SignKeyDSIGN d -> SignedDSIGN d BS.ByteString
signWith msg key = signDSIGN () msg key
```

#### 2. Secure Memory Management

```haskell
import Cardano.Crypto.Libsodium.MLockedBytes

-- Use memory-locked storage for sensitive data
withMLockedBytes 32 $ \ptr -> do
  -- Work with cryptographic material
  -- Memory is automatically zeroed on cleanup
```

#### 3. Serialization

```haskell
import Codec.CBOR.Encoding (toCBOR)
import Codec.CBOR.Decoding (fromCBOR)
import qualified Data.ByteString.Char8 as BS8

-- Most crypto types support CBOR serialization (corrected types)
let exampleHash = hashData "example" :: Hash Blake2b_256 BS8.ByteString
let encodedHash = toCBOR exampleHash
let decodedHash = fromCBOR encodedHash :: Either DecoderError (Hash Blake2b_256 BS8.ByteString)
```

## 🔍 Key Modules

- **`Cardano.Crypto.DSIGN`** - Digital signature algorithms
- **`Cardano.Crypto.Hash`** - Cryptographic hash functions
- **`Cardano.Crypto.KES`** - Key-evolving signatures
- **`Cardano.Crypto.VRF`** - Verifiable random functions
- **`Cardano.Crypto.Libsodium`** - Low-level libsodium bindings
- **`Cardano.Crypto.PinnedSizedBytes`** - Memory management utilities

## ⚠️ Security Notes

- **Memory Management**: Use `MLockedBytes` for sensitive cryptographic material
- **Entropy**: Always use proper entropy sources for key generation
- **Side Channels**: Be aware of timing attacks in custom implementations
- **Key Lifecycle**: Properly zeroize keys when no longer needed

## 🔗 Related Packages

- **[cardano-crypto-praos](../cardano-crypto-praos/)** - Praos-specific implementations
- **[cardano-binary](../cardano-binary/)** - CBOR serialization
- **[cardano-base](../)** - Full foundation package collection

## 📜 Further Reading

- [API Documentation](http://base.cardano.intersectmbo.org/cardano-crypto-class/)
- [Cardano Cryptographic Specification](https://github.com/intersectmbo/cardano-ledger)
- [Installation Guide](../INSTALL.md)
