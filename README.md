# cardano-base

A collection of foundational packages used by Cardano that provide core abstractions for:

* **cryptography** - Digital signatures, hashing, VRF, KES
* **serialization** - CBOR encoding/decoding for blockchain data
* **slotting** - Time and slot calculations for the blockchain

## 🚀 Getting Started

### What is cardano-base?

`cardano-base` provides the foundational libraries that all other Cardano components depend on. If you're building applications that interact with Cardano, you'll likely need these packages for:

- **Cryptographic operations**: Creating and verifying signatures, hashing data
- **Data serialization**: Encoding/decoding transaction and block data  
- **Time calculations**: Working with slots, epochs, and blockchain time
- **Memory management**: Secure handling of cryptographic material

### Architecture Overview

```
cardano-node, cardano-cli, cardano-db-sync, etc.
                    ↓ depend on
            cardano-base packages
                    ↓ depend on  
   System crypto libraries (libsodium-vrf, libsecp256k1, libblst)
```

### Key Packages

| Package | Purpose | Use When |
|---------|---------|----------|
| **[cardano-crypto-class](cardano-crypto-class/)** | Cryptographic type classes and abstractions | Need signing, hashing, VRF operations | ✅ Complete with examples |
| **[cardano-binary](cardano-binary/)** | CBOR serialization utilities | Encoding/decoding blockchain data | ✅ Complete with examples |
| **[cardano-slotting](cardano-slotting/)** | Time and slot calculations | Working with blockchain time | ✅ Complete with examples |
| **[cardano-crypto-praos](cardano-crypto-praos/)** | Praos-specific cryptography (VRF, KES) | Building consensus or validation logic | ⚠️ Basic |
| **[cardano-strict-containers](cardano-strict-containers/)** | Memory-efficient data structures | Performance-critical applications | ⚠️ Basic |

### Quick Start

#### For New Developers
1. **Installation**: See [INSTALL.md](INSTALL.md) for detailed setup instructions
2. **Start with Examples**: 
   - Try [`cardano-crypto-class` examples](cardano-crypto-class/README.md#basic-usage) for hashing and signatures
   - Practice [`cardano-binary` examples](cardano-binary/README.md#key-types-and-usage) for CBOR serialization
   - Explore [`cardano-slotting` examples](cardano-slotting/README.md#key-types-and-usage) for time calculations
3. **API Documentation**: Browse the [Haddock documentation](http://base.cardano.intersectmbo.org/) 

#### For Experienced Developers
- **Quick Reference**: See package-specific READMEs for API patterns and integration examples
- **Integration**: Use `cabal.project` files that point to [CHaP](https://github.com/intersectmbo/cardano-haskell-packages) for dependencies


### Common Use Cases

- **Transaction Validation**: Use `cardano-crypto-class` for signature verification
- **Block Parsing**: Use `cardano-binary` for CBOR decoding 
- **Time Calculations**: Use `cardano-slotting` for slot/epoch conversions
- **Key Generation**: Use `cardano-crypto-praos` for cryptographic key operations

### Package Dependencies

Understanding how packages relate to each other:

```
cardano-crypto-class ← Core crypto abstractions (hashing, signing, VRF)
        ↑
        └── cardano-crypto-praos ← Praos-specific implementations
        
cardano-binary ← CBOR serialization (independent)
        
cardano-slotting ← Time/slot calculations
        ├─ depends on: cardano-binary (for serialization)
        └─ used by: consensus layer packages
```

**Integration Pattern**: Most applications will use `cardano-crypto-class` + `cardano-binary` together, with `cardano-slotting` when working with blockchain time.



Haddock for all packages from master branch can be found here:
[http://base.cardano.intersectmbo.org](http://base.cardano.intersectmbo.org/)

All releases for packages found in this repository are recorded in [Cardano Haskell
package repository](https://github.com/intersectmbo/cardano-haskell-packages)

## Building

### Quick Start with `nix` (Recommended)

With nix it is as easy as:

```
$ nix develop
...
$ cabal build all
```

### Without `nix`

**IMPORTANT**: This project requires custom versions of cryptographic libraries with VRF support.

See **[INSTALL.md](INSTALL.md)** for detailed installation instructions including:
- Pre-built binaries for macOS, Linux, and Windows
- Building from source
- Environment setup
- Troubleshooting

Quick overview of required dependencies:
* **libsodium-vrf** - Custom fork with VRF batch verification ([source](https://github.com/input-output-hk/libsodium/tree/iquerejeta/vrf_batchverify))
* **libsecp256k1** - With Schnorr signature support
* **libblst** - BLS12-381 implementation

Pre-built binaries available at: https://github.com/input-output-hk/iohk-nix/releases/latest


## GHC

Default version of GHC used in `nix` is `9.6.7`. The project is tested with GHC versions `9.6.7`, `9.8.4`, `9.10.2`, and `9.12.2`.


### Testing

This is a command to run test suites for all packages:

```
$ cabal build all
```

The test suites use [Tasty](https://github.com/feuerbach/tasty),
which allows for running specific tests.
This is done by passing the `-p` flag to the test program, followed by an `awk` pattern.
You can alternatively use the `TASTY_PATTERN` environment variable with a pattern.
For example, the `cardano-crypto-tests` can be run with:

```shell
$ cabal test cardano-crypto-tests --test-options '-p blake2b_256'
```

or

```shell
$ TASTY_PATTERN="blake2b_256" cabal test cardano-crypto-tests
```

## 🤝 Contributing

We welcome contributions to cardano-base! Whether you're:

- **Fixing bugs** in cryptographic implementations
- **Adding new features** to serialization libraries  
- **Improving documentation** and examples
- **Optimizing performance** for critical paths
- **Writing tests** for edge cases

### Getting Started

1. **Fork this repository** and create a feature branch
2. **Follow the build instructions** in [INSTALL.md](INSTALL.md)
3. **Run the test suite** with `cabal test all` to ensure nothing breaks
4. **Add tests** for any new functionality
5. **Submit a pull request** with a clear description of your changes

### Development Guidelines

- Maintain backward compatibility for public APIs
- Include comprehensive tests for cryptographic functions
- Follow existing code style and documentation patterns
- Update package READMEs when adding new features

## 📚 Resources

- **[API Documentation](http://base.cardano.intersectmbo.org/)** - Complete Haddock documentation
- **[Package Repository](https://github.com/intersectmbo/cardano-haskell-packages)** - Release information and changelogs
- **[Installation Guide](INSTALL.md)** - Detailed setup instructions
- **[Cardano Developer Portal](https://developers.cardano.org/)** - Broader ecosystem documentation

## 📄 License

This project is licensed under the Apache 2.0 License - see individual package directories for specific license information.

---

**Built with ❤️ by the Cardano community**  
*Providing the cryptographic foundation for the next generation of blockchain applications*

