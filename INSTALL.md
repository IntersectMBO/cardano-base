# Installation Guide for cardano-base

This document provides detailed installation instructions for building `cardano-base` from source.

## Table of Contents

- [Quick Start Script](#quick-start-script)
- [Prerequisites](#prerequisites)
- [Option 1: Using Nix (Recommended)](#option-1-using-nix-recommended)
- [Option 2: Using Pre-built Binaries](#option-2-using-pre-built-binaries)
- [Option 3: Building from Source](#option-3-building-from-source)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Quick Start Script

We provide a helper script that automates installation and verification:

```bash
# Install pre-built cryptographic dependencies
./scripts/devenv.sh install

# Verify installation and check for conflicts
./scripts/devenv.sh doctor
```

The `doctor` command provides colored output:
- 🟢 Green checkmarks for passing checks
- 🟡 Yellow warnings for deviations or potential conflicts
- 🔴 Red errors for missing or incorrect installations

For detailed manual installation instructions, continue reading below.

## Prerequisites

### Required Tools

- **GHC**: 9.6.7, 9.8.4, 9.10.2, or 9.12.2
- **Cabal**: 3.14.1.0 or later
- **pkg-config**: For locating system libraries
- **Git**: For cloning the repository

### Required Cryptographic Libraries

**IMPORTANT**: This project requires **custom versions** of cryptographic libraries, not standard versions from system package managers:

1. **libsodium-vrf** - A custom fork with VRF (Verifiable Random Function) batch verification support
2. **libsecp256k1** - With Schnorr signature support
3. **libblst** - BLS12-381 curve implementation

**WARNING**: Do NOT use standard `libsodium` from Homebrew, apt, or other package managers. The build will fail because the VRF functionality is not present in standard libsodium.

## Option 1: Using Nix (Recommended)

Nix provides all dependencies automatically, including the correct versions of cryptographic libraries.

### Installation Steps

```bash
# 1. Install Nix (if not already installed)
curl -L https://nixos.org/nix/install | sh

# 2. Clone the repository
git clone https://github.com/intersectmbo/cardano-base.git
cd cardano-base

# 3. Enter the Nix development shell
nix develop

# 4. Update Cabal package index
cabal update

# 5. Build the project
cabal build all

# 6. Run tests
cabal test all
```

### Alternative Nix Shells

```bash
nix develop .#ghc912          # Use GHC 9.12
nix develop .#profiling       # Shell with profiling enabled
nix develop .#pre-commit      # Shell with pre-commit hooks
```

## Option 2: Using Pre-built Binaries

We provide pre-built binaries of the required cryptographic libraries for common platforms.

### macOS

#### For Apple Silicon (M1/M2/M3/M4)

```bash
# 1. Download the pre-built packages
cd /tmp
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/arm64-macos.libsodium-vrf.pkg
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/arm64-macos.libsecp256k1.pkg
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/arm64-macos.libblst.pkg

# 2. Install the packages (requires sudo password)
sudo installer -pkg arm64-macos.libsodium-vrf.pkg -target /
sudo installer -pkg arm64-macos.libsecp256k1.pkg -target /
sudo installer -pkg arm64-macos.libblst.pkg -target /

# 3. Verify installation
pkg-config --list-all | grep -E 'libsodium|secp256k1|blst'

# 4. Configure environment
export PKG_CONFIG_PATH="/usr/local/opt/cardano/lib/pkgconfig:$PKG_CONFIG_PATH"

# 5. Make permanent (optional but recommended)
echo 'export PKG_CONFIG_PATH="/usr/local/opt/cardano/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.zshrc

# 6. Build cardano-base
cd /path/to/cardano-base
cabal update
cabal build all
```

#### For Intel Macs

Replace `arm64-macos` with `x86_64-macos` in the download URLs:

```bash
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/x86_64-macos.libsodium-vrf.pkg
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/x86_64-macos.libsecp256k1.pkg
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/x86_64-macos.libblst.pkg
```

Then follow the same installation steps as Apple Silicon.

### Linux

#### Using Pre-built Binaries

```bash
# 1. Download and extract binaries
cd /tmp
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/debian.zip
unzip debian.zip

# 2. Install to system directories (requires sudo)
sudo cp -r lib/* /usr/local/lib/
sudo cp -r include/* /usr/local/include/
sudo ldconfig

# 3. Configure pkg-config
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"

# 4. Make permanent
echo 'export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.bashrc

# 5. Build
cd /path/to/cardano-base
cabal update
cabal build all
```

### Windows

```bash
# Download Windows binaries
curl -L -O https://github.com/input-output-hk/iohk-nix/releases/latest/download/x86_64-windows.zip

# Extract and follow Windows-specific installation procedures
# Add library paths to system PATH
```

## Option 3: Building from Source

**Only use this option if pre-built binaries don't work for your platform.**

### Building libsodium-vrf

```bash
# Clone the custom fork with VRF support
git clone https://github.com/input-output-hk/libsodium.git
cd libsodium
git checkout iquerejeta/vrf_batchverify

# Build and install
./autogen.sh
./configure --prefix=/usr/local/opt/cardano
make
sudo make install
```

If you encounter libtool version mismatch errors:

```bash
# Regenerate build files
autoreconf -fi
./configure --prefix=/usr/local/opt/cardano
make
sudo make install
```

### Building libsecp256k1

```bash
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1

./autogen.sh
./configure --prefix=/usr/local/opt/cardano \
  --enable-module-schnorrsig \
  --enable-module-recovery \
  --enable-module-ecdh
make
sudo make install
```

### Building libblst

```bash
git clone https://github.com/supranational/blst.git
cd blst

./build.sh
sudo mkdir -p /usr/local/opt/cardano/lib /usr/local/opt/cardano/include
sudo cp libblst.a /usr/local/opt/cardano/lib/
sudo cp bindings/blst*.h /usr/local/opt/cardano/include/
```

### Environment Setup After Building

```bash
# Set PKG_CONFIG_PATH
export PKG_CONFIG_PATH="/usr/local/opt/cardano/lib/pkgconfig:$PKG_CONFIG_PATH"

# Add to shell profile for persistence
echo 'export PKG_CONFIG_PATH="/usr/local/opt/cardano/lib/pkgconfig:$PKG_CONFIG_PATH"' >> ~/.bashrc  # or ~/.zshrc
```

## Verification

After installation, verify everything is working correctly:

```bash
# 1. Check libraries are found by pkg-config
pkg-config --modversion libsodium      # Should show 1.0.18
pkg-config --modversion libsecp256k1   # Should show a version number
pkg-config --modversion libblst        # Should show a version number

# 2. Verify libsodium has VRF support (critical!)
nm /usr/local/opt/cardano/lib/libsodium.a | grep vrf
# Should show VRF-related symbols like:
#   crypto_vrf_keypair
#   crypto_vrf_ietfdraft13_prove
#   crypto_vrf_ietfdraft13_verify

# 3. Check include and library paths
pkg-config --cflags libsodium          # Should show -I/usr/local/opt/cardano/include
pkg-config --libs libsodium            # Should show -L/usr/local/opt/cardano/lib -lsodium

# 4. Build cardano-base
cd /path/to/cardano-base
cabal update
cabal build all

# 5. Run tests
cabal test all
```

## Troubleshooting

### Error: hsc2hs crashes with exit code -9

**Symptom:**
```
running .../Constants_hsc_make failed (exit code -9)
```

**Cause:** You're using standard libsodium instead of the VRF fork.

**Solution:**
1. Remove any existing libsodium installations from Homebrew/apt
2. Install the pre-built binaries or build from source as described above
3. Verify VRF support with `nm` as shown in Verification section

### Error: Cannot find libsodium/libsecp256k1/libblst

**Symptom:**
```
Package libsodium was not found in the pkg-config search path
```

**Solution:**
```bash
# Ensure PKG_CONFIG_PATH is set
export PKG_CONFIG_PATH="/usr/local/opt/cardano/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify libraries are in the expected location
ls -l /usr/local/opt/cardano/lib/
ls -l /usr/local/opt/cardano/include/
```

### Error: Perl interpreter issues on macOS

**Symptom:**
```
sh: /usr/bin/perl5.30: bad interpreter: No such file or directory
```

**Solution:**
```bash
# Reinstall autotools to fix perl paths
brew reinstall autoconf automake libtool
```

### Error: libtool version mismatch

**Symptom:**
```
libtool: Version mismatch error. This is libtool 2.5.4, but the
libtool: definition of this LT_INIT comes from libtool 2.4.7.
```

**Solution:**
```bash
# Regenerate build files with your system's libtool
autoreconf -fi
./configure --prefix=/usr/local/opt/cardano
make
```

### Still having issues?

1. Check that you're not mixing libraries from different sources (Homebrew + custom install)
2. Verify GHC and Cabal versions meet requirements
3. Try using Nix - it handles all dependencies automatically
4. Check the [project issues](https://github.com/intersectmbo/cardano-base/issues) for similar problems

## Platform-Specific Notes

### macOS

- Libraries install to `/usr/local/opt/cardano/` by default
- Homebrew's libsodium will NOT work - do not install it
- Use `pkg-config --list-all` to verify which libsodium is found first

### Linux

- May need to run `sudo ldconfig` after installing libraries
- Some distributions require `pkg-config` to be installed separately
- Check `/usr/local/lib/pkgconfig/` exists and is in PKG_CONFIG_PATH

### Windows

- Pre-built binaries are provided but may require additional MSYS2 setup
- See CI configuration in `.github/workflows/` for Windows-specific build steps

## Additional Resources

- [Main README](README.md) - Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow
- [cardano-crypto-praos README](cardano-crypto-praos/README.md) - VRF implementation details
- [iohk-nix releases](https://github.com/input-output-hk/iohk-nix/releases/latest) - Pre-built binaries
- [libsodium VRF fork](https://github.com/input-output-hk/libsodium/tree/iquerejeta/vrf_batchverify) - Source code
