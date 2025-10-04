#!/usr/bin/env bash

# devenv.sh - Development environment setup and verification for cardano-base
#
# Usage:
#   ./scripts/devenv.sh install  - Install pre-built cryptographic dependencies
#   ./scripts/devenv.sh doctor   - Verify installation and check for conflicts

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation prefix for cardano crypto libraries
INSTALL_PREFIX="/usr/local/opt/cardano"

# GitHub release URL
RELEASE_URL="https://github.com/input-output-hk/iohk-nix/releases/latest/download"

# Detect platform and architecture
detect_platform() {
    local os
    local arch

    case "$(uname -s)" in
        Darwin)
            os="macos"
            ;;
        Linux)
            os="linux"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            os="windows"
            ;;
        *)
            echo -e "${RED}✗ Unsupported operating system: $(uname -s)${NC}"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        arm64|aarch64)
            arch="arm64"
            ;;
        *)
            echo -e "${RED}✗ Unsupported architecture: $(uname -m)${NC}"
            exit 1
            ;;
    esac

    echo "${arch}-${os}"
}

# Print colored status
print_status() {
    local status=$1
    local message=$2

    case "$status" in
        ok)
            echo -e "${GREEN}✓${NC} $message"
            ;;
        warn)
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
        error)
            echo -e "${RED}✗${NC} $message"
            ;;
        info)
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
    esac
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect shell profile file
detect_shell_profile() {
    # Detect current shell
    local current_shell
    current_shell=$(basename "$SHELL")

    case "$current_shell" in
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                echo "$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.bashrc"
            fi
            ;;
        zsh)
            echo "$HOME/.zshrc"
            ;;
        fish)
            echo "$HOME/.config/fish/config.fish"
            ;;
        *)
            echo "$HOME/.profile"
            ;;
    esac
}

# Check if shell profile already has PKG_CONFIG_PATH configured
check_shell_profile() {
    local profile_file
    profile_file=$(detect_shell_profile)

    if [ -f "$profile_file" ]; then
        if grep -q "PKG_CONFIG_PATH.*${INSTALL_PREFIX}" "$profile_file" 2>/dev/null; then
            return 0  # Already configured
        fi
    fi
    return 1  # Not configured
}

# Configure shell profile
configure_shell_profile() {
    local profile_file
    profile_file=$(detect_shell_profile)

    echo ""
    print_status "info" "Configuring shell environment..."

    # Check if already in current environment
    if [[ "${PKG_CONFIG_PATH:-}" == *"${INSTALL_PREFIX}"* ]]; then
        print_status "ok" "PKG_CONFIG_PATH already set in current session"
    else
        print_status "warn" "PKG_CONFIG_PATH not set in current session"
        print_status "info" "Run: export PKG_CONFIG_PATH=\"${INSTALL_PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH\""
    fi

    # Check shell profile
    if check_shell_profile; then
        print_status "ok" "Shell profile ($profile_file) already configured"
    else
        print_status "warn" "Shell profile ($profile_file) not configured"
        echo ""
        echo "Would you like to add PKG_CONFIG_PATH to $profile_file? [y/N]"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "" >> "$profile_file"
            echo "# Added by cardano-base devenv.sh" >> "$profile_file"
            echo "export PKG_CONFIG_PATH=\"${INSTALL_PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH\"" >> "$profile_file"
            print_status "ok" "Added PKG_CONFIG_PATH to $profile_file"
            print_status "info" "Restart your shell or run: source $profile_file"
        else
            print_status "info" "To configure manually, add this line to $profile_file:"
            echo ""
            echo "    export PKG_CONFIG_PATH=\"${INSTALL_PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH\""
        fi
    fi
    echo ""
}

# Install pre-built binaries
install_dependencies() {
    local platform
    platform=$(detect_platform)

    echo -e "${BLUE}Installing cardano-base cryptographic dependencies${NC}"
    echo -e "${BLUE}Platform: ${platform}${NC}"
    echo ""

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    cd "$tmp_dir"

    if [[ "$platform" == *"macos"* ]]; then
        install_macos "$platform"
    elif [[ "$platform" == *"linux"* ]]; then
        install_linux "$platform"
    elif [[ "$platform" == *"windows"* ]]; then
        install_windows "$platform"
    fi

    echo ""
    print_status "ok" "Installation complete!"

    # Configure shell profile
    configure_shell_profile
}

install_macos() {
    local platform=$1

    print_status "info" "Downloading pre-built packages for macOS..."

    local packages=("libsodium-vrf" "libsecp256k1" "libblst")

    for pkg in "${packages[@]}"; do
        local filename="${platform}.${pkg}.pkg"
        local url="${RELEASE_URL}/${filename}"

        echo -n "  Downloading ${pkg}... "
        if curl -L -f -s -o "$filename" "$url"; then
            echo "done"
        else
            echo -e "${RED}failed${NC}"
            print_status "error" "Failed to download ${pkg}"
            exit 1
        fi
    done

    echo ""
    print_status "info" "Installing packages (requires sudo)..."

    for pkg in "${packages[@]}"; do
        local filename="${platform}.${pkg}.pkg"
        echo "  Installing ${pkg}..."
        if ! sudo installer -pkg "$filename" -target /; then
            print_status "error" "Failed to install ${pkg}"
            exit 1
        fi
    done
}

install_linux() {
    local platform=$1

    print_status "info" "Downloading pre-built binaries for Linux..."

    # Use debian.zip for all Linux x86_64 platforms
    local filename="debian.zip"
    local url="${RELEASE_URL}/${filename}"

    if ! command_exists unzip; then
        print_status "error" "unzip is required but not installed. Please install it first."
        exit 1
    fi

    echo -n "  Downloading... "
    if curl -L -f -s -o "$filename" "$url"; then
        echo "done"
    else
        echo -e "${RED}failed${NC}"
        print_status "error" "Failed to download binaries"
        exit 1
    fi

    echo -n "  Extracting... "
    if unzip -q "$filename"; then
        echo "done"
    else
        echo -e "${RED}failed${NC}"
        print_status "error" "Failed to extract archive"
        exit 1
    fi

    print_status "info" "Installing to ${INSTALL_PREFIX} (requires sudo)..."

    sudo mkdir -p "${INSTALL_PREFIX}/lib" "${INSTALL_PREFIX}/include"

    if [ -d "lib" ]; then
        sudo cp -r lib/* "${INSTALL_PREFIX}/lib/"
    fi

    if [ -d "include" ]; then
        sudo cp -r include/* "${INSTALL_PREFIX}/include/"
    fi

    print_status "info" "Running ldconfig..."
    sudo ldconfig 2>/dev/null || true
}

install_windows() {
    local platform=$1

    print_status "warn" "Windows installation not fully automated"
    print_status "info" "Please download manually from:"
    echo "  ${RELEASE_URL}/${platform}.zip"
    print_status "info" "Extract and add library paths to your PATH environment variable"
}

# Doctor: Check installation
check_installation() {
    echo -e "${BLUE}Checking cardano-base development environment${NC}"
    echo ""

    local has_errors=0
    local has_warnings=0

    # Check required tools
    echo -e "${BLUE}Required Tools:${NC}"

    for tool in ghc cabal pkg-config; do
        if command_exists "$tool"; then
            local version
            case "$tool" in
                ghc)
                    version=$(ghc --numeric-version 2>/dev/null || echo "unknown")
                    ;;
                cabal)
                    version=$(cabal --numeric-version 2>/dev/null || echo "unknown")
                    ;;
                pkg-config)
                    version=$(pkg-config --version 2>/dev/null || echo "unknown")
                    ;;
            esac
            print_status "ok" "$tool installed (version: $version)"
        else
            print_status "error" "$tool not found"
            ((has_errors++))
        fi
    done

    echo ""

    # Check PKG_CONFIG_PATH
    echo -e "${BLUE}Environment:${NC}"

    if [[ "${PKG_CONFIG_PATH:-}" == *"${INSTALL_PREFIX}"* ]]; then
        print_status "ok" "PKG_CONFIG_PATH includes ${INSTALL_PREFIX} in current session"
    else
        print_status "warn" "PKG_CONFIG_PATH does not include ${INSTALL_PREFIX} in current session"
        print_status "info" "Run: export PKG_CONFIG_PATH=\"${INSTALL_PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH\""
        ((has_warnings++))
    fi

    # Check shell profile
    local profile_file
    profile_file=$(detect_shell_profile)

    if check_shell_profile; then
        print_status "ok" "Shell profile ($profile_file) is configured"
    else
        print_status "warn" "Shell profile ($profile_file) is not configured"
        print_status "info" "Run './scripts/devenv.sh install' to configure automatically"
        print_status "info" "Or manually add: export PKG_CONFIG_PATH=\"${INSTALL_PREFIX}/lib/pkgconfig:\$PKG_CONFIG_PATH\""
        ((has_warnings++))
    fi

    echo ""

    # Check cryptographic libraries
    echo -e "${BLUE}Cryptographic Libraries:${NC}"

    check_library "libsodium" "1.0.18" true
    check_library "libsecp256k1" "" false
    check_library "libblst" "" false

    echo ""

    # Check for conflicting installations
    echo -e "${BLUE}Checking for Conflicts:${NC}"

    check_conflicts "libsodium"
    check_conflicts "libsecp256k1"
    check_conflicts "blst"

    echo ""

    # Final summary
    if [ $has_errors -eq 0 ] && [ $has_warnings -eq 0 ]; then
        print_status "ok" "All checks passed! ✨"
        return 0
    elif [ $has_errors -eq 0 ]; then
        print_status "warn" "Checks passed with $has_warnings warning(s)"
        return 0
    else
        print_status "error" "Found $has_errors error(s) and $has_warnings warning(s)"
        return 1
    fi
}

check_library() {
    local lib_name=$1
    local expected_version=$2
    local check_vrf=$3

    # Check if library is found via pkg-config
    if ! command_exists pkg-config; then
        print_status "error" "pkg-config not available, cannot check $lib_name"
        return 1
    fi

    if pkg-config --exists "$lib_name" 2>/dev/null; then
        local version
        version=$(pkg-config --modversion "$lib_name" 2>/dev/null || echo "unknown")

        local lib_path
        lib_path=$(pkg-config --variable=libdir "$lib_name" 2>/dev/null || echo "unknown")

        # Check if it's from our installation
        if [[ "$lib_path" == *"${INSTALL_PREFIX}"* ]]; then
            print_status "ok" "$lib_name found (version: $version, path: $lib_path)"

            # For libsodium, check VRF support
            if [ "$check_vrf" = true ]; then
                check_vrf_support "$lib_path"
            fi
        else
            print_status "warn" "$lib_name found but NOT from ${INSTALL_PREFIX} (path: $lib_path)"
            print_status "info" "This may cause build issues. Expected path: ${INSTALL_PREFIX}"
        fi

        # Check version if specified
        if [ -n "$expected_version" ] && [ "$version" != "$expected_version" ]; then
            print_status "warn" "Version mismatch: expected $expected_version, got $version"
        fi
    else
        print_status "error" "$lib_name not found via pkg-config"
    fi
}

check_vrf_support() {
    local lib_path=$1

    # Look for libsodium library files
    local lib_file
    if [ -f "${lib_path}/libsodium.a" ]; then
        lib_file="${lib_path}/libsodium.a"
    elif [ -f "${INSTALL_PREFIX}/lib/libsodium.a" ]; then
        lib_file="${INSTALL_PREFIX}/lib/libsodium.a"
    else
        print_status "warn" "  Could not find libsodium.a to check VRF support"
        return 0
    fi

    # Check for VRF symbols
    # Note: grep with -q returns 1 if no match, which would trigger set -e
    # So we capture the result explicitly
    if nm "$lib_file" 2>/dev/null | grep -i "vrf" >/dev/null 2>&1; then
        print_status "ok" "  VRF support detected in libsodium"
        return 0
    else
        print_status "error" "  VRF support NOT found in libsodium"
        print_status "info" "  This is likely standard libsodium, not the VRF fork"
        print_status "info" "  Run './scripts/devenv.sh install' to install the correct version"
        return 0
    fi
}

check_conflicts() {
    local lib_name=$1

    # Check Homebrew (macOS)
    if command_exists brew; then
        if brew list "$lib_name" &>/dev/null; then
            print_status "warn" "Homebrew $lib_name is installed (may conflict)"
            print_status "info" "  Consider: brew uninstall $lib_name"
        fi
    fi

    # Check common system locations
    local system_paths=(
        "/usr/local/lib"
        "/usr/lib"
        "/opt/homebrew/lib"
    )

    for path in "${system_paths[@]}"; do
        if [ -f "$path/lib${lib_name}.dylib" ] || [ -f "$path/lib${lib_name}.so" ] || [ -f "$path/lib${lib_name}.a" ]; then
            # Skip if it's our installation
            if [[ "$path" != *"${INSTALL_PREFIX}"* ]]; then
                print_status "warn" "Found $lib_name in $path (may conflict)"
            fi
        fi
    done
}

# Show usage
usage() {
    cat <<EOF
Usage: $(basename "$0") <command>

Development environment setup and verification for cardano-base

Commands:
    install     Install pre-built cryptographic dependencies
    doctor      Verify installation and check for conflicts

Examples:
    $(basename "$0") install
    $(basename "$0") doctor

For more information, see INSTALL.md
EOF
}

# Main
main() {
    if [ $# -eq 0 ]; then
        usage
        exit 1
    fi

    case "$1" in
        install)
            install_dependencies
            ;;
        doctor)
            check_installation
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown command '$1'${NC}"
            echo ""
            usage
            exit 1
            ;;
    esac
}

main "$@"
