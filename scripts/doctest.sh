#!/usr/bin/env bash

set -euo pipefail

# GHC 9.14's interactive linker does not pull in symbols from pkgconfig
# C libraries when loading the doctest shared object, so doctests for
# packages that FFI into libsodium fail with `undefined symbol: sodium_*`.
# Preloading libsodium makes those symbols available to GHCi.
# `--repl-options=--optimistic-linking` would also work, but doctest 0.25
# passes that flag to the non-interactive GHC extraction stage which
# rejects it as unknown.
if [[ "$(uname -s)" == Linux ]] && libsodium_libdir=$(pkg-config --variable=libdir libsodium 2>/dev/null); then
  export LD_PRELOAD="${libsodium_libdir}/libsodium.so${LD_PRELOAD:+:$LD_PRELOAD}"
fi

# Packages to run doctests for; defaults to all packages if none are specified
PACKAGES=("$@")

# Install doctest's Cabal integration, if it's not present already
if [[ -z "$(type -t cabal-doctest)" ]]
then
  cabal install doctest --flag cabal-doctest --ignore-project --overwrite-policy=always
fi

# Ensure doctest and PATH are using the same ghc version

getExecutablePath()
{
  "$1" -package-env - -e 'import System.Environment' -e 'putStrLn =<< getExecutablePath'
}

default_ghc=$(type -p ghc)
doctest_ghc=$(doctest --info | ghc -e 'interact $ maybe "" id . lookup "ghc" . read')

if [[ "$(getExecutablePath "$default_ghc")" != "$(getExecutablePath "$doctest_ghc")" ]]
then
  echo "Incompatible GHC's:" >&2
  echo "  Default ghc: $(getExecutablePath "$default_ghc")" >&2
  echo "  Doctest ghc: $(getExecutablePath "$doctest_ghc")" >&2
  exit 1
fi

# Ensure the cabal-doctest executable can be found
PATH=$(cabal path --installdir):$PATH

# Ensure other scripts (eg cabal-targets.hs) can be found
case "$0" in
  */*) PATH=$(dirname "$(which "$0")"):$PATH;;
esac

# Specify additional arguments needed for specific modules
EXTRA_ARGS=$(mktemp)
trap 'rm -f "$EXTRA_ARGS"' EXIT
cat <<EOF >"$EXTRA_ARGS"
cardano-ledger-api:lib:cardano-ledger-api --build-depends=cardano-ledger-babbage:testlib
EOF

# Run the doctests for some or all packages
cabal-targets.hs "${PACKAGES[@]}" |
sort | join -t' ' -a1 -j1 - "$EXTRA_ARGS" |
while read -ra ARGS
do
  echo "***** cabal doctest ${ARGS[0]} *****"
  cabal doctest --repl-options='-w -Wdefault' "${ARGS[@]}"
done
