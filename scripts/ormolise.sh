#!/usr/bin/env bash

set -euo pipefail

ormolu -c -m inplace $(git ls-files -- '*.hs' | grep -v Setup.hs)

git diff --exit-code