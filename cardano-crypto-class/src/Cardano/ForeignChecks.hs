{-# LANGUAGE TemplateHaskell #-}

module Cardano.ForeignChecks () where

import Cardano.ForeignChecks.TH (
  ensureExactVersion,
  ensureExactVersionOrCommit,
 )

-- libsodium == 1.0.18
$(ensureExactVersion "libsodium" (1, 0, 18))

-- libblst == 0.3.14 OR libblst == "commit hash"
-- see: https://github.com/input-output-hk/iohk-nix/blob/64ca6f4c0c6db283e2ec457c775bce75173fb319/overlays/crypto/libblst.nix#L44
-- and: https://github.com/input-output-hk/iohk-nix/blob/64ca6f4c0c6db283e2ec457c775bce75173fb319/flake.nix#L15
-- and: https://github.com/supranational/blst/commit/8c7db7fe8d2ce6e76dc398ebd4d475c0ec564355
$( ensureExactVersionOrCommit
     "libblst"
     (Just (0, 3, 14))
     [ "8c7db7fe8d2ce6e76dc398ebd4d475c0ec564355"
     , "03b5124029979755c752eec45f3c29674b558446"
     , "3dd0f804b1819e5d03fb22ca2e6fac105932043a"
     ]
 )
