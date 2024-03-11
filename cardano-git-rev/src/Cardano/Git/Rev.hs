{-# LANGUAGE CPP #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Cardano.Git.Rev
  ( gitRev
  ) where

import           Data.Text (Text)
import qualified Data.Text as T

#if !defined(arm_HOST_ARCH)
import           Cardano.Git.RevFromGit (gitRevFromGit)
#endif
import           Foreign.C.String (CString)
import           GHC.Foreign (peekCStringLen)
import           Language.Haskell.TH (Exp, Q)
import           System.IO (utf8)
import           System.IO.Unsafe (unsafeDupablePerformIO)

foreign import ccall "&_cardano_git_rev" c_gitrev :: CString

-- This must be a TH splice to ensure the git commit is captured at build time.
-- ie called as `$(gitRev)`.
gitRev :: Q Exp
gitRev =
    [| if
         | gitRevEmbed /= zeroRev -> gitRevEmbed
         | T.null fromGit         -> zeroRev
         | otherwise              -> fromGit
    |]

-- Git revision embedded after compilation using
-- Data.FileEmbed.injectWith. If nothing has been injected,
-- this will be filled with 0 characters.
gitRevEmbed :: Text
gitRevEmbed = T.pack $ drop 28 $ unsafeDupablePerformIO (peekCStringLen utf8 (c_gitrev, 68))

-- Git revision found during compilation by running git. If
-- git could not be run, then this will be empty.
fromGit :: Text
#if defined(arm_HOST_ARCH)
  -- cross compiling to arm fails; due to a linker bug
fromGit = ""
#else
fromGit = T.strip (T.pack $(gitRevFromGit))
#endif

zeroRev :: Text
zeroRev = "0000000000000000000000000000000000000000"
