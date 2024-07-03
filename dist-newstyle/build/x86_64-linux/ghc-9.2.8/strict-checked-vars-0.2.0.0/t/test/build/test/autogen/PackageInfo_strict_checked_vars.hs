{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_strict_checked_vars (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "strict_checked_vars"
version :: Version
version = Version [0,2,0,0] []

synopsis :: String
synopsis = "Strict MVars and TVars with invariant checking for IO and IOSim"
copyright :: String
copyright = "2019-2023 Input Output Global Inc (IOG)."
homepage :: String
homepage = ""
