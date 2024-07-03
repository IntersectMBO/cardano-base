{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_git_rev (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_git_rev"
version :: Version
version = Version [0,2,2,0] []

synopsis :: String
synopsis = "Git revisioning"
copyright :: String
copyright = "2022-2023 Input Output Global Inc (IOG)."
homepage :: String
homepage = ""
