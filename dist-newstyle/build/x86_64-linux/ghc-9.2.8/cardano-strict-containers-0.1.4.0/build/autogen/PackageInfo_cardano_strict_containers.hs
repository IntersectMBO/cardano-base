{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_strict_containers (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_strict_containers"
version :: Version
version = Version [0,1,4,0] []

synopsis :: String
synopsis = "Various strict container types"
copyright :: String
copyright = "IOHK"
homepage :: String
homepage = ""
