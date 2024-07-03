{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_measures (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "measures"
version :: Version
version = Version [0,1,0,2] []

synopsis :: String
synopsis = "An abstraction for (tuples of) measured quantities"
copyright :: String
copyright = "IOHK"
homepage :: String
homepage = ""
