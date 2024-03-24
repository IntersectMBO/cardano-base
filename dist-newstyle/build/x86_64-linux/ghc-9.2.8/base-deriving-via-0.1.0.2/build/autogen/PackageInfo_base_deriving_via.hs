{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_base_deriving_via (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "base_deriving_via"
version :: Version
version = Version [0,1,0,2] []

synopsis :: String
synopsis = "A general hook newtype for use with deriving via"
copyright :: String
copyright = "IOHK"
homepage :: String
homepage = ""
