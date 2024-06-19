{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_binary_test (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_binary_test"
version :: Version
version = Version [1,4,0,2] []

synopsis :: String
synopsis = "Test helpers from cardano-binary exposed to other packages"
copyright :: String
copyright = "2019-2021 IOHK"
homepage :: String
homepage = ""
