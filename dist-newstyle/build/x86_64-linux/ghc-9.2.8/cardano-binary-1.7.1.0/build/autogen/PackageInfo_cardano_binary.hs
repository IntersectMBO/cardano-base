{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_binary (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_binary"
version :: Version
version = Version [1,7,1,0] []

synopsis :: String
synopsis = "Binary serialization for Cardano"
copyright :: String
copyright = "2019-2021 IOHK"
homepage :: String
homepage = ""
