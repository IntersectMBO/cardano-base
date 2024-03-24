{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_slotting (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_slotting"
version :: Version
version = Version [0,2,0,0] []

synopsis :: String
synopsis = "Key slotting types for cardano libraries"
copyright :: String
copyright = "IOHK"
homepage :: String
homepage = ""
