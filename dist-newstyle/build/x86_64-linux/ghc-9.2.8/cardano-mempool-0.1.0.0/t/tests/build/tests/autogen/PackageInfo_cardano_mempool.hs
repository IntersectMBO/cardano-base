{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_mempool (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_mempool"
version :: Version
version = Version [0,1,0,0] []

synopsis :: String
synopsis = "Short description"
copyright :: String
copyright = "2022 IOHK"
homepage :: String
homepage = "https://github.com/input-output-hk/cardano-base"
