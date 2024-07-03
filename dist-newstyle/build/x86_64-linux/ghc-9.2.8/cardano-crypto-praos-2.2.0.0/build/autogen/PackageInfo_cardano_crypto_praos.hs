{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_crypto_praos (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_crypto_praos"
version :: Version
version = Version [2,2,0,0] []

synopsis :: String
synopsis = "Crypto primitives from libsodium"
copyright :: String
copyright = "2019-2021 IOHK"
homepage :: String
homepage = ""
