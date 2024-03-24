{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_cardano_crypto_tests (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "cardano_crypto_tests"
version :: Version
version = Version [2,2,0,1] []

synopsis :: String
synopsis = "Tests for cardano-crypto-class and -praos"
copyright :: String
copyright = "2020-2021 IOHK"
homepage :: String
homepage = ""
