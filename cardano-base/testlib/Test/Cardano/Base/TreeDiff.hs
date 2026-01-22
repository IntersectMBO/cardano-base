{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Base.TreeDiff where

import Cardano.Base.IP
import Data.TreeDiff

instance ToExpr IPv4 where
  toExpr = defaultExprViaShow

instance ToExpr IPv6 where
  toExpr = defaultExprViaShow
