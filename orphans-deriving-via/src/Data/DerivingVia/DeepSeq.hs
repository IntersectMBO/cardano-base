{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- | "GHC.Generics" definition of 'rnf'
module Data.DerivingVia.DeepSeq
  (
  )
where

import Control.DeepSeq
import Data.DerivingVia
import GHC.Generics

instance
  (Generic a, GNFData (Rep a)) =>
  NFData (InstantiatedAt Generic a)
  where
  rnf (InstantiatedAt x) = grnf (from x)

class GNFData rep where
  grnf :: rep x -> ()

instance NFData c => GNFData (K1 i c) where
  grnf (K1 a) = rnf a

instance GNFData f => GNFData (M1 i c f) where
  grnf (M1 a) = grnf a

instance GNFData V1 where
  grnf = \case {}

instance GNFData U1 where
  grnf U1 = ()

instance (GNFData l, GNFData r) => GNFData (l :*: r) where
  grnf (l :*: r) = grnf l `seq` grnf r

instance (GNFData l, GNFData r) => GNFData (l :+: r) where
  grnf = \case
    L1 l -> grnf l
    R1 r -> grnf r
