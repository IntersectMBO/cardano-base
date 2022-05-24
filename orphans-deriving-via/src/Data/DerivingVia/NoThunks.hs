{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- | "GHC.Generics" definition of 'NoThunks'
module Data.DerivingVia.NoThunks
  (
  )
where

import Data.DerivingVia
import Data.Proxy
import GHC.Generics
import NoThunks.Class

-- | Copied from the "NoThunks.Class" default method definitions
instance
  (Generic a, GShowTypeOf (Rep a), GWNoThunks '[] (Rep a)) =>
  NoThunks (InstantiatedAt Generic a)
  where
  wNoThunks ctxt (InstantiatedAt x) =
    gwNoThunks (Proxy @'[]) ctxt fp
    where
      !fp = from x

  showTypeOf _ = gShowTypeOf (from (undefined :: a))

-- Copied from the "NoThunks.Class"
class GShowTypeOf f where gShowTypeOf :: f x -> String

instance Datatype c => GShowTypeOf (D1 c f) where gShowTypeOf = datatypeName
