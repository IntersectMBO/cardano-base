{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE UndecidableInstances       #-}

-- | Newtype wrappers for us in @deriving via@ clauses that " should " have
-- been defined in @base@ and other packages we depend on but do not control
--
-- We expected variations of these to eventually be defined upstream, but we'd
-- like to use these concepts before that happens.
module Data.DerivingVia
  ( InstantiatedAt (..)
  )
where

import Data.Kind (Constraint, Type)
import GHC.Generics

import Data.DerivingVia.GHC.Generics.Monoid
import Data.DerivingVia.GHC.Generics.Semigroup

infix 0 `InstantiatedAt`

-- | A hook that represents a @deriving via@ scheme via some class constraint
--
-- The most notable example is 'GHC.Generics.Generic'.
--
-- > data T = ...
-- >   deriving (Monoid, Semigroup)
-- >        via InstantiatedAt Generic T
--
-- This type's parameterization is useful because many such schemes are
-- similarly identified by a single type class, such as 'Ord'.
newtype InstantiatedAt (c :: Type -> Constraint) a = InstantiatedAt a
  deriving newtype (Eq, Ord, Show)

instance (Generic a, GSemigroup (Rep a))
      => Semigroup (InstantiatedAt Generic a) where
  InstantiatedAt l <> InstantiatedAt r =
    InstantiatedAt $ to $ gsappend (from l) (from r)

instance (Generic a, GSemigroup (Rep a), GMonoid (Rep a))
      => Monoid (InstantiatedAt Generic a) where
  mempty = InstantiatedAt $ to gmempty
