{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS -Wno-unticked-promoted-constructors #-}

-- | "GHC.Generics" definition of 'mempty'
module Data.DerivingVia.GHC.Generics.Monoid
  ( GMonoid (..)
  )
where

import GHC.Generics
import GHC.TypeLits

class GMonoid rep where
  gmempty :: rep x

instance Monoid c => GMonoid (K1 i c) where
  gmempty = K1 mempty

instance GMonoid f => GMonoid (M1 i c f) where
  gmempty = M1 gmempty

instance GMonoid V1 where
  gmempty = error "GMonoid V1"

instance GMonoid U1 where
  gmempty = U1

instance (GMonoid l, GMonoid r) => GMonoid (l :*: r) where
  gmempty = gmempty :*: gmempty

instance TypeError (     Text "No Generics definition of "
                    :<>: ShowType Monoid
                    :<>: Text " for types with multiple constructors "
                    :<>: ShowType (l :+: r)
                   )
      => GMonoid (l :+: r) where
  gmempty = error "GMonoid :+:"
