{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE EmptyCase            #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS -Wno-unticked-promoted-constructors #-}

-- | "GHC.Generics" definition of '<>'
module Data.DerivingVia.GHC.Generics.Semigroup
  ( GSemigroup (..)
  )
where

import GHC.Generics
import GHC.TypeLits

class GSemigroup rep where
  gsappend :: rep x -> rep x -> rep x

instance Monoid c => GSemigroup (K1 i c) where
  gsappend (K1 l) (K1 r) = K1 (l <> r)

instance GSemigroup f => GSemigroup (M1 i c f) where
  gsappend (M1 l) (M1 r) = M1 (gsappend l r)

instance GSemigroup V1 where
  gsappend = \case {}

instance GSemigroup U1 where
  gsappend U1 U1 = U1

instance (GSemigroup l, GSemigroup r) => GSemigroup (l :*: r) where
  gsappend (l1 :*: r1) (l2 :*: r2) = gsappend l1 l2 :*: gsappend r1 r2

instance TypeError (     Text "No Generics definition of "
                    :<>: ShowType Semigroup
                    :<>: Text " for types with multiple constructors "
                    :<>: ShowType (l :+: r)
                   )
      => GSemigroup (l :+: r) where
  gsappend = error "GSemigroup :+:"
