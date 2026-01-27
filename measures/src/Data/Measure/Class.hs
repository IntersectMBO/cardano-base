{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoImplicitPrelude #-}

{-# OPTIONS -Wno-unticked-promoted-constructors #-}

-- | See 'Measure'
module Data.Measure.Class (
  BoundedMeasure (..),
  Measure (..),

  -- * Exceptions
  DataMeasureClassOverflowException (..),
)
where

import Control.Exception (Exception, throw)
import Data.Coerce
import Data.DerivingVia
import Data.Word (Word16, Word32, Word64, Word8)
import GHC.Generics
import GHC.TypeLits
import Prelude (($))
import qualified Prelude

-- | Core combinators for a possibly-multidimensional measurement
--
-- @a@ is a fixed set of measurements of a /single/ object. It is not the
-- measurements from multiple objects.
--
-- - @('zero', 'plus')@ is a commutative monoid
--
-- - @('zero', 'max')@ is a bounded join-semilattice
--
-- - @('min', 'max')@ is a lattice
--
-- - /lattice-ordered monoid/ @'min' ('plus' a b) ('plus' a c) = a + 'min' b c@
--
-- Note that the bounded join-semilattice precludes negative (components of)
-- measurements.
class Prelude.Eq a => Measure a where
  -- | The measurement of nothing
  --
  -- See 'Measure' for laws.
  zero :: a

  -- | Combine two measurements
  --
  -- If @a@ consists of multiple measurements, this is componentwise.
  --
  -- See 'Measure' for laws.
  plus :: a -> a -> a

  -- | The lesser of two measurements
  --
  -- If @a@ consists of multiple measurements, this is componentwise.
  --
  -- See 'Measure' for laws.
  min :: a -> a -> a

  -- | The greater of two measurements
  --
  -- If @a@ consists of multiple measurements, this is componentwise.
  --
  -- See 'Measure' for laws.
  max :: a -> a -> a

-- | A unique maximal measurement
--
-- - @('maxBound', 'min')@ is a bounded meet-semilattice
class Measure a => BoundedMeasure a where
  -- | A unique maximal measurement
  --
  -- See 'BoundedMeasure' for laws.
  maxBound :: a

--------------------------------------------------------------------------------
-- Primitive instances
--------------------------------------------------------------------------------

-- we conservatively don't instantiate for types that represent negative
-- numbers

instance Measure Natural where
  zero = 0
  plus = (Prelude.+)
  min = Prelude.min
  max = Prelude.max

deriving via
  InstantiatedAt Generic (a, b)
  instance
    (Measure a, Measure b) => Measure (a, b)

deriving via
  InstantiatedAt Generic (a, b, c)
  instance
    (Measure a, Measure b, Measure c) => Measure (a, b, c)

deriving via
  InstantiatedAt Generic (a, b, c, d)
  instance
    (Measure a, Measure b, Measure c, Measure d) =>
    Measure (a, b, c, d)

deriving via
  InstantiatedAt Generic (a, b, c, d, e)
  instance
    (Measure a, Measure b, Measure c, Measure d, Measure e) =>
    Measure (a, b, c, d, e)

deriving via
  InstantiatedAt Generic (a, b, c, d, e, f)
  instance
    (Measure a, Measure b, Measure c, Measure d, Measure e, Measure f) =>
    Measure (a, b, c, d, e, f)

deriving via
  InstantiatedAt Generic (a, b, c, d, e, f, g)
  instance
    ( Measure a
    , Measure b
    , Measure c
    , Measure d
    , Measure e
    , Measure f
    , Measure g
    ) =>
    Measure (a, b, c, d, e, f, g)

-- larger tuples unfortunatley do not have Generic instances

-- | 'plus' throws 'DataMeasureClassOverflowException'
instance Measure Word8 where
  zero = 0
  plus = checkedPlus
  min = Prelude.min
  max = Prelude.max

instance BoundedMeasure Word8 where
  maxBound = Prelude.maxBound

-- | 'plus' throws 'DataMeasureClassOverflowException'
instance Measure Word16 where
  zero = 0
  plus = checkedPlus
  min = Prelude.min
  max = Prelude.max

instance BoundedMeasure Word16 where
  maxBound = Prelude.maxBound

-- | 'plus' throws 'DataMeasureClassOverflowException'
instance Measure Word32 where
  zero = 0
  plus = checkedPlus
  min = Prelude.min
  max = Prelude.max

instance BoundedMeasure Word32 where
  maxBound = Prelude.maxBound

-- | 'plus' throws 'DataMeasureClassOverflowException'
instance Measure Word64 where
  zero = 0
  plus = checkedPlus
  min = Prelude.min
  max = Prelude.max

instance BoundedMeasure Word64 where
  maxBound = Prelude.maxBound

-- not exported
--
-- Throws 'DataMeasureClassOverflowException'
checkedPlus ::
  (Prelude.Bounded a, Prelude.Integral a) =>
  a ->
  a ->
  a
checkedPlus x y =
  if x Prelude.> Prelude.maxBound Prelude.- y
    then throw DataMeasureClassOverflowException
    else x Prelude.+ y

-- | An exception thrown by 'plus' on overflow, since overflow violates
-- /lattice-ordered monoid/
data DataMeasureClassOverflowException = DataMeasureClassOverflowException
  deriving (Prelude.Show)

instance Exception DataMeasureClassOverflowException

--------------------------------------------------------------------------------
-- DerivingVia instances via these classes
--------------------------------------------------------------------------------

-- | The @('zero', 'plus')@ monoid
instance Measure a => Prelude.Monoid (InstantiatedAt Measure a) where
  mempty = coerce $ zero @a

-- | The @('zero', 'plus')@ monoid
instance Measure a => Prelude.Semigroup (InstantiatedAt Measure a) where
  (<>) = coerce $ plus @a

--------------------------------------------------------------------------------
-- DerivingVia instances of these classes
--------------------------------------------------------------------------------

instance
  (Prelude.Monoid a, Prelude.Ord a) =>
  Measure (InstantiatedAt Prelude.Ord a)
  where
  zero = coerce $ Prelude.mempty @a
  plus = coerce $ (Prelude.<>) @a
  min = coerce $ Prelude.min @a
  max = coerce $ Prelude.max @a

instance
  (Prelude.Bounded a, Prelude.Monoid a, Prelude.Ord a) =>
  BoundedMeasure (InstantiatedAt Prelude.Ord a)
  where
  maxBound = coerce $ Prelude.maxBound @a

instance
  (Prelude.Eq a, Generic a, GMeasure (Rep a)) =>
  Measure (InstantiatedAt Generic a)
  where
  zero = coerce $ to @a gzero
  plus = coerce $ gbinop @a gplus
  min = coerce $ gbinop @a gmin
  max = coerce $ gbinop @a gmax

instance
  (Prelude.Eq a, Generic a, GBoundedMeasure (Rep a), GMeasure (Rep a)) =>
  BoundedMeasure (InstantiatedAt Generic a)
  where
  maxBound = coerce $ to @a gmaxBound

-- not exported
gbinop ::
  Generic a => (forall x. Rep a x -> Rep a x -> Rep a x) -> a -> a -> a
gbinop f l r = to $ f (from l) (from r)

class GMeasure rep where
  gzero :: rep x
  gplus :: rep x -> rep x -> rep x
  gmin :: rep x -> rep x -> rep x
  gmax :: rep x -> rep x -> rep x

instance Measure c => GMeasure (K1 i c) where
  gzero = K1 zero
  gplus (K1 l) (K1 r) = K1 (plus l r)
  gmin (K1 l) (K1 r) = K1 (min l r)
  gmax (K1 l) (K1 r) = K1 (max l r)

instance GMeasure f => GMeasure (M1 i c f) where
  gzero = M1 gzero
  gplus (M1 l) (M1 r) = M1 (gplus l r)
  gmin (M1 l) (M1 r) = M1 (gmin l r)
  gmax (M1 l) (M1 r) = M1 (gmax l r)

instance GMeasure V1 where
  gzero = Prelude.error "GMeasure V1"
  gplus = \case {}
  gmin = \case {}
  gmax = \case {}

instance GMeasure U1 where
  gzero = U1
  gplus U1 U1 = U1
  gmin U1 U1 = U1
  gmax U1 U1 = U1

instance (GMeasure l, GMeasure r) => GMeasure (l :*: r) where
  gzero = gzero :*: gzero
  gplus (l1 :*: r1) (l2 :*: r2) = gplus l1 l2 :*: gplus r1 r2
  gmin (l1 :*: r1) (l2 :*: r2) = gmin l1 l2 :*: gmin r1 r2
  gmax (l1 :*: r1) (l2 :*: r2) = gmax l1 l2 :*: gmax r1 r2

instance
  TypeError
    ( Text "No Generics definition of "
        :<>: ShowType Measure
        :<>: Text " for types with multiple constructors "
        :<>: ShowType (l :+: r)
    ) =>
  GMeasure (l :+: r)
  where
  gzero = Prelude.error "GMeasure gzero :+:"
  gplus = Prelude.error "GMeasure gplus :+:"
  gmin = Prelude.error "GMeasure gmin :+:"
  gmax = Prelude.error "GMeasure gmax :+:"

class GBoundedMeasure rep where
  gmaxBound :: rep x

instance BoundedMeasure c => GBoundedMeasure (K1 i c) where
  gmaxBound = K1 maxBound

instance GBoundedMeasure f => GBoundedMeasure (M1 i c f) where
  gmaxBound = M1 gmaxBound

instance GBoundedMeasure V1 where
  gmaxBound = Prelude.error "GBoundedMeasure V1"

instance GBoundedMeasure U1 where
  gmaxBound = U1

instance (GBoundedMeasure l, GBoundedMeasure r) => GBoundedMeasure (l :*: r) where
  gmaxBound = gmaxBound :*: gmaxBound

instance
  TypeError
    ( Text "No Generics definition of "
        :<>: ShowType BoundedMeasure
        :<>: Text " for types with multiple constructors "
        :<>: ShowType (l :+: r)
    ) =>
  GBoundedMeasure (l :+: r)
  where
  gmaxBound = Prelude.error "GBoundedMeasure :+:"
