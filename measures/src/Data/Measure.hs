{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NoImplicitPrelude #-}

-- | Combinators for a possibly-multidimensional measurement
--
-- The type @(Age, Height)@ is archetypal example of 'Measure'. It's typically
-- a fixed-length vector of non-negative " measurements ".
--
-- The anticipated use-cases involve some notion of a capacity that is limited
-- on a per-dimension basis. Thus the measure of each included candidate
-- quantifies how much of that capacity the candidate would occupy. See eg
-- 'splitAt'.
--
-- See the 'Measure' class for more.
module Data.Measure
  ( module Data.Measure.Class,
    (<=),
    (>=),
    drop,
    splitAt,
    take,
  )
where

import Data.Measure.Class
import qualified Prelude

infix 4 <=, >=

-- | The partial order induced by 'min'
--
-- It's only true if every component on the left is @<=@ the corresponding
-- component on the right.
(<=) :: Measure a => a -> a -> Prelude.Bool
x <= y = x Prelude.== min x y

-- | The partial order induced by 'max'
--
-- It's only true if every component on the left is @>=@ the corresponding
-- component on the right.
(>=) :: Measure a => a -> a -> Prelude.Bool
x >= y = x Prelude.== max x y

-- | Split a list once a prefix fills up the given capacity
--
-- Note that this just splits the given list; it does not attempt anything
-- clever like bin-packing etc.
splitAt :: Measure a => (e -> a) -> a -> [e] -> ([e], [e])
splitAt measure limit =
  go zero []
  where
    go !tot acc = \case
      [] -> (Prelude.reverse acc, [])
      e : es ->
        if tot' <= limit
          then go tot' (e : acc) es
          else (Prelude.reverse acc, e : es)
        where
          tot' = plus tot (measure e)

-- | @fst . 'splitAt' measure limit@, but non-strict
take :: Measure a => (e -> a) -> a -> [e] -> [e]
take measure limit =
  go zero
  where
    go !tot = \case
      [] -> []
      e : es ->
        if tot' <= limit
          then e : go tot' es
          else []
        where
          tot' = plus tot (measure e)

-- | @snd . 'splitAt' measure limit@, with a bit less allocation
drop :: Measure a => (e -> a) -> a -> [e] -> [e]
drop measure limit =
  go zero
  where
    go !tot = \case
      [] -> []
      e : es ->
        if tot' <= limit
          then go tot' es
          else e : es
        where
          tot' = plus tot (measure e)
