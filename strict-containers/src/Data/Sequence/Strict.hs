{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}

-- | Strict variants of 'Seq' operations.
module Data.Sequence.Strict
  ( StrictSeq (Empty, (:<|), (:|>)),
    fromStrict,
    forceToStrict,

    -- * Construction
    empty,
    singleton,
    (<|),
    (|>),
    (><),
    fromList,

    -- * Deconstruction

    -- | Additional functions for deconstructing sequences are available
    -- via the 'Foldable' instance of 'Seq'.

    -- ** Queries
    null,
    length,

    -- * Scans
    scanl,

    -- * Sublists

    -- ** Sequential searches
    dropWhileL,
    dropWhileR,
    spanl,
    spanr,

    -- * Indexing
    lookup,
    (!?),
    take,
    takeLast,
    drop,
    dropLast,
    splitAt,
    splitAtEnd,

    -- * Indexing with predicates
    findIndexL,
    findIndicesL,
    findIndexR,
    findIndicesR,

    -- * Zips and unzips
    zip,
    zipWith,
    unzip,
    unzipWith,
  )
where

import Codec.Serialise (Serialise)
import Control.Arrow ((***))
import Data.Foldable (foldl', toList)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Unit.Strict (forceElemsToWHNF)
import NoThunks.Class (NoThunks (..), noThunksInValues)
import Prelude hiding
  ( drop,
    length,
    lookup,
    null,
    scanl,
    splitAt,
    take,
    unzip,
    zip,
    zipWith,
  )

infixr 5 ><

infixr 5 <|

infixl 5 |>

infixr 5 :<|

infixl 5 :|>

{-# COMPLETE Empty, (:<|) #-}

{-# COMPLETE Empty, (:|>) #-}

-- | A @newtype@ wrapper around a 'Seq', representing a general-purpose finite
-- sequence that is strict in its values.
--
-- This strictness is not enforced at the type level, but rather by the
-- construction functions in this module. These functions essentially just
-- wrap the original "Data.Sequence" functions while forcing the provided
-- value to WHNF.
newtype StrictSeq a = StrictSeq {fromStrict :: Seq a}
  deriving stock (Eq, Ord, Show)
  deriving newtype (Foldable, Monoid, Semigroup, Serialise)

instance Functor StrictSeq where
  fmap f (StrictSeq s) = StrictSeq . forceElemsToWHNF $ fmap f s

instance Traversable StrictSeq where
  sequenceA (StrictSeq xs) = forceToStrict <$> sequenceA xs

-- | Instance for 'StrictSeq' checks elements only
--
-- The internal fingertree in 'Seq' might have thunks, which is essential for
-- its asymptotic complexity.
instance NoThunks a => NoThunks (StrictSeq a) where
  showTypeOf _ = "StrictSeq"
  wNoThunks ctxt = noThunksInValues ctxt . toList

-- | A helper function for the ':<|' pattern.
viewFront :: StrictSeq a -> Maybe (a, StrictSeq a)
viewFront (StrictSeq xs) = case Seq.viewl xs of
  Seq.EmptyL -> Nothing
  x Seq.:< xs' -> Just (x, StrictSeq xs')

-- | A helper function for the ':|>' pattern.
viewBack :: StrictSeq a -> Maybe (StrictSeq a, a)
viewBack (StrictSeq xs) = case Seq.viewr xs of
  Seq.EmptyR -> Nothing
  xs' Seq.:> x -> Just (StrictSeq xs', x)

-- | A bidirectional pattern synonym matching an empty sequence.
pattern Empty :: StrictSeq a
pattern Empty = StrictSeq Seq.Empty

-- | A bidirectional pattern synonym viewing the front of a non-empty
-- sequence.
pattern (:<|) :: a -> StrictSeq a -> StrictSeq a
pattern x :<| xs <-
  (viewFront -> Just (x, xs))
  where
    x :<| xs = x <| xs

-- | A bidirectional pattern synonym viewing the rear of a non-empty
-- sequence.
pattern (:|>) :: StrictSeq a -> a -> StrictSeq a
pattern xs :|> x <-
  (viewBack -> Just (xs, x))
  where
    xs :|> x = xs |> x

{-------------------------------------------------------------------------------
  Construction
-------------------------------------------------------------------------------}

-- | \( O(1) \). The empty sequence.
empty :: StrictSeq a
empty = Empty

-- | \( O(1) \). A singleton sequence.
singleton :: a -> StrictSeq a
singleton !x = StrictSeq (Seq.singleton x)

-- | \( O(1) \). Add an element to the left end of a sequence.
-- Mnemonic: a triangle with the single element at the pointy end.
(<|) :: a -> StrictSeq a -> StrictSeq a
(!x) <| StrictSeq s = StrictSeq (x Seq.<| s)

-- | \( O(1) \). Add an element to the right end of a sequence.
-- Mnemonic: a triangle with the single element at the pointy end.
(|>) :: StrictSeq a -> a -> StrictSeq a
StrictSeq s |> (!x) = StrictSeq (s Seq.|> x)

-- | \( O(\log(\min(n_1,n_2))) \). Concatenate two sequences.
(><) :: StrictSeq a -> StrictSeq a -> StrictSeq a
StrictSeq xs >< StrictSeq ys = StrictSeq (xs Seq.>< ys)

fromList :: [a] -> StrictSeq a
fromList !xs = foldl' (|>) empty xs

-- | Convert a 'Seq' into a 'StrictSeq' by forcing each element to WHNF.
forceToStrict :: Seq a -> StrictSeq a
forceToStrict xs = StrictSeq (forceElemsToWHNF xs)

{-------------------------------------------------------------------------------
  Deconstruction
-------------------------------------------------------------------------------}

-- | \( O(1) \). Is this the empty sequence?
null :: StrictSeq a -> Bool
null (StrictSeq xs) = Seq.null xs

-- | \( O(1) \). The number of elements in the sequence.
length :: StrictSeq a -> Int
length (StrictSeq xs) = Seq.length xs

{-------------------------------------------------------------------------------
  Scans
-------------------------------------------------------------------------------}

-- | 'scanl' is similar to 'foldl', but returns a sequence of reduced
-- values from the left:
--
-- > scanl f z (fromList [x1, x2, ...]) = fromList [z, z `f` x1, (z `f` x1) `f` x2, ...]
scanl :: (a -> b -> a) -> a -> StrictSeq b -> StrictSeq a
scanl f !z0 (StrictSeq xs) = StrictSeq $ forceElemsToWHNF (Seq.scanl f z0 xs)

{-------------------------------------------------------------------------------
  Sublists
-------------------------------------------------------------------------------}

-- | \( O(i) \) where \( i \) is the prefix length.  @'dropWhileL' p xs@ returns
-- the suffix remaining after @'takeWhileL' p xs@.
dropWhileL :: (a -> Bool) -> StrictSeq a -> StrictSeq a
dropWhileL p (StrictSeq xs) = StrictSeq (Seq.dropWhileL p xs)

-- | \( O(i) \) where \( i \) is the suffix length.  @'dropWhileR' p xs@ returns
-- the prefix remaining after @'takeWhileR' p xs@.
--
-- @'dropWhileR' p xs@ is equivalent to @'reverse' ('dropWhileL' p ('reverse' xs))@.
dropWhileR :: (a -> Bool) -> StrictSeq a -> StrictSeq a
dropWhileR p (StrictSeq xs) = StrictSeq (Seq.dropWhileR p xs)

-- | \( O(i) \) where \( i \) is the prefix length.  'spanl', applied to
-- a predicate @p@ and a sequence @xs@, returns a pair whose first
-- element is the longest prefix (possibly empty) of @xs@ of elements that
-- satisfy @p@ and the second element is the remainder of the sequence.
spanl :: (a -> Bool) -> StrictSeq a -> (StrictSeq a, StrictSeq a)
spanl p (StrictSeq xs) = toStrictSeqTuple (Seq.spanl p xs)

-- | \( O(i) \) where \( i \) is the suffix length.  'spanr', applied to a
-- predicate @p@ and a sequence @xs@, returns a pair whose /first/ element
-- is the longest /suffix/ (possibly empty) of @xs@ of elements that
-- satisfy @p@ and the second element is the remainder of the sequence.
spanr :: (a -> Bool) -> StrictSeq a -> (StrictSeq a, StrictSeq a)
spanr p (StrictSeq xs) = toStrictSeqTuple (Seq.spanr p xs)

{-------------------------------------------------------------------------------
  Indexing
-------------------------------------------------------------------------------}

-- | \( O(\log(\min(i,n-i))) \). The element at the specified position,
-- counting from 0. If the specified position is negative or at
-- least the length of the sequence, 'lookup' returns 'Nothing'.
--
-- prop> 0 <= i < length xs ==> lookup i xs == Just (toList xs !! i)
-- prop> i < 0 || i >= length xs ==> lookup i xs = Nothing
--
-- Unlike 'index', this can be used to retrieve an element without
-- forcing it. For example, to insert the fifth element of a sequence
-- @xs@ into a 'Data.Map.Lazy.Map' @m@ at key @k@, you could use
--
-- @
-- case lookup 5 xs of
--   Nothing -> m
--   Just x -> 'Data.Map.Lazy.insert' k x m
-- @
lookup :: Int -> StrictSeq a -> Maybe a
lookup i (StrictSeq xs) = Seq.lookup i xs

-- | \( O(\log(\min(i,n-i))) \). A flipped, infix version of 'lookup'.
(!?) :: StrictSeq a -> Int -> Maybe a
(!?) = flip lookup

-- | \( O(\log(\min(i,n-i))) \). The first @i@ elements of a sequence.
-- If @i@ is negative, @'take' i s@ yields the empty sequence.
-- If the sequence contains fewer than @i@ elements, the whole sequence
-- is returned.
take :: Int -> StrictSeq a -> StrictSeq a
take i (StrictSeq xs) = StrictSeq (Seq.take i xs)

-- | Take the last @n@ elements
--
-- Returns the entire sequence if it has fewer than @n@ elements.
--
-- Inherits asymptotic complexity from @drop@.
takeLast :: Int -> StrictSeq a -> StrictSeq a
takeLast i xs
  | length xs >= i = drop (length xs - i) xs
  | otherwise = xs

-- | \( O(\log(\min(i,n-i))) \). Elements of a sequence after the first @i@.
-- If @i@ is negative, @'drop' i s@ yields the whole sequence.
-- If the sequence contains fewer than @i@ elements, the empty sequence
-- is returned.
drop :: Int -> StrictSeq a -> StrictSeq a
drop i (StrictSeq xs) = StrictSeq (Seq.drop i xs)

-- | Drop the last @n@ elements
--
-- Returns the @Empty@ sequence if it has fewer than @n@ elements.
--
-- Inherits asymptotic complexity from @take@.
dropLast :: Int -> StrictSeq a -> StrictSeq a
dropLast i xs
  | length xs >= i = take (length xs - i) xs
  | otherwise = Empty

-- | \( O(\log(\min(i,n-i))) \). Split a sequence at a given position.
-- @'splitAt' i s = ('take' i s, 'drop' i s)@.
splitAt :: Int -> StrictSeq a -> (StrictSeq a, StrictSeq a)
splitAt i (StrictSeq xs) = toStrictSeqTuple (Seq.splitAt i xs)

-- | Split at the given position counting from the end of the sequence.
--
-- Inherits asymptotic complexity from 'splitAt'.
splitAtEnd :: Int -> StrictSeq a -> (StrictSeq a, StrictSeq a)
splitAtEnd i xs
  | length xs >= i = splitAt (length xs - i) xs
  | otherwise = (Empty, xs)

-- | @'findIndexL' p xs@ finds the index of the leftmost element that
-- satisfies @p@, if any exist.
findIndexL :: (a -> Bool) -> StrictSeq a -> Maybe Int
findIndexL p (StrictSeq xs) = Seq.findIndexL p xs

-- | @'findIndexR' p xs@ finds the index of the rightmost element that
-- satisfies @p@, if any exist.
findIndexR :: (a -> Bool) -> StrictSeq a -> Maybe Int
findIndexR p (StrictSeq xs) = Seq.findIndexR p xs

-- | @'findIndicesL' p@ finds all indices of elements that satisfy @p@, in
-- ascending order.
findIndicesL :: (a -> Bool) -> StrictSeq a -> [Int]
findIndicesL p (StrictSeq xs) = Seq.findIndicesL p xs

-- | @'findIndicesR' p@ finds all indices of elements that satisfy @p@, in
-- descending order.
findIndicesR :: (a -> Bool) -> StrictSeq a -> [Int]
findIndicesR p (StrictSeq xs) = Seq.findIndicesR p xs

{-------------------------------------------------------------------------------
  Zips and Unzips
-------------------------------------------------------------------------------}

zip :: StrictSeq a -> StrictSeq b -> StrictSeq (a, b)
zip = zipWith (,)

zipWith :: (a -> b -> c) -> StrictSeq a -> StrictSeq b -> StrictSeq c
zipWith f (StrictSeq x) (StrictSeq y) = forceToStrict $ Seq.zipWith f x y

unzip :: StrictSeq (a, b) -> (StrictSeq a, StrictSeq b)
unzip = unzipWith id

unzipWith :: (a -> (b, c)) -> StrictSeq a -> (StrictSeq b, StrictSeq c)
unzipWith f (StrictSeq xs) = StrictSeq *** StrictSeq $ Seq.unzipWith f xs

{-------------------------------------------------------------------------------
  Helpers
-------------------------------------------------------------------------------}

toStrictSeqTuple :: (Seq a, Seq a) -> (StrictSeq a, StrictSeq a)
toStrictSeqTuple (a, b) = (StrictSeq a, StrictSeq b)
