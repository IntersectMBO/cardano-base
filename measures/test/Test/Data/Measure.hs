{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Test.Data.Measure (
  tests,
)
where

import GHC.Natural
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import qualified Data.Measure as M

tests :: Spec
tests =
  describe "Data.Measure" $ do
    prop "uncurry (++) undoes splitAt" prop_idAppendSplitAt
    prop "take and drop agrees with splitAt" prop_eqTakeDropSplitAt

--------------------------------------------------------------------------------
-- A nice measure to run tests with
--------------------------------------------------------------------------------

newtype Item = Item Natural
  deriving (Eq, M.Measure, Show)

integerToItem :: Integer -> Item
integerToItem = Item . naturalFromInteger . abs

itemToInteger :: Item -> Integer
itemToInteger (Item n) = naturalToInteger n

instance Arbitrary Item where
  arbitrary = fmap (integerToItem . getSmall) arbitrary
  shrink =
    fmap (integerToItem . getSmall)
      . filter (>= 0)
      . shrink
      . Small
      . itemToInteger

--------------------------------------------------------------------------------
-- Required properties
--------------------------------------------------------------------------------

-- | @uncurry (++)@ undoes 'M.splitAt'
prop_idAppendSplitAt :: Item -> [Item] -> Property
prop_idAppendSplitAt limit es =
  l ++ r === es
  where
    (l, r) = M.splitAt id limit es

-- | 'M.take' and 'M.drop' are the components of 'M.splitAt'
prop_eqTakeDropSplitAt :: Item -> [Item] -> Property
prop_eqTakeDropSplitAt limit es =
  (M.take id limit es, M.drop id limit es)
    === M.splitAt id limit es
