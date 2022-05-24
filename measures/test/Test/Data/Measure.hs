{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Test.Data.Measure
  ( tests,
  )
where

import qualified Data.Measure as M
import GHC.Natural
import Test.Tasty
import Test.Tasty.QuickCheck

tests :: TestTree
tests =
  testGroup
    "Data.Measure"
    [ testProperty "uncurry (++) undoes splitAt" prop_idAppendSplitAt,
      testProperty "take and drop agrees with splitAt" prop_eqTakeDropSplitAt
    ]

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
