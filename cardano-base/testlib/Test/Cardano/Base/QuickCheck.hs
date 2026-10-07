{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Cardano.Base.QuickCheck (
  withNumTests,
  testLawsGroup,
)
where

-- QuickCheck 2.18 replaces `withMaxSuccess` with `withNumTests` and
-- immediately deprecates the former.
-- We handle this for the whole Cardano stack here. Any other code
-- that uses withMaxSuccess should import this module or switch to
-- using withNumTests.
--
#if MIN_VERSION_QuickCheck(2, 18, 0)
import Test.QuickCheck (withNumTests)
import Data.Proxy (Proxy (Proxy))
import Test.Hspec (Spec, describe)
import Test.QuickCheck.Classes (Laws (Laws, lawsTypeclass, lawsProperties))
import Data.Foldable (traverse_)
import Test.Hspec.QuickCheck (prop)
#else
import Test.QuickCheck (
    Property,
    Testable,
    withMaxSuccess,
  )
#endif

#if !MIN_VERSION_QuickCheck(2, 18, 0)
withNumTests :: Testable prop => Int -> prop -> Property
withNumTests = withMaxSuccess
#endif

-- | Check the typeclass `Laws` of a type, one example per law:
--
-- > describe "Semigroup and Monoid" $
-- >   testLawsGroup @ValidityInterval
-- >     [ semigroupLaws
-- >     , monoidLaws
-- >     ]
--
-- This should be used instead of `Test.QuickCheck.Classes.lawsCheckOne`, which
-- reports through `Test.QuickCheck.quickCheck`. That writes straight to stdout,
-- thus it is not properly indented in the test console output. It also discards
-- the QuickCheck `Result`, which means that a violated law does not fail the
-- test suite.
testLawsGroup :: forall a. [Proxy a -> Laws] -> Spec
testLawsGroup =
  traverse_ $ \mkLaws -> do
    let Laws {..} = mkLaws (Proxy @a)
    describe lawsTypeclass $ traverse_ (uncurry prop) lawsProperties
