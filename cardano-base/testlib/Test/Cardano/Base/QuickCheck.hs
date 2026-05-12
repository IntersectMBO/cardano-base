{-# LANGUAGE CPP #-}

module Test.Cardano.Base.QuickCheck (
  withNumTests,
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
#else
import Test.QuickCheck (
    Property,
    withMaxSuccess,
  )
#endif

#if !MIN_VERSION_QuickCheck(2, 18, 0)
withNumTests :: Int -> Property -> Property
withNumTests = withMaxSuccess
#endif
