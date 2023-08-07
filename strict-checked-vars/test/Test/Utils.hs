{-# LANGUAGE RankNTypes #-}

module Test.Utils (
    -- * Property runners
    monadicSim
  , runSimGen
    -- * Function composition
  , (..:)
    -- * Invariants
  , Invariant (..)
  , noInvariant
  , trivialInvariant
  , whnfInvariant
  ) where

import           Control.Monad.IOSim (IOSim, runSimOrThrow)
import           Data.Typeable (Typeable)
import           NoThunks.Class (OnlyCheckWhnf (..), unsafeNoThunks)
import           Test.QuickCheck (Gen, Property, Testable (..))
import           Test.QuickCheck.Gen.Unsafe (Capture (..), capture)
import           Test.QuickCheck.Monadic (PropertyM, monadic')

{-------------------------------------------------------------------------------
  Property runners (copied from "Ouroboros.Network.Testing.QuickCheck")
-------------------------------------------------------------------------------}

runSimGen :: (forall s. Gen (IOSim s a)) -> Gen a
runSimGen f = do
    Capture eval <- capture
    return $ runSimOrThrow (eval f)

monadicSim :: Testable a => (forall s. PropertyM (IOSim s) a) -> Property
monadicSim m = property (runSimGen (monadic' m))

{-------------------------------------------------------------------------------
  Function composition
-------------------------------------------------------------------------------}

infixr 9 ..:

(..:) :: (y -> z) -> (x0 -> x1 -> x2 -> y) -> (x0 -> x1 -> x2 -> z)
(..:) g f x0 x1 x2 = g (f x0 x1 x2)

{-------------------------------------------------------------------------------
  Invariants
-------------------------------------------------------------------------------}

-- | Invariants
--
-- Testing with @'Invariant' (const Nothing)'@ /should/ be the same as testing
-- with 'NoInvariant'.
data Invariant a =
    NoInvariant
  | Invariant (a -> Maybe String)

noInvariant :: Invariant a
noInvariant = NoInvariant

whnfInvariant :: Typeable a => Invariant a
whnfInvariant = Invariant $ fmap show . unsafeNoThunks . OnlyCheckWhnf

trivialInvariant :: Invariant a
trivialInvariant = Invariant $ const Nothing
