{-# LANGUAGE RankNTypes #-}

module Test.Utils (
    monadicSim
  , runSimGen
  ) where

import           Control.Monad.IOSim (IOSim, runSimOrThrow)
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
