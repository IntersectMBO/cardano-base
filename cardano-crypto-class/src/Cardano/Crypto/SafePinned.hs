{-#LANGUAGE DerivingVia #-}
{-#LANGUAGE GeneralizedNewtypeDeriving #-}
module Cardano.Crypto.SafePinned
( SafePinned
, makeSafePinned
, releaseSafePinned
, interactSafePinned
, Release (..)
)
where

import Control.Concurrent.MVar
import Cardano.Crypto.PinnedSizedBytes
import Cardano.Crypto.Libsodium.MLockedBytes
import Control.Exception (Exception, throw)
import Control.DeepSeq (NFData (..))
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, OnlyCheckWhnf (..))


data SafePinnedFinalizedError = SafePinnedFinalizedError
  deriving (Show)

instance Exception SafePinnedFinalizedError

class Release a where
  release :: a -> IO ()

instance Release (MLockedSizedBytes a) where
  release = mlsbFinalize

newtype SafePinned a =
  SafePinned { safePinnedMVar :: MVar a }
  deriving NoThunks via OnlyCheckWhnf (MVar a)

makeSafePinned :: a -> IO (SafePinned a)
makeSafePinned val = SafePinned <$> newMVar val

releaseSafePinned :: Release a => SafePinned a -> IO ()
releaseSafePinned (SafePinned var) = do
  mval <- tryTakeMVar var
  maybe (return ()) release mval

interactSafePinned :: SafePinned a -> (a -> IO b) -> IO b
interactSafePinned (SafePinned var) action = do
  mval <- tryTakeMVar var
  case mval of
    Just val -> do
      result <- action val
      result `seq` putMVar var val
      return result
    Nothing -> do
      throw SafePinnedFinalizedError

-- If it's fine by Kmett & Marlow, ...
-- https://github.com/haskell/deepseq/issues/6
instance NFData (SafePinned a) where
  rnf x = x `seq` ()
