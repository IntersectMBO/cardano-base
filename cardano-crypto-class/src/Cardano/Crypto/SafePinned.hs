{-#LANGUAGE DerivingVia #-}
{-#LANGUAGE MultiParamTypeClasses #-}
{-#LANGUAGE GeneralizedNewtypeDeriving #-}
{-#LANGUAGE FlexibleInstances #-}
module Cardano.Crypto.SafePinned
( SafePinned
, makeSafePinned
, releaseSafePinned
, interactSafePinned
, mapSafePinned
, Release (..)
)
where

import Control.Monad.Class.MonadMVar
import Control.Exception (Exception, throw)
import Control.DeepSeq (NFData (..))
import NoThunks.Class (NoThunks, OnlyCheckWhnf (..))
import Cardano.Crypto.MonadSodium

data SafePinnedFinalizedError = SafePinnedFinalizedError
  deriving (Show)

instance Exception SafePinnedFinalizedError

class Release m a where
  release :: a -> m ()

instance MonadSodium m => Release m (MLockedSizedBytes a) where
  release = mlsbFinalize

newtype SafePinned m a =
  SafePinned { safePinnedMVar :: MVar m a }
  deriving NoThunks via OnlyCheckWhnf (MVar m a)

makeSafePinned :: MonadMVar m => a -> m (SafePinned m a)
makeSafePinned val = SafePinned <$> newMVar val

mapSafePinned :: MonadMVar m => (a -> m b) -> SafePinned m a -> m (SafePinned m b)
mapSafePinned f p =
  interactSafePinned p f >>= makeSafePinned

releaseSafePinned :: (MonadMVar m, Release m a) => SafePinned m a -> m ()
releaseSafePinned sp = do
  mval <- tryTakeMVar (safePinnedMVar sp)
  maybe (return ()) release mval

interactSafePinned :: MonadMVar m => SafePinned m a -> (a -> m b) -> m b
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
instance NFData (SafePinned m a) where
  rnf x = x `seq` ()
