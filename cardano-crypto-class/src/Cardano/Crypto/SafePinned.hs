{-#LANGUAGE DerivingVia #-}
{-#LANGUAGE GeneralizedNewtypeDeriving #-}
module Cardano.Crypto.SafePinned
( SafePinned
, makeSafePinned
, releaseSafePinned
, interactSafePinned
, mapSafePinned
, Release (..)
)
where

import Control.Concurrent.MVar
import Control.Exception (Exception, throw)
import Control.DeepSeq (NFData (..))
import NoThunks.Class (NoThunks, OnlyCheckWhnf (..))
import Control.Monad.IO.Class (MonadIO, liftIO)
import Cardano.Crypto.Libsodium.MLockedBytes

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

makeSafePinned :: MonadIO m => a -> m (SafePinned a)
makeSafePinned val = SafePinned <$> liftIO (newMVar val)

mapSafePinned :: MonadIO m => (a -> m b) -> SafePinned a -> m (SafePinned b)
mapSafePinned f p =
  interactSafePinned p f >>= makeSafePinned

releaseSafePinned :: (MonadIO m, Release a) => SafePinned a -> m ()
releaseSafePinned sp = do
  mval <- liftIO $ tryTakeMVar (safePinnedMVar sp)
  maybe (return ()) (liftIO . release) mval

interactSafePinned :: MonadIO m => SafePinned a -> (a -> m b) -> m b
interactSafePinned (SafePinned var) action = do
  mval <- liftIO (tryTakeMVar var)
  case mval of
    Just val -> do
      result <- action val
      result `seq` liftIO (putMVar var val)
      return result
    Nothing -> do
      throw SafePinnedFinalizedError

-- If it's fine by Kmett & Marlow, ...
-- https://github.com/haskell/deepseq/issues/6
instance NFData (SafePinned a) where
  rnf x = x `seq` ()
