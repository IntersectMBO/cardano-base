module Test.Crypto.RunIO
where

import Control.Monad.Identity

class RunIO m where
  io :: m a -> IO a

instance RunIO IO where
  io = id

instance RunIO Identity where
  io = return . runIdentity
