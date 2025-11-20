{-# LANGUAGE RankNTypes #-}

-- | Wrapper for Data.Proxy, plus convenience functions
module Cardano.Base.Proxy (
  module X,
  asProxy,
) where

import Data.Proxy as X

asProxy :: forall a. a -> Proxy a
asProxy _ = Proxy
