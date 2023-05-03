{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
module Cardano.Crypto.MEqOrd where

import Control.Monad.Class.MonadST (MonadST)

-- | Monadic flavor of 'Eq', for things that can only be compared in a monadic
-- context.
-- This is needed because we cannot have a sound 'Eq' instance on mlocked
-- memory types.
class MEq a where
  equalsM :: MonadST m => a -> a -> m Bool

nequalsM :: (MonadST m, MEq a) => a -> a -> m Bool
nequalsM a b = not <$> equalsM a b

-- | Infix version of 'equalsM'
(==!) :: (MonadST m, MEq a) => a -> a -> m Bool
(==!) = equalsM
infix 4 ==!

-- | Infix version of 'nequalsM'
(!=!) :: (MonadST m, MEq a) => a -> a -> m Bool
(!=!) = nequalsM
infix 4 !=!

instance MEq a => MEq (Maybe a) where
  equalsM Nothing Nothing = pure True
  equalsM (Just a) (Just b) = equalsM a b
  equalsM _ _ = pure False

instance (MEq a, MEq b) => MEq (Either a b) where
  equalsM (Left x) (Left y) = equalsM x y
  equalsM (Right x) (Right y) = equalsM x y
  equalsM _ _ = pure False

instance (MEq a, MEq b) => MEq (a, b) where
  equalsM (a, b) (a', b') = (&&) <$> equalsM a a' <*> equalsM b b'

instance (MEq a, MEq b, MEq c) => MEq (a, b, c) where
  equalsM (a, b, c) (a', b', c') = equalsM ((a, b), c) ((a', b'), c')

instance (MEq a, MEq b, MEq c, MEq d) => MEq (a, b, c, d) where
  equalsM (a, b, c, d) (a', b', c', d') = equalsM ((a, b, c), d) ((a', b', c'), d')

-- TODO: If anyone needs larger tuples, add more instances here...

-- | Helper newtype, useful for defining 'MEq' in terms of 'Eq' for types that
-- have sound 'Eq' instances, using @DerivingVia@. An 'Applicative' context
-- must be provided for such instances to work, so this will generally require
-- @StandaloneDeriving@ as well.
--
-- Ex.: @deriving via PureEq Int instance Applicative m => MEq m Int@
newtype PureMEq a = PureMEq a

instance Eq a => MEq (PureMEq a) where
  equalsM (PureMEq a) (PureMEq b) = pure (a == b)
