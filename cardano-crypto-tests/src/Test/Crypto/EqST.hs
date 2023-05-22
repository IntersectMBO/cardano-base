{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE StandaloneDeriving #-}

module Test.Crypto.EqST where

import GHC.TypeLits (KnownNat)
import qualified Data.Vector as Vec
import Control.Monad.Class.MonadST (MonadST)

import Cardano.Crypto.Libsodium.MLockedBytes.Internal
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.DSIGN.Ed25519ML
import Cardano.Crypto.DSIGNM.Class
import Cardano.Crypto.KES.Simple

-- | Monadic flavor of 'Eq', for things that can only be compared in a monadic
-- context that satisfies 'MonadST'.
-- This is needed because we cannot have a sound 'Eq' instance on mlocked
-- memory types, but we do need to compare them for equality in tests.
class EqST a where
  equalsM :: MonadST m => a -> a -> m Bool

nequalsM :: (MonadST m, EqST a) => a -> a -> m Bool
nequalsM a b = not <$> equalsM a b

-- | Infix version of 'equalsM'
(==!) :: (MonadST m, EqST a) => a -> a -> m Bool
(==!) = equalsM
infix 4 ==!

-- | Infix version of 'nequalsM'
(!=!) :: (MonadST m, EqST a) => a -> a -> m Bool
(!=!) = nequalsM
infix 4 !=!

instance EqST a => EqST (Maybe a) where
  equalsM Nothing Nothing = pure True
  equalsM (Just a) (Just b) = equalsM a b
  equalsM _ _ = pure False

instance (EqST a, EqST b) => EqST (Either a b) where
  equalsM (Left x) (Left y) = equalsM x y
  equalsM (Right x) (Right y) = equalsM x y
  equalsM _ _ = pure False

instance (EqST a, EqST b) => EqST (a, b) where
  equalsM (a, b) (a', b') = (&&) <$> equalsM a a' <*> equalsM b b'

instance (EqST a, EqST b, EqST c) => EqST (a, b, c) where
  equalsM (a, b, c) (a', b', c') = equalsM ((a, b), c) ((a', b'), c')

instance (EqST a, EqST b, EqST c, EqST d) => EqST (a, b, c, d) where
  equalsM (a, b, c, d) (a', b', c', d') = equalsM ((a, b, c), d) ((a', b', c'), d')

-- TODO: If anyone needs larger tuples, add more instances here...

-- | Helper newtype, useful for defining 'EqST' in terms of 'Eq' for types that
-- have sound 'Eq' instances, using @DerivingVia@. An 'Applicative' context
-- must be provided for such instances to work, so this will generally require
-- @StandaloneDeriving@ as well.
--
-- Ex.: @deriving via PureEq Int instance Applicative m => EqST m Int@
newtype PureEqST a = PureEqST a

instance Eq a => EqST (PureEqST a) where
  equalsM (PureEqST a) (PureEqST b) = pure (a == b)

instance KnownNat n => EqST (MLockedSizedBytes n) where
  equalsM = mlsbEq

deriving via
  MLockedSizedBytes n
  instance
    KnownNat n => EqST (MLockedSeed n)

deriving via (MLockedSizedBytes (SizeSignKeyDSIGNM Ed25519DSIGNM))
  instance EqST (SignKeyDSIGNM Ed25519DSIGNM)

instance EqST (SignKeyDSIGNM d) => EqST (SignKeyKES (SimpleKES d t)) where
  equalsM (ThunkySignKeySimpleKES a) (ThunkySignKeySimpleKES b) =
    -- No need to check that lengths agree, the types already guarantee this.
    Vec.and <$> Vec.zipWithM equalsM a b
