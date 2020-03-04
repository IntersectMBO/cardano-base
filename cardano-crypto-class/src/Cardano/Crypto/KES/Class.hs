{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract key evolving signatures.
module Cardano.Crypto.KES.Class
  ( KESAlgorithm (..)
  , SignedKES (..)
  , signedKES
  , verifySignedKES
  , encodeSignedKES
  , decodeSignedKES
  )
where

import Cardano.Binary (Decoder, Encoding)
import Cardano.Crypto.Util (Empty)
import Cardano.Prelude (NoUnexpectedThunks)
import Crypto.Random (MonadRandom)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import Numeric.Natural (Natural)

class ( Typeable v
      , Show (VerKeyKES v)
      , Eq (VerKeyKES v)
      , Show (SignKeyKES v)
      , Show (SigKES v)
      , Eq (SigKES v)
      , NoUnexpectedThunks (SigKES     v)
      , NoUnexpectedThunks (SignKeyKES v)
      , NoUnexpectedThunks (VerKeyKES  v)
      )
      => KESAlgorithm v where

  data VerKeyKES v :: Type

  data SignKeyKES v :: Type

  data SigKES v :: Type

  type Signable v :: Type -> Constraint
  type Signable v = Empty

  -- | Context required to run the KES algorithm
  --
  -- Unit by default (no context required)
  type ContextKES v :: Type
  type ContextKES v = ()

  encodeVerKeyKES :: VerKeyKES v -> Encoding

  encodeSignKeyKES :: SignKeyKES v -> Encoding

  encodeSigKES :: SigKES v -> Encoding

  decodeVerKeyKES :: Decoder s (VerKeyKES v)

  decodeSignKeyKES :: Decoder s (SignKeyKES v)

  decodeSigKES :: Decoder s (SigKES v)

  genKeyKES :: MonadRandom m => Natural -> m (SignKeyKES v)

  deriveVerKeyKES :: SignKeyKES v -> VerKeyKES v

  updateKES
    :: (MonadRandom m, HasCallStack)
    => ContextKES v
    -> SignKeyKES v
    -> m (Maybe (SignKeyKES v))

  signKES
    :: (MonadRandom m, Signable v a, HasCallStack)
    => ContextKES v
    -> Natural
    -> a
    -> SignKeyKES v
    -> m (Maybe (SigKES v))

  verifyKES
    :: (Signable v a, HasCallStack)
    => ContextKES v
    -> VerKeyKES v
    -> Natural
    -> a
    -> SigKES v
    -> Either String ()

  -- | Return the number of times a KES signature key has been updated.
  iterationCountKES
    :: HasCallStack
    => ContextKES v
    -> SignKeyKES v
    -> Natural

newtype SignedKES v a = SignedKES {getSig :: SigKES v}
  deriving Generic

deriving instance KESAlgorithm v => Show (SignedKES v a)
deriving instance KESAlgorithm v => Eq   (SignedKES v a)

instance KESAlgorithm v => NoUnexpectedThunks (SignedKES v a)
  -- use generic instance

signedKES
  :: (KESAlgorithm v, MonadRandom m, Signable v a)
  => ContextKES v
  -> Natural
  -> a
  -> SignKeyKES v
  -> m (Maybe (SignedKES v a))
signedKES ctxt time a key = do
  m <- signKES ctxt time a key
  return $ case m of
    Nothing          -> Nothing
    Just sig -> Just (SignedKES sig)

verifySignedKES
  :: (KESAlgorithm v, Signable v a)
  => ContextKES v
  -> VerKeyKES v
  -> Natural
  -> a
  -> SignedKES v a
  -> Either String ()
verifySignedKES ctxt vk j a (SignedKES sig) = verifyKES ctxt vk j a sig

encodeSignedKES :: KESAlgorithm v => SignedKES v a -> Encoding
encodeSignedKES (SignedKES s) = encodeSigKES s

decodeSignedKES :: KESAlgorithm v => Decoder s (SignedKES v a)
decodeSignedKES = SignedKES <$> decodeSigKES
