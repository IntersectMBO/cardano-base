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
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (Empty)
import Cardano.Prelude (NoUnexpectedThunks)
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

  genKeyKES :: Seed -> Natural -> SignKeyKES v

  -- | The upper bound on the 'Seed' size needed by 'genKeyKES'
  seedSizeKES :: proxy v -> Natural -> Natural

  deriveVerKeyKES :: SignKeyKES v -> VerKeyKES v

  -- | Update the KES signature key to the specified period. The intended
  -- behavior is to return `Nothing` in the case that the key cannot be evolved
  -- that far.
  --
  -- The precondition is that the current KES period of the input key is before
  -- the target period.
  -- The postcondition is that in case a key is returned, its current KES period
  -- corresponds to the target KES period.
  updateKES
    :: HasCallStack
    => ContextKES v
    -> SignKeyKES v
    -> Natural
    -> Maybe (SignKeyKES v)

  signKES
    :: (Signable v a, HasCallStack)
    => ContextKES v
    -> Natural
    -> a
    -> SignKeyKES v
    -> Maybe (SigKES v)

  verifyKES
    :: (Signable v a, HasCallStack)
    => ContextKES v
    -> VerKeyKES v
    -> Natural
    -> a
    -> SigKES v
    -> Either String ()

  -- | Return the current KES period of a KES signing key.
  currentPeriodKES
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
  :: (KESAlgorithm v, Signable v a)
  => ContextKES v
  -> Natural
  -> a
  -> SignKeyKES v
  -> Maybe (SignedKES v a)
signedKES ctxt time a key = SignedKES <$> signKES ctxt time a key

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
