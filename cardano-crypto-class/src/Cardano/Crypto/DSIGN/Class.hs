{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract digital signatures.
module Cardano.Crypto.DSIGN.Class
  ( DSIGNAlgorithm (..)
  , SignedDSIGN (..)
  , signedDSIGN
  , verifySignedDSIGN
  , encodeSignedDSIGN
  , decodeSignedDSIGN
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
import Numeric.Natural

class ( Typeable v
      , Show (VerKeyDSIGN v)
      , Eq (VerKeyDSIGN v)
      , Show (SignKeyDSIGN v)
      , Show (SigDSIGN v)
      , Eq (SigDSIGN v)
      , NoUnexpectedThunks (SigDSIGN     v)
      , NoUnexpectedThunks (SignKeyDSIGN v)
      , NoUnexpectedThunks (VerKeyDSIGN  v)
      )
      => DSIGNAlgorithm v where

  data VerKeyDSIGN v :: Type

  data SignKeyDSIGN v :: Type

  data SigDSIGN v :: Type

  type Signable v :: Type -> Constraint
  type Signable v = Empty


  -- | Abstract sizes for verification keys and signatures, specifies an upper
  -- bound on the real byte sizes.
  abstractSizeVKey :: proxy v -> Natural
  abstractSizeSig  :: proxy v -> Natural

  -- | Context required to run the DSIGN algorithm
  --
  -- Unit by default (no context required)
  type ContextDSIGN v :: Type
  type ContextDSIGN v = ()

  encodeVerKeyDSIGN :: VerKeyDSIGN v -> Encoding

  encodeSignKeyDSIGN :: SignKeyDSIGN v -> Encoding

  encodeSigDSIGN :: SigDSIGN v -> Encoding

  decodeVerKeyDSIGN :: Decoder s (VerKeyDSIGN v)

  decodeSignKeyDSIGN :: Decoder s (SignKeyDSIGN v)

  decodeSigDSIGN :: Decoder s (SigDSIGN v)

  genKeyDSIGN :: MonadRandom m => m (SignKeyDSIGN v)

  deriveVerKeyDSIGN :: SignKeyDSIGN v -> VerKeyDSIGN v

  signDSIGN
    :: (Signable v a, HasCallStack)
    => ContextDSIGN v
    -> a
    -> SignKeyDSIGN v
    -> SigDSIGN v

  verifyDSIGN
    :: (Signable v a, HasCallStack)
    => ContextDSIGN v
    -> VerKeyDSIGN v
    -> a
    -> SigDSIGN v
    -> Either String ()

newtype SignedDSIGN v a = SignedDSIGN (SigDSIGN v)
  deriving Generic

deriving instance DSIGNAlgorithm v => Show (SignedDSIGN v a)
deriving instance DSIGNAlgorithm v => Eq   (SignedDSIGN v a)

instance DSIGNAlgorithm v => NoUnexpectedThunks (SignedDSIGN v a)
  -- use generic instance

signedDSIGN
  :: (DSIGNAlgorithm v, Signable v a)
  => ContextDSIGN v
  -> a
  -> SignKeyDSIGN v
  -> SignedDSIGN v a
signedDSIGN ctxt a key = SignedDSIGN (signDSIGN ctxt a key)

verifySignedDSIGN
  :: (DSIGNAlgorithm v, Signable v a, HasCallStack)
  => ContextDSIGN v
  -> VerKeyDSIGN v
  -> a
  -> SignedDSIGN v a
  -> Either String ()
verifySignedDSIGN ctxt key a (SignedDSIGN s) = verifyDSIGN ctxt key a s

encodeSignedDSIGN :: DSIGNAlgorithm v => SignedDSIGN v a -> Encoding
encodeSignedDSIGN (SignedDSIGN s) = encodeSigDSIGN s

decodeSignedDSIGN :: DSIGNAlgorithm v => Decoder s (SignedDSIGN v a)
decodeSignedDSIGN = SignedDSIGN <$> decodeSigDSIGN
