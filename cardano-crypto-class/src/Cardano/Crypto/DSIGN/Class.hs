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

class ( Typeable v
      , Show (VerKeyDSIGN v)
      , Eq (VerKeyDSIGN v)
      , Show (SignKeyDSIGN v)
      , Show (SigDSIGN v)
      , Eq (SigDSIGN v)
      , NoUnexpectedThunks (SigDSIGN v)
      , NoUnexpectedThunks (VerKeyDSIGN v)
      )
      => DSIGNAlgorithm v where

  data VerKeyDSIGN v :: Type

  data SignKeyDSIGN v :: Type

  data SigDSIGN v :: Type

  type Signable v :: Type -> Constraint

  type Signable c = Empty

  encodeVerKeyDSIGN :: VerKeyDSIGN v -> Encoding

  encodeSignKeyDSIGN :: SignKeyDSIGN v -> Encoding

  encodeSigDSIGN :: SigDSIGN v -> Encoding

  decodeVerKeyDSIGN :: Decoder s (VerKeyDSIGN v)

  decodeSignKeyDSIGN :: Decoder s (SignKeyDSIGN v)

  decodeSigDSIGN :: Decoder s (SigDSIGN v)

  genKeyDSIGN :: MonadRandom m => m (SignKeyDSIGN v)

  deriveVerKeyDSIGN :: SignKeyDSIGN v -> VerKeyDSIGN v

  signDSIGN
    :: (MonadRandom m, Signable v a, HasCallStack)
    => a
    -> SignKeyDSIGN v
    -> m (SigDSIGN v)

  verifyDSIGN
    :: (Signable v a, HasCallStack)
    => VerKeyDSIGN v
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
  :: (DSIGNAlgorithm v, MonadRandom m, Signable v a)
  => a
  -> SignKeyDSIGN v
  -> m (SignedDSIGN v a)
signedDSIGN a key = SignedDSIGN <$> signDSIGN a key

verifySignedDSIGN
  :: (DSIGNAlgorithm v, Signable v a, HasCallStack)
  => VerKeyDSIGN v
  -> a
  -> SignedDSIGN v a
  -> Either String ()
verifySignedDSIGN key a (SignedDSIGN s) = verifyDSIGN key a s

encodeSignedDSIGN :: DSIGNAlgorithm v => SignedDSIGN v a -> Encoding
encodeSignedDSIGN (SignedDSIGN s) = encodeSigDSIGN s

decodeSignedDSIGN :: DSIGNAlgorithm v => Decoder s (SignedDSIGN v a)
decodeSignedDSIGN = SignedDSIGN <$> decodeSigDSIGN
