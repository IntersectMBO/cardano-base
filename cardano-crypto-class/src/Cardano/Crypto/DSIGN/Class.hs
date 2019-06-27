{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE PolyKinds #-}
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
import Crypto.Random (MonadRandom)
import Data.Kind (Type)
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack

class ( Typeable v
      , Show (VerKeyDSIGN v)
      , Ord (VerKeyDSIGN v)
      , Show (SignKeyDSIGN v)
      , Ord (SignKeyDSIGN v)
      , Show (SigDSIGN v)
      , Ord (SigDSIGN v)
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
    => (a -> Encoding)
    -> a
    -> SignKeyDSIGN v
    -> m (SigDSIGN v)

  verifyDSIGN
    :: (Signable v a, HasCallStack)
    => (a -> Encoding)
    -> VerKeyDSIGN v
    -> a
    -> SigDSIGN v
    -> Either String ()

newtype SignedDSIGN v a = SignedDSIGN (SigDSIGN v)
  deriving Generic

deriving instance DSIGNAlgorithm v => Show (SignedDSIGN v a)

deriving instance DSIGNAlgorithm v => Eq (SignedDSIGN v a)

deriving instance DSIGNAlgorithm v => Ord (SignedDSIGN v a)

signedDSIGN
  :: (DSIGNAlgorithm v, MonadRandom m, Signable v a)
  => (a -> Encoding)
  -> a
  -> SignKeyDSIGN v
  -> m (SignedDSIGN v a)
signedDSIGN encoder a key = SignedDSIGN <$> signDSIGN encoder a key

verifySignedDSIGN
  :: (DSIGNAlgorithm v, Signable v a, HasCallStack)
  => (a -> Encoding)
  -> VerKeyDSIGN v
  -> a
  -> SignedDSIGN v a
  -> Either String ()
verifySignedDSIGN encoder key a (SignedDSIGN s) = verifyDSIGN encoder key a s

encodeSignedDSIGN :: DSIGNAlgorithm v => SignedDSIGN v a -> Encoding
encodeSignedDSIGN (SignedDSIGN s) = encodeSigDSIGN s

decodeSignedDSIGN :: DSIGNAlgorithm v => Decoder s (SignedDSIGN v a)
decodeSignedDSIGN = SignedDSIGN <$> decodeSigDSIGN
