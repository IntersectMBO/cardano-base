{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RankNTypes #-}

-- | Abstract digital signatures.
module Cardano.Crypto.DSIGNM.Class
  (
    -- * DSIGNMM algorithm class
    DSIGNMAlgorithmBase (..)
  , DSIGNMAlgorithm (..)
  , MLockedSeed
  , seedSizeDSIGNM
  , sizeVerKeyDSIGNM
  , sizeSignKeyDSIGNM
  , sizeSigDSIGNM
  , genKeyDSIGNM
  , cloneKeyDSIGNM
  , getSeedDSIGNM
  , forgetSignKeyDSIGNM

    -- * 'SignedDSIGNM' wrapper
  , SignedDSIGNM (..)
  , signedDSIGNM
  , verifySignedDSIGNM

    -- * CBOR encoding and decoding
  , encodeVerKeyDSIGNM
  , decodeVerKeyDSIGNM
  , encodeSigDSIGNM
  , decodeSigDSIGNM
  , encodeSignedDSIGNM
  , decodeSignedDSIGNM

    -- * Encoded 'Size' expresssions
  , encodedVerKeyDSIGNMSizeExpr
  , encodedSignKeyDSIGNMSizeExpr
  , encodedSigDSIGNMSizeExpr

    -- * Unsound API
  , UnsoundDSIGNMAlgorithm (..)
  , encodeSignKeyDSIGNM
  , decodeSignKeyDSIGNM
  , rawDeserialiseSignKeyDSIGNM
  )
where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Kind (Type)
import Data.Proxy (Proxy(..))
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack (HasCallStack)
import GHC.TypeLits (KnownNat, Nat, natVal, TypeError, ErrorMessage (..))
import NoThunks.Class (NoThunks)
import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow)

import Cardano.Binary (Decoder, decodeBytes, Encoding, encodeBytes, Size, withWordSize)

import Cardano.Crypto.Util (Empty)
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Libsodium (MLockedAllocator, mlockedMalloc)
import Cardano.Crypto.Hash.Class (HashAlgorithm, Hash, hashWith)

class ( Typeable v
      , Show (VerKeyDSIGNM v)
      , Eq (VerKeyDSIGNM v)
      , Show (SignKeyDSIGNM v)
      , Show (SigDSIGNM v)
      , Eq (SigDSIGNM v)
      , NoThunks (SigDSIGNM v)
      , NoThunks (SignKeyDSIGNM v)
      , NoThunks (VerKeyDSIGNM v)
      , KnownNat (SeedSizeDSIGNM v)
      , KnownNat (SizeVerKeyDSIGNM v)
      , KnownNat (SizeSignKeyDSIGNM v)
      , KnownNat (SizeSigDSIGNM v)
      )
      => DSIGNMAlgorithmBase v where

  type SeedSizeDSIGNM    v :: Nat
  type SizeVerKeyDSIGNM  v :: Nat
  type SizeSignKeyDSIGNM v :: Nat
  type SizeSigDSIGNM     v :: Nat

  --
  -- Key and signature types
  --

  data VerKeyDSIGNM  v :: Type
  data SignKeyDSIGNM v :: Type
  data SigDSIGNM     v :: Type

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGNM :: proxy v -> String

  hashVerKeyDSIGNM :: HashAlgorithm h => VerKeyDSIGNM v -> Hash h (VerKeyDSIGNM v)
  hashVerKeyDSIGNM = hashWith rawSerialiseVerKeyDSIGNM

  --
  -- Core algorithm operations
  --

  -- | Context required to run the DSIGNM algorithm
  --
  -- Unit by default (no context required)
  type ContextDSIGNM v :: Type
  type ContextDSIGNM v = ()

  type SignableM v :: Type -> Constraint
  type SignableM v = Empty

  verifyDSIGNM
    :: (SignableM v a, HasCallStack)
    => ContextDSIGNM v
    -> VerKeyDSIGNM v
    -> a
    -> SigDSIGNM v
    -> Either String ()

  --
  -- Serialisation/(de)serialisation in fixed-size raw format
  --

  rawSerialiseVerKeyDSIGNM    :: VerKeyDSIGNM v -> ByteString
  rawSerialiseSigDSIGNM       :: SigDSIGNM v -> ByteString

  rawDeserialiseVerKeyDSIGNM  :: ByteString -> Maybe (VerKeyDSIGNM v)
  rawDeserialiseSigDSIGNM     :: ByteString -> Maybe (SigDSIGNM v)

class DSIGNMAlgorithmBase v => DSIGNMAlgorithm v where

  --
  -- Metadata and basic key operations
  --

  deriveVerKeyDSIGNM :: (MonadThrow m, MonadST m) => SignKeyDSIGNM v -> m (VerKeyDSIGNM v)

  --
  -- Core algorithm operations
  --

  signDSIGNM
    :: (SignableM v a, MonadST m, MonadThrow m)
    => ContextDSIGNM v
    -> a
    -> SignKeyDSIGNM v
    -> m (SigDSIGNM v)

  --
  -- Key generation
  --

  genKeyDSIGNMWith :: (MonadST m, MonadThrow m)
                   => MLockedAllocator m
                   -> MLockedSeed (SeedSizeDSIGNM v)
                   -> m (SignKeyDSIGNM v)

  cloneKeyDSIGNMWith :: MonadST m => MLockedAllocator m -> SignKeyDSIGNM v -> m (SignKeyDSIGNM v)

  getSeedDSIGNMWith :: (MonadST m, MonadThrow m)
                    => MLockedAllocator m
                    -> Proxy v
                    -> SignKeyDSIGNM v
                    -> m (MLockedSeed (SeedSizeDSIGNM v))

  --
  -- Secure forgetting
  --

  forgetSignKeyDSIGNMWith :: (MonadST m, MonadThrow m) => MLockedAllocator m -> SignKeyDSIGNM v -> m ()


forgetSignKeyDSIGNM :: (DSIGNMAlgorithm v, MonadST m, MonadThrow m) => SignKeyDSIGNM v -> m ()
forgetSignKeyDSIGNM = forgetSignKeyDSIGNMWith mlockedMalloc


genKeyDSIGNM ::
     (DSIGNMAlgorithm v, MonadST m, MonadThrow m)
  => MLockedSeed (SeedSizeDSIGNM v)
  -> m (SignKeyDSIGNM v)
genKeyDSIGNM = genKeyDSIGNMWith mlockedMalloc

cloneKeyDSIGNM ::
  (DSIGNMAlgorithm v, MonadST m, MonadThrow m) => SignKeyDSIGNM v -> m (SignKeyDSIGNM v)
cloneKeyDSIGNM = cloneKeyDSIGNMWith mlockedMalloc

getSeedDSIGNM ::
     (DSIGNMAlgorithm v, MonadST m, MonadThrow m)
  => Proxy v
  -> SignKeyDSIGNM v
  -> m (MLockedSeed (SeedSizeDSIGNM v))
getSeedDSIGNM = getSeedDSIGNMWith mlockedMalloc


-- | Unsound operations on DSIGNM sign keys. These operations violate secure
-- forgetting constraints by leaking secrets to unprotected memory. Consider
-- using the 'DirectSerialise' / 'DirectDeserialise' APIs instead.
class DSIGNMAlgorithm v => UnsoundDSIGNMAlgorithm v where
  --
  -- Serialisation/(de)serialisation in fixed-size raw format
  --

  rawSerialiseSignKeyDSIGNM ::
    (MonadST m, MonadThrow m) => SignKeyDSIGNM v -> m ByteString

  rawDeserialiseSignKeyDSIGNMWith ::
    (MonadST m, MonadThrow m) => MLockedAllocator m -> ByteString -> m (Maybe (SignKeyDSIGNM v))

rawDeserialiseSignKeyDSIGNM ::
     (UnsoundDSIGNMAlgorithm v, MonadST m, MonadThrow m)
  => ByteString
  -> m (Maybe (SignKeyDSIGNM v))
rawDeserialiseSignKeyDSIGNM =
  rawDeserialiseSignKeyDSIGNMWith mlockedMalloc


--
-- Do not provide Ord instances for keys, see #38
--

instance ( TypeError ('Text "Ord not supported for signing keys, use the hash instead")
         , Eq (SignKeyDSIGNM v)
         )
      => Ord (SignKeyDSIGNM v) where
    compare = error "unsupported"

instance ( TypeError ('Text "Ord not supported for verification keys, use the hash instead")
         , Eq (VerKeyDSIGNM v)
         )
      => Ord (VerKeyDSIGNM v) where
    compare = error "unsupported"

-- | The upper bound on the seed size needed by 'genKeyDSIGNM'
seedSizeDSIGNM :: forall v proxy. DSIGNMAlgorithmBase v => proxy v -> Word
seedSizeDSIGNM _ = fromInteger (natVal (Proxy @(SeedSizeDSIGNM v)))

sizeVerKeyDSIGNM    :: forall v proxy. DSIGNMAlgorithmBase v => proxy v -> Word
sizeVerKeyDSIGNM  _ = fromInteger (natVal (Proxy @(SizeVerKeyDSIGNM v)))
sizeSignKeyDSIGNM   :: forall v proxy. DSIGNMAlgorithmBase v => proxy v -> Word
sizeSignKeyDSIGNM _ = fromInteger (natVal (Proxy @(SizeSignKeyDSIGNM v)))
sizeSigDSIGNM       :: forall v proxy. DSIGNMAlgorithmBase v => proxy v -> Word
sizeSigDSIGNM     _ = fromInteger (natVal (Proxy @(SizeSigDSIGNM v)))

--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeVerKeyDSIGNM :: DSIGNMAlgorithmBase v => VerKeyDSIGNM v -> Encoding
encodeVerKeyDSIGNM = encodeBytes . rawSerialiseVerKeyDSIGNM

encodeSignKeyDSIGNM ::
     (UnsoundDSIGNMAlgorithm v, MonadST m, MonadThrow m)
  => SignKeyDSIGNM v
  -> m Encoding
encodeSignKeyDSIGNM = fmap encodeBytes . rawSerialiseSignKeyDSIGNM

encodeSigDSIGNM :: DSIGNMAlgorithmBase v => SigDSIGNM v -> Encoding
encodeSigDSIGNM = encodeBytes . rawSerialiseSigDSIGNM

decodeVerKeyDSIGNM :: forall v s. DSIGNMAlgorithmBase v => Decoder s (VerKeyDSIGNM v)
decodeVerKeyDSIGNM = do
    bs <- decodeBytes
    case rawDeserialiseVerKeyDSIGNM bs of
      Just vk -> return vk
      Nothing
        | actual /= expected
                    -> fail ("decodeVerKeyDSIGNM: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeVerKeyDSIGNM: cannot decode key"
        where
          expected = fromIntegral (sizeVerKeyDSIGNM (Proxy :: Proxy v))
          actual   = BS.length bs

decodeSignKeyDSIGNM :: forall m v s
                     . (UnsoundDSIGNMAlgorithm v, MonadST m, MonadThrow m)
                    => Decoder s (m (SignKeyDSIGNM v))
decodeSignKeyDSIGNM = do
    bs <- decodeBytes
    return $ rawDeserialiseSignKeyDSIGNM bs >>= \case
      Just vk -> return vk
      Nothing
        | actual /= expected
                    -> error ("decodeSignKeyDSIGNM: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> error "decodeSignKeyDSIGNM: cannot decode key"
        where
          expected = fromIntegral (sizeSignKeyDSIGNM (Proxy :: Proxy v))
          actual   = BS.length bs

decodeSigDSIGNM :: forall v s. DSIGNMAlgorithmBase v => Decoder s (SigDSIGNM v)
decodeSigDSIGNM = do
    bs <- decodeBytes
    case rawDeserialiseSigDSIGNM bs of
      Just sig -> return sig
      Nothing
        | actual /= expected
                    -> fail ("decodeSigDSIGNM: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeSigDSIGNM: cannot decode signature"
        where
          expected = fromIntegral (sizeSigDSIGNM (Proxy :: Proxy v))
          actual   = BS.length bs


newtype SignedDSIGNM v a = SignedDSIGNM (SigDSIGNM v)
  deriving Generic

deriving instance DSIGNMAlgorithmBase v => Show (SignedDSIGNM v a)
deriving instance DSIGNMAlgorithmBase v => Eq   (SignedDSIGNM v a)

instance DSIGNMAlgorithmBase v => NoThunks (SignedDSIGNM v a)
  -- use generic instance

signedDSIGNM
  :: (DSIGNMAlgorithm v, SignableM v a, MonadST m, MonadThrow m)
  => ContextDSIGNM v
  -> a
  -> SignKeyDSIGNM v
  -> m (SignedDSIGNM v a)
signedDSIGNM ctxt a key = SignedDSIGNM <$> signDSIGNM ctxt a key

verifySignedDSIGNM
  :: (DSIGNMAlgorithmBase v, SignableM v a, HasCallStack)
  => ContextDSIGNM v
  -> VerKeyDSIGNM v
  -> a
  -> SignedDSIGNM v a
  -> Either String ()
verifySignedDSIGNM ctxt key a (SignedDSIGNM s) = verifyDSIGNM ctxt key a s

encodeSignedDSIGNM :: DSIGNMAlgorithmBase v => SignedDSIGNM v a -> Encoding
encodeSignedDSIGNM (SignedDSIGNM s) = encodeSigDSIGNM s

decodeSignedDSIGNM :: DSIGNMAlgorithmBase v => Decoder s (SignedDSIGNM v a)
decodeSignedDSIGNM = SignedDSIGNM <$> decodeSigDSIGNM

--
-- Encoded 'Size' expressions for 'ToCBOR' instances
--

-- | 'Size' expression for 'VerKeyDSIGNM' which is using 'sizeVerKeyDSIGNM'
-- encoded as 'Size'.
--
encodedVerKeyDSIGNMSizeExpr :: forall v. DSIGNMAlgorithmBase v => Proxy (VerKeyDSIGNM v) -> Size
encodedVerKeyDSIGNMSizeExpr _proxy =
      -- 'encodeBytes' envelope
      fromIntegral ((withWordSize :: Word -> Integer) (sizeVerKeyDSIGNM (Proxy :: Proxy v)))
      -- payload
    + fromIntegral (sizeVerKeyDSIGNM (Proxy :: Proxy v))

-- | 'Size' expression for 'SignKeyDSIGNM' which is using 'sizeSignKeyDSIGNM'
-- encoded as 'Size'.
--
encodedSignKeyDSIGNMSizeExpr :: forall v. DSIGNMAlgorithmBase v => Proxy (SignKeyDSIGNM v) -> Size
encodedSignKeyDSIGNMSizeExpr _proxy =
      -- 'encodeBytes' envelope
      fromIntegral ((withWordSize :: Word -> Integer) (sizeSignKeyDSIGNM (Proxy :: Proxy v)))
      -- payload
    + fromIntegral (sizeSignKeyDSIGNM (Proxy :: Proxy v))

-- | 'Size' expression for 'SigDSIGNM' which is using 'sizeSigDSIGNM' encoded as
-- 'Size'.
--
encodedSigDSIGNMSizeExpr :: forall v. DSIGNMAlgorithmBase v => Proxy (SigDSIGNM v) -> Size
encodedSigDSIGNMSizeExpr _proxy =
      -- 'encodeBytes' envelope
      fromIntegral ((withWordSize :: Word -> Integer) (sizeSigDSIGNM (Proxy :: Proxy v)))
      -- payload
    + fromIntegral (sizeSigDSIGNM (Proxy :: Proxy v))
