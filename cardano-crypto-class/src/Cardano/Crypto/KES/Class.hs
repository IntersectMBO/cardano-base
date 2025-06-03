{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Abstract key evolving signatures.
module Cardano.Crypto.KES.Class (
  -- * KES algorithm class
  KESAlgorithm (..),
  genKeyKES,
  updateKES,
  forgetSignKeyKES,
  Period,
  OptimizedKESAlgorithm (..),
  verifyOptimizedKES,

  -- * 'SignKeyWithPeriodKES' wrapper
  SignKeyWithPeriodKES (..),
  updateKESWithPeriod,

  -- * 'SignedKES' wrapper
  SignedKES (..),
  signedKES,
  verifySignedKES,

  -- * CBOR encoding and decoding
  encodeVerKeyKES,
  decodeVerKeyKES,
  encodeSigKES,
  decodeSigKES,
  encodeSignedKES,
  decodeSignedKES,

  -- * Encoded 'Size' expressions
  encodedVerKeyKESSizeExpr,
  encodedSignKeyKESSizeExpr,
  encodedSigKESSizeExpr,

  -- * Raw sizes
  sizeVerKeyKES,
  sizeSigKES,
  sizeSignKeyKES,
  seedSizeKES,

  -- * Unsound APIs
  UnsoundKESAlgorithm (..),
  encodeSignKeyKES,
  decodeSignKeyKES,
  rawDeserialiseSignKeyKES,
  UnsoundPureKESAlgorithm (..),
  unsoundPureSignedKES,
  encodeUnsoundPureSignKeyKES,
  decodeUnsoundPureSignKeyKES,

  -- * Utility functions

  -- These are used between multiple KES implementations. User code will
  -- most likely not need these, but they are required for recursive
  -- definitions of the SumKES algorithms, and can be expressed entirely in
  -- terms of the KES, DSIGN and Hash typeclasses, so we keep them here for
  -- convenience.
  hashPairOfVKeys,
  mungeName,
  unsoundPureSignKeyKESToSoundSignKeyKESViaSer,
)
where

import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow)
import Control.Monad.Trans.Maybe (MaybeT (..), runMaybeT)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import GHC.TypeLits (ErrorMessage (..), KnownNat, Nat, TypeError, natVal)
import NoThunks.Class (NoThunks)

import Cardano.Binary (Decoder, Encoding, Size, decodeBytes, encodeBytes, withWordSize)

import Cardano.Crypto.DSIGN.Class (failSizeCheck)
import Cardano.Crypto.Hash.Class (Hash, HashAlgorithm, hashWith)
import Cardano.Crypto.Libsodium (MLockedAllocator, mlockedMalloc)
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (Empty)

class
  ( Typeable v
  , Show (VerKeyKES v)
  , Eq (VerKeyKES v)
  , Show (SigKES v)
  , Eq (SigKES v)
  , NoThunks (SigKES v)
  , NoThunks (SignKeyKES v)
  , NoThunks (VerKeyKES v)
  , KnownNat (SeedSizeKES v)
  , KnownNat (SizeVerKeyKES v)
  , KnownNat (SizeSignKeyKES v)
  , KnownNat (SizeSigKES v)
  ) =>
  KESAlgorithm v
  where
  --
  -- Key and signature types
  --
  data VerKeyKES v :: Type
  data SigKES v :: Type
  data SignKeyKES v :: Type

  type SeedSizeKES v :: Nat
  type SizeVerKeyKES v :: Nat
  type SizeSignKeyKES v :: Nat
  type SizeSigKES v :: Nat

  --
  -- Metadata and basic key operations
  --
  algorithmNameKES :: proxy v -> String

  hashVerKeyKES :: HashAlgorithm h => VerKeyKES v -> Hash h (VerKeyKES v)
  hashVerKeyKES = hashWith rawSerialiseVerKeyKES

  -- | Context required to run the KES algorithm
  --
  -- Unit by default (no context required)
  type ContextKES v :: Type

  type ContextKES v = ()

  type Signable v :: Type -> Constraint
  type Signable v = Empty

  --
  -- Core algorithm operations
  --

  -- | Full KES verification. This method checks that the signature itself
  -- checks out (as per 'verifySigKES'), and also makes sure that it matches
  -- the provided VerKey.
  verifyKES ::
    (Signable v a, HasCallStack) =>
    ContextKES v ->
    VerKeyKES v ->
    -- | The /current/ period for the key
    Period ->
    a ->
    SigKES v ->
    Either String ()

  -- | Return the total number of KES periods supported by this algorithm. The
  -- KES algorithm is assumed to support a fixed maximum number of periods, not
  -- a variable number.
  --
  -- Do note that this is the total number of /periods/ not the total number of
  -- evolutions. The difference is off-by-one. For example if there are 2
  -- periods (period 0 and 1) then there is only one evolution.
  totalPeriodsKES ::
    proxy v -> Word

  --
  -- Serialisation/(de)serialisation in fixed-size raw format
  --

  rawSerialiseVerKeyKES :: VerKeyKES v -> ByteString
  rawSerialiseSigKES :: SigKES v -> ByteString

  rawDeserialiseVerKeyKES :: ByteString -> Maybe (VerKeyKES v)
  rawDeserialiseSigKES :: ByteString -> Maybe (SigKES v)

  deriveVerKeyKES :: (MonadST m, MonadThrow m) => SignKeyKES v -> m (VerKeyKES v)

  --
  -- Core algorithm operations
  --

  signKES ::
    forall a m.
    (Signable v a, MonadST m, MonadThrow m) =>
    ContextKES v ->
    -- | The /current/ period for the key
    Period ->
    a ->
    SignKeyKES v ->
    m (SigKES v)

  updateKESWith ::
    (MonadST m, MonadThrow m) =>
    MLockedAllocator m ->
    ContextKES v ->
    SignKeyKES v ->
    -- | The /current/ period for the key, not the target period.
    Period ->
    m (Maybe (SignKeyKES v))

  genKeyKESWith ::
    (MonadST m, MonadThrow m) =>
    MLockedAllocator m ->
    MLockedSeed (SeedSizeKES v) ->
    m (SignKeyKES v)

  --
  -- Secure forgetting
  --

  -- | Forget a signing key synchronously, rather than waiting for GC. In some
  -- non-mock instances this provides a guarantee that the signing key is no
  -- longer in memory.
  --
  -- The precondition is that this key value will not be used again.
  forgetSignKeyKESWith ::
    (MonadST m, MonadThrow m) =>
    MLockedAllocator m ->
    SignKeyKES v ->
    m ()

sizeVerKeyKES :: forall v proxy. KESAlgorithm v => proxy v -> Word
sizeVerKeyKES _ = fromInteger (natVal (Proxy @(SizeVerKeyKES v)))

sizeSigKES :: forall v proxy. KESAlgorithm v => proxy v -> Word
sizeSigKES _ = fromInteger (natVal (Proxy @(SizeSigKES v)))

sizeSignKeyKES :: forall v proxy. KESAlgorithm v => proxy v -> Word
sizeSignKeyKES _ = fromInteger (natVal (Proxy @(SizeSignKeyKES v)))

-- | The upper bound on the 'Seed' size needed by 'genKeyKES'
seedSizeKES :: forall v proxy. KESAlgorithm v => proxy v -> Word
seedSizeKES _ = fromInteger (natVal (Proxy @(SeedSizeKES v)))

-- | Forget a signing key synchronously, rather than waiting for GC. In some
-- non-mock instances this provides a guarantee that the signing key is no
-- longer in memory.
--
-- The precondition is that this key value will not be used again.
forgetSignKeyKES ::
  (KESAlgorithm v, MonadST m, MonadThrow m) =>
  SignKeyKES v ->
  m ()
forgetSignKeyKES = forgetSignKeyKESWith mlockedMalloc

-- | Key generation
genKeyKES ::
  forall v m.
  (KESAlgorithm v, MonadST m, MonadThrow m) =>
  MLockedSeed (SeedSizeKES v) ->
  m (SignKeyKES v)
genKeyKES = genKeyKESWith mlockedMalloc

-- | Update the KES signature key to the /next/ period, given the /current/
-- period.
--
-- It returns 'Nothing' if the cannot be evolved any further.
--
-- The precondition (to get a 'Just' result) is that the current KES period
-- of the input key is not the last period. The given period must be the
-- current KES period of the input key (not the next or target).
--
-- The postcondition is that in case a key is returned, its current KES
-- period is incremented by one compared to before.
--
-- Note that you must track the current period separately, and to skip to a
-- later period requires repeated use of this function, since it only
-- increments one period at once.
updateKES ::
  forall v m.
  (KESAlgorithm v, MonadST m, MonadThrow m) =>
  ContextKES v ->
  SignKeyKES v ->
  -- | The /current/ period for the key, not the target period.
  Period ->
  m (Maybe (SignKeyKES v))
updateKES = updateKESWith mlockedMalloc

-- | Pure implementations of the core KES operations. These are unsound, because
-- proper handling of KES secrets (seeds, sign keys) requires mlocking and
-- deterministic erasure (\"secure forgetting\"), which is not possible in pure
-- code.
-- This API is only provided for testing purposes; it must not be used to
-- generate or use real KES keys.
class
  ( KESAlgorithm v
  , NoThunks (UnsoundPureSignKeyKES v)
  ) =>
  UnsoundPureKESAlgorithm v
  where
  data UnsoundPureSignKeyKES v :: Type

  unsoundPureSignKES ::
    forall a.
    Signable v a =>
    ContextKES v ->
    -- | The /current/ period for the key
    Period ->
    a ->
    UnsoundPureSignKeyKES v ->
    SigKES v

  unsoundPureUpdateKES ::
    ContextKES v ->
    UnsoundPureSignKeyKES v ->
    -- | The /current/ period for the key, not the target period.
    Period ->
    Maybe (UnsoundPureSignKeyKES v)

  unsoundPureGenKeyKES ::
    Seed ->
    UnsoundPureSignKeyKES v

  unsoundPureDeriveVerKeyKES ::
    UnsoundPureSignKeyKES v ->
    VerKeyKES v

  unsoundPureSignKeyKESToSoundSignKeyKES ::
    (MonadST m, MonadThrow m) =>
    UnsoundPureSignKeyKES v ->
    m (SignKeyKES v)

  rawSerialiseUnsoundPureSignKeyKES :: UnsoundPureSignKeyKES v -> ByteString
  rawDeserialiseUnsoundPureSignKeyKES :: ByteString -> Maybe (UnsoundPureSignKeyKES v)

-- | Unsound operations on KES sign keys. These operations violate secure
-- forgetting constraints by leaking secrets to unprotected memory. Consider
-- using the 'DirectSerialise' / 'DirectDeserialise' APIs instead.
class KESAlgorithm v => UnsoundKESAlgorithm v where
  rawDeserialiseSignKeyKESWith ::
    (MonadST m, MonadThrow m) =>
    MLockedAllocator m ->
    ByteString ->
    m (Maybe (SignKeyKES v))

  rawSerialiseSignKeyKES :: (MonadST m, MonadThrow m) => SignKeyKES v -> m ByteString

rawDeserialiseSignKeyKES ::
  (UnsoundKESAlgorithm v, MonadST m, MonadThrow m) =>
  ByteString ->
  m (Maybe (SignKeyKES v))
rawDeserialiseSignKeyKES = rawDeserialiseSignKeyKESWith mlockedMalloc

-- | Helper function for implementing 'unsoundPureSignKeyKESToSoundSignKeyKES'
-- for KES algorithms that support both 'UnsoundKESAlgorithm' and
-- 'UnsoundPureKESAlgorithm'. For such KES algorithms, unsound sign keys can be
-- marshalled to sound sign keys by serializing and then deserializing them.
unsoundPureSignKeyKESToSoundSignKeyKESViaSer ::
  (MonadST m, MonadThrow m, UnsoundKESAlgorithm k, UnsoundPureKESAlgorithm k) =>
  UnsoundPureSignKeyKES k ->
  m (SignKeyKES k)
unsoundPureSignKeyKESToSoundSignKeyKESViaSer sk =
  maybe (error "unsoundPureSignKeyKESToSoundSignKeyKES: deserialisation failure") return
    =<< (rawDeserialiseSignKeyKES . rawSerialiseUnsoundPureSignKeyKES $ sk)

-- | Subclass for KES algorithms that embed a copy of the VerKey into the
-- signature itself, rather than relying on the externally supplied VerKey
-- alone. Some optimizations made in the 'Cardano.Crypto.KES.CompactSingleKES'
-- and 'Cardano.Crypto.KES.CompactSumKES' implementations require this
-- additional interface in order to avoid redundant computations.
class KESAlgorithm v => OptimizedKESAlgorithm v where
  -- | Partial verification: this method only verifies the signature itself,
  -- but it does not check it against any externally-provided VerKey. Use
  -- 'verifyKES' for full KES verification.
  verifySigKES ::
    (Signable v a, HasCallStack) =>
    ContextKES v ->
    -- | The /current/ period for the key
    Period ->
    a ->
    SigKES v ->
    Either String ()

  -- | Extract a VerKey from a SigKES. Note that a VerKey embedded in or
  -- derived from a SigKES is effectively user-supplied, so it is not enough
  -- to validate a SigKES against this VerKey (like 'verifySigKES' does); you
  -- must also compare the VerKey against an externally-provided key that you
  -- want to verify against (see 'verifyKES').
  verKeyFromSigKES ::
    ContextKES v ->
    Period ->
    SigKES v ->
    VerKeyKES v

verifyOptimizedKES ::
  (OptimizedKESAlgorithm v, Signable v a, HasCallStack) =>
  ContextKES v ->
  VerKeyKES v ->
  Period ->
  a ->
  SigKES v ->
  Either String ()
verifyOptimizedKES ctx vk t a sig = do
  verifySigKES ctx t a sig
  let vk' = verKeyFromSigKES ctx t sig
  if vk' == vk
    then
      return ()
    else
      Left "KES verification failed"

--
-- Do not provide Ord instances for keys, see #38
--

instance
  ( TypeError ('Text "Ord not supported for signing keys, use the hash instead")
  , Eq (SignKeyKES v)
  ) =>
  Ord (SignKeyKES v)
  where
  compare = error "unsupported"

instance
  ( TypeError ('Text "Ord not supported for verification keys, use the hash instead")
  , KESAlgorithm v
  ) =>
  Ord (VerKeyKES v)
  where
  compare = error "unsupported"

--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeVerKeyKES :: KESAlgorithm v => VerKeyKES v -> Encoding
encodeVerKeyKES = encodeBytes . rawSerialiseVerKeyKES

encodeUnsoundPureSignKeyKES :: UnsoundPureKESAlgorithm v => UnsoundPureSignKeyKES v -> Encoding
encodeUnsoundPureSignKeyKES = encodeBytes . rawSerialiseUnsoundPureSignKeyKES

encodeSigKES :: KESAlgorithm v => SigKES v -> Encoding
encodeSigKES = encodeBytes . rawSerialiseSigKES

encodeSignKeyKES ::
  forall v m.
  (UnsoundKESAlgorithm v, MonadST m, MonadThrow m) =>
  SignKeyKES v ->
  m Encoding
encodeSignKeyKES = fmap encodeBytes . rawSerialiseSignKeyKES

decodeVerKeyKES :: forall v s. KESAlgorithm v => Decoder s (VerKeyKES v)
decodeVerKeyKES = do
  bs <- decodeBytes
  case rawDeserialiseVerKeyKES bs of
    Just vk -> return vk
    Nothing -> failSizeCheck "decodeVerKeyKES" "key" bs (sizeVerKeyKES (Proxy :: Proxy v))
{-# INLINE decodeVerKeyKES #-}

decodeUnsoundPureSignKeyKES ::
  forall v s. UnsoundPureKESAlgorithm v => Decoder s (UnsoundPureSignKeyKES v)
decodeUnsoundPureSignKeyKES = do
  bs <- decodeBytes
  case rawDeserialiseUnsoundPureSignKeyKES bs of
    Just vk -> return vk
    Nothing -> failSizeCheck "decodeUnsoundPureSignKeyKES" "key" bs (sizeSignKeyKES (Proxy :: Proxy v))
{-# INLINE decodeUnsoundPureSignKeyKES #-}

decodeSigKES :: forall v s. KESAlgorithm v => Decoder s (SigKES v)
decodeSigKES = do
  bs <- decodeBytes
  case rawDeserialiseSigKES bs of
    Just sig -> return sig
    Nothing -> failSizeCheck "decodeSigKES" "signature" bs (sizeSigKES (Proxy :: Proxy v))
{-# INLINE decodeSigKES #-}

decodeSignKeyKES ::
  forall v s m.
  (UnsoundKESAlgorithm v, MonadST m, MonadThrow m) =>
  Decoder s (m (Maybe (SignKeyKES v)))
decodeSignKeyKES = do
  bs <- decodeBytes
  let expected = fromIntegral (sizeSignKeyKES (Proxy @v))
      actual = BS.length bs
  if actual /= expected
    then
      fail
        ( "decodeSignKeyKES: wrong length, expected "
            ++ show expected
            ++ " bytes but got "
            ++ show actual
        )
    else
      return $ rawDeserialiseSignKeyKES bs

-- | The KES period. Periods are enumerated from zero.
--
-- Be careful of fencepost errors: if there are 2 periods (period 0 and 1)
-- then there is only one key evolution.
type Period = Word

newtype SignedKES v a = SignedKES {getSig :: SigKES v}
  deriving (Generic)

deriving instance KESAlgorithm v => Show (SignedKES v a)
deriving instance KESAlgorithm v => Eq (SignedKES v a)

instance KESAlgorithm v => NoThunks (SignedKES v a)

-- use generic instance

signedKES ::
  (KESAlgorithm v, Signable v a, MonadST m, MonadThrow m) =>
  ContextKES v ->
  Period ->
  a ->
  SignKeyKES v ->
  m (SignedKES v a)
signedKES ctxt time a key = SignedKES <$> signKES ctxt time a key

verifySignedKES ::
  (KESAlgorithm v, Signable v a) =>
  ContextKES v ->
  VerKeyKES v ->
  Period ->
  a ->
  SignedKES v a ->
  Either String ()
verifySignedKES ctxt vk j a (SignedKES sig) = verifyKES ctxt vk j a sig

unsoundPureSignedKES ::
  (UnsoundPureKESAlgorithm v, Signable v a) =>
  ContextKES v ->
  Period ->
  a ->
  UnsoundPureSignKeyKES v ->
  SignedKES v a
unsoundPureSignedKES ctxt time a key = SignedKES $ unsoundPureSignKES ctxt time a key

encodeSignedKES :: KESAlgorithm v => SignedKES v a -> Encoding
encodeSignedKES (SignedKES s) = encodeSigKES s

decodeSignedKES :: KESAlgorithm v => Decoder s (SignedKES v a)
decodeSignedKES = SignedKES <$> decodeSigKES
{-# INLINE decodeSignedKES #-}

-- | A sign key bundled with its associated period.
data SignKeyWithPeriodKES v
  = SignKeyWithPeriodKES
  { skWithoutPeriodKES :: !(SignKeyKES v)
  , periodKES :: !Period
  }
  deriving (Generic)

deriving instance (KESAlgorithm v, Eq (SignKeyKES v)) => Eq (SignKeyWithPeriodKES v)

deriving instance (KESAlgorithm v, Show (SignKeyKES v)) => Show (SignKeyWithPeriodKES v)

instance KESAlgorithm v => NoThunks (SignKeyWithPeriodKES v)

-- use generic instance

updateKESWithPeriod ::
  (KESAlgorithm v, MonadST m, MonadThrow m) =>
  ContextKES v ->
  SignKeyWithPeriodKES v ->
  m (Maybe (SignKeyWithPeriodKES v))
updateKESWithPeriod c (SignKeyWithPeriodKES sk t) = runMaybeT $ do
  sk' <- MaybeT $ updateKES c sk t
  return $ SignKeyWithPeriodKES sk' (succ t)

--
-- 'Size' expressions for 'ToCBOR' instances.
--

-- | 'Size' expression for 'VerKeyKES' which is using 'sizeVerKeyKES' encoded
-- as 'Size'.
encodedVerKeyKESSizeExpr :: forall v. KESAlgorithm v => Proxy (VerKeyKES v) -> Size
encodedVerKeyKESSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral ((withWordSize :: Word -> Integer) (sizeVerKeyKES (Proxy :: Proxy v)))
    -- payload
    + fromIntegral (sizeVerKeyKES (Proxy :: Proxy v))

-- | 'Size' expression for 'SignKeyKES' which is using 'sizeSignKeyKES' encoded
-- as 'Size'.
encodedSignKeyKESSizeExpr :: forall v. KESAlgorithm v => Proxy (SignKeyKES v) -> Size
encodedSignKeyKESSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral ((withWordSize :: Word -> Integer) (sizeSignKeyKES (Proxy @v)))
    -- payload
    + fromIntegral (sizeSignKeyKES (Proxy :: Proxy v))

-- | 'Size' expression for 'SigKES' which is using 'sizeSigKES' encoded as
-- 'Size'.
encodedSigKESSizeExpr :: forall v. KESAlgorithm v => Proxy (SigKES v) -> Size
encodedSigKESSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral ((withWordSize :: Word -> Integer) (sizeSigKES (Proxy :: Proxy v)))
    -- payload
    + fromIntegral (sizeSigKES (Proxy :: Proxy v))

hashPairOfVKeys ::
  (KESAlgorithm d, HashAlgorithm h) =>
  (VerKeyKES d, VerKeyKES d) ->
  Hash h (VerKeyKES d, VerKeyKES d)
hashPairOfVKeys =
  hashWith $ \(a, b) ->
    rawSerialiseVerKeyKES a <> rawSerialiseVerKeyKES b

mungeName :: String -> String
mungeName basename
  | (name, '^' : nstr) <- span (/= '^') basename
  , [(n, "")] <- reads nstr =
      name ++ '^' : show (n + 1 :: Word)
  | otherwise =
      basename ++ "_2^1"
