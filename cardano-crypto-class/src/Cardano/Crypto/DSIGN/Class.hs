{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Abstract digital signatures.
module Cardano.Crypto.DSIGN.Class (
  -- * DSIGN algorithm class
  DSIGNAlgorithm (..),
  Seed,
  seedSizeDSIGN,
  sizeVerKeyDSIGN,
  sizeSignKeyDSIGN,
  sizeSigDSIGN,

  -- * MLocked DSIGN algorithm class
  DSIGNMAlgorithm (..),
  genKeyDSIGNM,
  cloneKeyDSIGNM,
  getSeedDSIGNM,
  forgetSignKeyDSIGNM,

  -- * 'SignedDSIGN' wrapper
  SignedDSIGN (..),
  signedDSIGN,
  verifySignedDSIGN,

  -- * CBOR encoding and decoding
  encodeVerKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSignKeyDSIGN,
  decodeSignKeyDSIGN,
  encodeSigDSIGN,
  decodeSigDSIGN,
  encodeSignedDSIGN,
  decodeSignedDSIGN,

  -- * Encoded 'Size' expresssions
  encodedVerKeyDSIGNSizeExpr,
  encodedSignKeyDSIGNSizeExpr,
  encodedSigDSIGNSizeExpr,

  -- * Helper
  failSizeCheck,

  -- * Unsound CBOR encoding and decoding of MLocked DSIGN keys
  UnsoundDSIGNMAlgorithm (..),
  encodeSignKeyDSIGNM,
  decodeSignKeyDSIGNM,
  rawDeserialiseSignKeyDSIGNM,

  -- * Aggregatable DSIGN algorithms with Proof of Possession
  DSIGNAggregatable (..),
  aggregateVerKeysDSIGN,
  sizePossessionProofDSIGN,
  encodePossessionProofDSIGN,
  decodePossessionProofDSIGN,
  encodedPossessionProofDSIGNSizeExpr,
)
where

import Control.DeepSeq (NFData)
import Control.Monad (forM_)
import Control.Monad.Class.MonadST (MonadST)
import Control.Monad.Class.MonadThrow (MonadThrow)
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

import Cardano.Crypto.Hash.Class (Hash, HashAlgorithm, hashWith)
import Cardano.Crypto.Libsodium (MLockedAllocator, mlockedMalloc)
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (Empty)

-- | The pure DSIGN API, which supports the full set of DSIGN operations, but
-- does not allow for secure forgetting of private keys.
class
  ( Typeable v
  , Show (VerKeyDSIGN v)
  , Eq (VerKeyDSIGN v)
  , Show (SignKeyDSIGN v)
  , Show (SigDSIGN v)
  , Eq (SigDSIGN v)
  , NoThunks (SigDSIGN v)
  , NoThunks (SignKeyDSIGN v)
  , NoThunks (VerKeyDSIGN v)
  , KnownNat (SeedSizeDSIGN v)
  , KnownNat (SizeVerKeyDSIGN v)
  , KnownNat (SizeSignKeyDSIGN v)
  , KnownNat (SizeSigDSIGN v)
  ) =>
  DSIGNAlgorithm v
  where
  type SeedSizeDSIGN v :: Nat
  type SizeVerKeyDSIGN v :: Nat
  type SizeSignKeyDSIGN v :: Nat
  type SizeSigDSIGN v :: Nat

  --
  -- Key and signature types
  --

  data VerKeyDSIGN v :: Type
  data SignKeyDSIGN v :: Type
  data SigDSIGN v :: Type

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN :: proxy v -> String

  deriveVerKeyDSIGN :: SignKeyDSIGN v -> VerKeyDSIGN v

  hashVerKeyDSIGN :: HashAlgorithm h => VerKeyDSIGN v -> Hash h (VerKeyDSIGN v)
  hashVerKeyDSIGN = hashWith rawSerialiseVerKeyDSIGN

  --
  -- Core algorithm operations
  --

  -- | Context required to run the DSIGN algorithm
  --
  -- Unit by default (no context required)
  type ContextDSIGN v :: Type

  type ContextDSIGN v = ()

  type Signable v :: Type -> Constraint
  type Signable v = Empty

  type KeyGenContextDSIGN v :: Type
  type KeyGenContextDSIGN v = ()

  signDSIGN ::
    (Signable v a, HasCallStack) =>
    ContextDSIGN v ->
    a ->
    SignKeyDSIGN v ->
    SigDSIGN v

  verifyDSIGN ::
    (Signable v a, HasCallStack) =>
    ContextDSIGN v ->
    VerKeyDSIGN v ->
    a ->
    SigDSIGN v ->
    Either String ()

  --
  -- Key generation
  --

  -- | Note that this function may error (with 'SeedBytesExhausted') if the
  -- provided seed is not long enough. Callers should ensure that the seed has
  -- is at least 'seedSizeDSIGN' bytes long.
  genKeyDSIGN :: Seed -> SignKeyDSIGN v

  genKeyDSIGNWithContext :: KeyGenContextDSIGN v -> Seed -> SignKeyDSIGN v
  genKeyDSIGNWithContext _ = genKeyDSIGN

  --
  -- Serialisation/(de)serialisation in fixed-size raw format
  --

  rawSerialiseVerKeyDSIGN :: VerKeyDSIGN v -> ByteString
  rawSerialiseSignKeyDSIGN :: SignKeyDSIGN v -> ByteString
  rawSerialiseSigDSIGN :: SigDSIGN v -> ByteString

  rawDeserialiseVerKeyDSIGN :: ByteString -> Maybe (VerKeyDSIGN v)
  rawDeserialiseSignKeyDSIGN :: ByteString -> Maybe (SignKeyDSIGN v)
  rawDeserialiseSigDSIGN :: ByteString -> Maybe (SigDSIGN v)

--
-- Do not provide Ord instances for keys, see #38
--

instance
  ( TypeError ('Text "Ord not supported for signing keys, use the hash instead")
  , Eq (SignKeyDSIGN v)
  ) =>
  Ord (SignKeyDSIGN v)
  where
  compare = error "unsupported"

instance
  ( TypeError ('Text "Ord not supported for verification keys, use the hash instead")
  , Eq (VerKeyDSIGN v)
  ) =>
  Ord (VerKeyDSIGN v)
  where
  compare = error "unsupported"

-- | The upper bound on the 'Seed' size needed by 'genKeyDSIGN'
seedSizeDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
seedSizeDSIGN _ = fromInteger (natVal (Proxy @(SeedSizeDSIGN v)))

sizeVerKeyDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sizeVerKeyDSIGN _ = fromInteger (natVal (Proxy @(SizeVerKeyDSIGN v)))
sizeSignKeyDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sizeSignKeyDSIGN _ = fromInteger (natVal (Proxy @(SizeSignKeyDSIGN v)))
sizeSigDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sizeSigDSIGN _ = fromInteger (natVal (Proxy @(SizeSigDSIGN v)))

--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeVerKeyDSIGN :: DSIGNAlgorithm v => VerKeyDSIGN v -> Encoding
encodeVerKeyDSIGN = encodeBytes . rawSerialiseVerKeyDSIGN

encodeSignKeyDSIGN :: DSIGNAlgorithm v => SignKeyDSIGN v -> Encoding
encodeSignKeyDSIGN = encodeBytes . rawSerialiseSignKeyDSIGN

encodeSigDSIGN :: DSIGNAlgorithm v => SigDSIGN v -> Encoding
encodeSigDSIGN = encodeBytes . rawSerialiseSigDSIGN

decodeVerKeyDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (VerKeyDSIGN v)
decodeVerKeyDSIGN = do
  bs <- decodeBytes
  case rawDeserialiseVerKeyDSIGN bs of
    Just vk -> return vk
    Nothing -> failSizeCheck "decodeVerKeyDSIGN" "key" bs (sizeVerKeyDSIGN (Proxy :: Proxy v))
{-# INLINE decodeVerKeyDSIGN #-}

decodeSignKeyDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (SignKeyDSIGN v)
decodeSignKeyDSIGN = do
  bs <- decodeBytes
  case rawDeserialiseSignKeyDSIGN bs of
    Just sk -> return sk
    Nothing -> failSizeCheck "decodeSignKeyDSIGN" "key" bs (sizeSignKeyDSIGN (Proxy :: Proxy v))

decodeSigDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (SigDSIGN v)
decodeSigDSIGN = do
  bs <- decodeBytes
  case rawDeserialiseSigDSIGN bs of
    Just sig -> return sig
    Nothing -> failSizeCheck "decodeSigDSIGN" "signature" bs (sizeSigDSIGN (Proxy :: Proxy v))
{-# INLINE decodeSigDSIGN #-}

-- | Helper function that always fails, but it provides a different message whenever
-- expected size does not match.
failSizeCheck :: MonadFail m => String -> String -> ByteString -> Word -> m a
failSizeCheck fname name bs expectedSize
  | actualSize /= expectedSize =
      fail
        ( fname
            ++ ": wrong length, expected "
            ++ show expectedSize
            ++ " bytes but got "
            ++ show actualSize
        )
  | otherwise = fail $ fname ++ ": cannot decode " ++ name
  where
    actualSize = fromIntegral @Int @Word (BS.length bs)
{-# NOINLINE failSizeCheck #-}

newtype SignedDSIGN v a = SignedDSIGN (SigDSIGN v)
  deriving (Generic)

deriving instance DSIGNAlgorithm v => Show (SignedDSIGN v a)
deriving instance DSIGNAlgorithm v => Eq (SignedDSIGN v a)

deriving instance NFData (SigDSIGN v) => NFData (SignedDSIGN v a)

instance DSIGNAlgorithm v => NoThunks (SignedDSIGN v a)

-- use generic instance

signedDSIGN ::
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  a ->
  SignKeyDSIGN v ->
  SignedDSIGN v a
signedDSIGN ctxt a key = SignedDSIGN (signDSIGN ctxt a key)

verifySignedDSIGN ::
  (DSIGNAlgorithm v, Signable v a, HasCallStack) =>
  ContextDSIGN v ->
  VerKeyDSIGN v ->
  a ->
  SignedDSIGN v a ->
  Either String ()
verifySignedDSIGN ctxt key a (SignedDSIGN s) = verifyDSIGN ctxt key a s

encodeSignedDSIGN :: DSIGNAlgorithm v => SignedDSIGN v a -> Encoding
encodeSignedDSIGN (SignedDSIGN s) = encodeSigDSIGN s

decodeSignedDSIGN :: DSIGNAlgorithm v => Decoder s (SignedDSIGN v a)
decodeSignedDSIGN = SignedDSIGN <$> decodeSigDSIGN
{-# INLINE decodeSignedDSIGN #-}

--
-- Encoded 'Size' expressions for 'ToCBOR' instances
--

-- | 'Size' expression for 'VerKeyDSIGN' which is using 'sizeVerKeyDSIGN'
-- encoded as 'Size'.
encodedVerKeyDSIGNSizeExpr :: forall v. DSIGNAlgorithm v => Proxy (VerKeyDSIGN v) -> Size
encodedVerKeyDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size ((withWordSize :: Word -> Integer) (sizeVerKeyDSIGN (Proxy :: Proxy v)))
    -- payload
    + fromIntegral @Word @Size (sizeVerKeyDSIGN (Proxy :: Proxy v))

-- | 'Size' expression for 'SignKeyDSIGN' which is using 'sizeSignKeyDSIGN'
-- encoded as 'Size'.
encodedSignKeyDSIGNSizeExpr :: forall v. DSIGNAlgorithm v => Proxy (SignKeyDSIGN v) -> Size
encodedSignKeyDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size
    ((withWordSize :: Word -> Integer) (sizeSignKeyDSIGN (Proxy :: Proxy v)))
    -- payload
    + fromIntegral @Word @Size (sizeSignKeyDSIGN (Proxy :: Proxy v))

-- | 'Size' expression for 'SigDSIGN' which is using 'sizeSigDSIGN' encoded as
-- 'Size'.
encodedSigDSIGNSizeExpr :: forall v. DSIGNAlgorithm v => Proxy (SigDSIGN v) -> Size
encodedSigDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size ((withWordSize :: Word -> Integer) (sizeSigDSIGN (Proxy :: Proxy v)))
    -- payload
    + fromIntegral @Word @Size (sizeSigDSIGN (Proxy :: Proxy v))

class (DSIGNAlgorithm v, NoThunks (SignKeyDSIGNM v)) => DSIGNMAlgorithm v where
  data SignKeyDSIGNM v :: Type

  deriveVerKeyDSIGNM :: (MonadThrow m, MonadST m) => SignKeyDSIGNM v -> m (VerKeyDSIGN v)

  --
  -- Core algorithm operations
  --

  signDSIGNM ::
    (Signable v a, MonadST m, MonadThrow m) =>
    ContextDSIGN v ->
    a ->
    SignKeyDSIGNM v ->
    m (SigDSIGN v)

  --
  -- Key generation
  --

  genKeyDSIGNMWith ::
    (MonadST m, MonadThrow m) =>
    MLockedAllocator m ->
    MLockedSeed (SeedSizeDSIGN v) ->
    m (SignKeyDSIGNM v)

  cloneKeyDSIGNMWith :: MonadST m => MLockedAllocator m -> SignKeyDSIGNM v -> m (SignKeyDSIGNM v)

  getSeedDSIGNMWith ::
    (MonadST m, MonadThrow m) =>
    MLockedAllocator m ->
    Proxy v ->
    SignKeyDSIGNM v ->
    m (MLockedSeed (SeedSizeDSIGN v))

  --
  -- Secure forgetting
  --

  forgetSignKeyDSIGNMWith ::
    (MonadST m, MonadThrow m) => MLockedAllocator m -> SignKeyDSIGNM v -> m ()

forgetSignKeyDSIGNM :: (DSIGNMAlgorithm v, MonadST m, MonadThrow m) => SignKeyDSIGNM v -> m ()
forgetSignKeyDSIGNM = forgetSignKeyDSIGNMWith mlockedMalloc

genKeyDSIGNM ::
  (DSIGNMAlgorithm v, MonadST m, MonadThrow m) =>
  MLockedSeed (SeedSizeDSIGN v) ->
  m (SignKeyDSIGNM v)
genKeyDSIGNM = genKeyDSIGNMWith mlockedMalloc

cloneKeyDSIGNM ::
  (DSIGNMAlgorithm v, MonadST m) => SignKeyDSIGNM v -> m (SignKeyDSIGNM v)
cloneKeyDSIGNM = cloneKeyDSIGNMWith mlockedMalloc

getSeedDSIGNM ::
  (DSIGNMAlgorithm v, MonadST m, MonadThrow m) =>
  Proxy v ->
  SignKeyDSIGNM v ->
  m (MLockedSeed (SeedSizeDSIGN v))
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
  (UnsoundDSIGNMAlgorithm v, MonadST m, MonadThrow m) =>
  ByteString ->
  m (Maybe (SignKeyDSIGNM v))
rawDeserialiseSignKeyDSIGNM =
  rawDeserialiseSignKeyDSIGNMWith mlockedMalloc

--
-- Do not provide Ord instances for keys, see #38
--

instance
  ( TypeError ('Text "Ord not supported for signing keys, use the hash instead")
  , Eq (SignKeyDSIGNM v)
  ) =>
  Ord (SignKeyDSIGNM v)
  where
  compare = error "unsupported"

--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeSignKeyDSIGNM ::
  (UnsoundDSIGNMAlgorithm v, MonadST m, MonadThrow m) =>
  SignKeyDSIGNM v ->
  m Encoding
encodeSignKeyDSIGNM = fmap encodeBytes . rawSerialiseSignKeyDSIGNM

decodeSignKeyDSIGNM ::
  forall m v s.
  (UnsoundDSIGNMAlgorithm v, MonadST m, MonadThrow m) =>
  Decoder s (m (SignKeyDSIGNM v))
decodeSignKeyDSIGNM = do
  bs <- decodeBytes
  return $
    rawDeserialiseSignKeyDSIGNM bs >>= \case
      Just vk -> return vk
      Nothing
        | actual /= expected ->
            error
              ( "decodeSignKeyDSIGNM: wrong length, expected "
                  ++ show expected
                  ++ " bytes but got "
                  ++ show actual
              )
        | otherwise -> error "decodeSignKeyDSIGNM: cannot decode key"
        where
          expected = fromIntegral @Word @Int (sizeSignKeyDSIGN (Proxy :: Proxy v))
          actual = BS.length bs

-- | Extension of the `DSIGNAlgorithm` to allow for aggregatable digital
-- signature schemes that support Proof of Possession (PoP) of signing keys.
-- Such schemes enable the aggregation of multiple signatures and verification
-- keys into a single signature and verification key, respectively, while
-- ensuring that each verification key is associated with a valid signing key
-- through the use of Proofs of Possession. The latter is against rogue-key
-- attacks.
--
-- Examples of aggregatable signatures schemes are the BLS signature scheme and
-- the Pixel scheme.
class
  ( DSIGNAlgorithm v
  , Show (PossessionProofDSIGN v)
  , Eq (PossessionProofDSIGN v)
  , NoThunks (PossessionProofDSIGN v)
  , KnownNat (PossessionProofSizeDSIGN v)
  ) =>
  DSIGNAggregatable v
  where
  type PossessionProofSizeDSIGN v :: Nat
  data PossessionProofDSIGN v :: Type

  -- | Aggregate multiple verification keys into a single verification key
  -- without requiring their corresponding Proofs of Possession. This function
  -- is unsafe and should only be used when verification keys are valid (i.e.,
  -- their PoPs have been verified through other means). See
  -- 'aggregateVerKeysDSIGN' for a function that does this using
  -- 'verifyPossessionProofDSIGN'.
  uncheckedAggregateVerKeysDSIGN ::
    HasCallStack =>
    [VerKeyDSIGN v] ->
    Either String (VerKeyDSIGN v)

  -- | Aggregate multiple signatures into a single signature
  aggregateSigsDSIGN ::
    HasCallStack =>
    [SigDSIGN v] ->
    Either String (SigDSIGN v)

  -- | Create a PoP from the signing key.
  createPossessionProofDSIGN ::
    HasCallStack =>
    ContextDSIGN v ->
    SignKeyDSIGN v ->
    PossessionProofDSIGN v

  -- | Verify that PoP matches the verification key.
  verifyPossessionProofDSIGN ::
    HasCallStack =>
    ContextDSIGN v ->
    VerKeyDSIGN v ->
    PossessionProofDSIGN v ->
    Either String ()

  -- | Serialise a PoP into fixed-size raw bytes.
  rawSerialisePossessionProofDSIGN :: PossessionProofDSIGN v -> ByteString

  -- | Deserialise a PoP from fixed-size raw bytes.
  rawDeserialisePossessionProofDSIGN :: ByteString -> Maybe (PossessionProofDSIGN v)

-- | Aggregate multiple verification keys into a single verification key given
-- their corresponding Proofs of Possession.
--
-- Note that the signing context is passed since the PoP might depend on it.
aggregateVerKeysDSIGN ::
  (HasCallStack, DSIGNAggregatable v) =>
  ContextDSIGN v ->
  [(VerKeyDSIGN v, PossessionProofDSIGN v)] ->
  Either String (VerKeyDSIGN v)
aggregateVerKeysDSIGN ctx verKeysAndPoPs = do
  -- Verify every verKey and its PoP (fail-fast)
  forM_ verKeysAndPoPs $ uncurry (verifyPossessionProofDSIGN ctx)
  uncheckedAggregateVerKeysDSIGN (map fst verKeysAndPoPs)

sizePossessionProofDSIGN :: forall v proxy. DSIGNAggregatable v => proxy v -> Word
sizePossessionProofDSIGN _ = fromInteger (natVal (Proxy @(PossessionProofSizeDSIGN v)))

-- | Encode a PoP into CBOR.
encodePossessionProofDSIGN :: DSIGNAggregatable v => PossessionProofDSIGN v -> Encoding
encodePossessionProofDSIGN = encodeBytes . rawSerialisePossessionProofDSIGN

-- | Decode a PoP from CBOR.
decodePossessionProofDSIGN ::
  forall v s. DSIGNAggregatable v => Decoder s (PossessionProofDSIGN v)
decodePossessionProofDSIGN = do
  bs <- decodeBytes
  case rawDeserialisePossessionProofDSIGN bs of
    Just pop -> return pop
    Nothing ->
      failSizeCheck
        "decodePossessionProof"
        "proof of possession"
        bs
        (sizePossessionProofDSIGN (Proxy :: Proxy v))

-- | 'Size' expression for 'PossessionProofDSIGN' which is using 'sizePossessionProofDSIGN'
-- encoded as 'Size'.
encodedPossessionProofDSIGNSizeExpr ::
  forall v. DSIGNAggregatable v => Proxy (PossessionProofDSIGN v) -> Size
encodedPossessionProofDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral ((withWordSize :: Word -> Integer) (sizePossessionProofDSIGN (Proxy :: Proxy v)))
    -- payload
    + fromIntegral (sizePossessionProofDSIGN (Proxy :: Proxy v))
