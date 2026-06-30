{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuantifiedConstraints #-}
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
  verKeySizeDSIGN,
  signKeySizeDSIGN,
  sigSizeDSIGN,

  -- * Deprecated size synonyms
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

  -- * Unsound CBOR encoding and decoding of MLocked DSIGN keys
  UnsoundDSIGNMAlgorithm (..),
  encodeSignKeyDSIGNM,
  decodeSignKeyDSIGNM,
  rawDeserialiseSignKeyDSIGNM,

  -- * Aggregatable DSIGN algorithms with Proof of Possession
  DSIGNAggregatable (..),
  aggregateVerKeysDSIGN,
  possessionProofSizeDSIGN,
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

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  fixedSize,
 )
import Cardano.Crypto.Hash.Class (Hash, HashAlgorithm, hashWith)
import Cardano.Crypto.Libsodium (MLockedAllocator, mlockedMalloc)
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (Empty)

{-# DEPRECATED SizeVerKeyDSIGN "In favor of `VerKeySizeDSIGN`" #-}
{-# DEPRECATED SizeSignKeyDSIGN "In favor of `SignKeySizeDSIGN`" #-}
{-# DEPRECATED SizeSigDSIGN "In favor of `SigSizeDSIGN`" #-}

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
  , KnownNat (SignKeySizeDSIGN v)
  , KnownNat (VerKeySizeDSIGN v)
  , KnownNat (SigSizeDSIGN v)
  , FixedSizeCodec (VerKeyDSIGN v)
  , FixedSizeCodec (SignKeyDSIGN v)
  , FixedSizeCodec (SigDSIGN v)
  ) =>
  DSIGNAlgorithm v
  where
  type SeedSizeDSIGN v :: Nat
  type SignKeySizeDSIGN v :: Nat
  type SignKeySizeDSIGN v = FixedSize (SignKeyDSIGN v)
  type VerKeySizeDSIGN v :: Nat
  type VerKeySizeDSIGN v = FixedSize (VerKeyDSIGN v)
  type SigSizeDSIGN v :: Nat
  type SigSizeDSIGN v = FixedSize (SigDSIGN v)

  type SizeSignKeyDSIGN v :: Nat
  type SizeSignKeyDSIGN v = SignKeySizeDSIGN v
  type SizeVerKeyDSIGN v :: Nat
  type SizeVerKeyDSIGN v = VerKeySizeDSIGN v
  type SizeSigDSIGN v :: Nat
  type SizeSigDSIGN v = SigSizeDSIGN v

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
  hashVerKeyDSIGN = hashWith rawEncodeFixedSized

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
  rawSerialiseVerKeyDSIGN = rawEncodeFixedSized
  rawSerialiseSignKeyDSIGN :: SignKeyDSIGN v -> ByteString
  rawSerialiseSignKeyDSIGN = rawEncodeFixedSized
  rawSerialiseSigDSIGN :: SigDSIGN v -> ByteString
  rawSerialiseSigDSIGN = rawEncodeFixedSized

  rawDeserialiseVerKeyDSIGN :: ByteString -> Maybe (VerKeyDSIGN v)
  rawDeserialiseVerKeyDSIGN = rawDecodeFixedSized
  rawDeserialiseSignKeyDSIGN :: ByteString -> Maybe (SignKeyDSIGN v)
  rawDeserialiseSignKeyDSIGN = rawDecodeFixedSized
  rawDeserialiseSigDSIGN :: ByteString -> Maybe (SigDSIGN v)
  rawDeserialiseSigDSIGN = rawDecodeFixedSized

{-# DEPRECATED rawSerialiseVerKeyDSIGN "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawSerialiseSignKeyDSIGN "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawSerialiseSigDSIGN "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialiseVerKeyDSIGN "Use `rawDecodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialiseSignKeyDSIGN "Use `rawDecodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialiseSigDSIGN "Use `rawDecodeFixedSized` instead" #-}

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

{-# DEPRECATED sizeVerKeyDSIGN "In favor of `fixedSize`" #-}
sizeVerKeyDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sizeVerKeyDSIGN _ = fixedSize $ Proxy @(VerKeyDSIGN v)

{-# DEPRECATED sizeSignKeyDSIGN "In favor of `fixedSize`" #-}
sizeSignKeyDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sizeSignKeyDSIGN _ = fixedSize $ Proxy @(SignKeyDSIGN v)

{-# DEPRECATED sizeSigDSIGN "In favor of `fixedSize`" #-}
sizeSigDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sizeSigDSIGN _ = fixedSize $ Proxy @(SigDSIGN v)

-- | The upper bound on the 'Seed' size needed by 'genKeyDSIGN'
seedSizeDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
seedSizeDSIGN _ = fromInteger (natVal (Proxy @(SeedSizeDSIGN v)))

verKeySizeDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
verKeySizeDSIGN _ = fixedSize $ Proxy @(VerKeyDSIGN v)
{-# DEPRECATED verKeySizeDSIGN "Use `fixedSize` instead" #-}

signKeySizeDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
signKeySizeDSIGN _ = fixedSize $ Proxy @(SignKeyDSIGN v)
{-# DEPRECATED signKeySizeDSIGN "Use `fixedSize` instead" #-}

sigSizeDSIGN :: forall v proxy. DSIGNAlgorithm v => proxy v -> Word
sigSizeDSIGN _ = fixedSize $ Proxy @(SigDSIGN v)
{-# DEPRECATED sigSizeDSIGN "Use `fixedSize` instead" #-}

--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeVerKeyDSIGN :: DSIGNAlgorithm v => VerKeyDSIGN v -> Encoding
encodeVerKeyDSIGN = encodeFixedSized
{-# DEPRECATED encodeVerKeyDSIGN "Use `encodeFixedSized` instead" #-}

encodeSignKeyDSIGN :: DSIGNAlgorithm v => SignKeyDSIGN v -> Encoding
encodeSignKeyDSIGN = encodeFixedSized
{-# DEPRECATED encodeSignKeyDSIGN "Use `encodeFixedSized` instead" #-}

encodeSigDSIGN :: DSIGNAlgorithm v => SigDSIGN v -> Encoding
encodeSigDSIGN = encodeFixedSized
{-# DEPRECATED encodeSigDSIGN "Use `encodeFixedSized` instead" #-}

decodeVerKeyDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (VerKeyDSIGN v)
decodeVerKeyDSIGN = decodeFixedSized
{-# INLINE decodeVerKeyDSIGN #-}
{-# DEPRECATED decodeVerKeyDSIGN "Use `decodeFixedSized` instead" #-}

decodeSignKeyDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (SignKeyDSIGN v)
decodeSignKeyDSIGN = decodeFixedSized
{-# INLINE decodeSignKeyDSIGN #-}
{-# DEPRECATED decodeSignKeyDSIGN "Use `decodeFixedSized` instead" #-}

decodeSigDSIGN :: forall v s. DSIGNAlgorithm v => Decoder s (SigDSIGN v)
decodeSigDSIGN = decodeFixedSized
{-# INLINE decodeSigDSIGN #-}
{-# DEPRECATED decodeSigDSIGN "Use `decodeFixedSized` instead" #-}

newtype SignedDSIGN v a = SignedDSIGN (SigDSIGN v)
  deriving (Generic)

deriving instance DSIGNAlgorithm v => Show (SignedDSIGN v a)
deriving instance DSIGNAlgorithm v => Eq (SignedDSIGN v a)

deriving instance NFData (SigDSIGN v) => NFData (SignedDSIGN v a)

instance DSIGNAlgorithm v => NoThunks (SignedDSIGN v a)

instance
  FixedSizeCodec (SigDSIGN v) =>
  FixedSizeCodec (SignedDSIGN v a)
  where
  type FixedSize (SignedDSIGN v a) = FixedSize (SigDSIGN v)

  rawEncodeFixedSized (SignedDSIGN x) = rawEncodeFixedSized x
  rawDecodeFixedSized bs = SignedDSIGN <$> rawDecodeFixedSized bs

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
encodeSignedDSIGN = encodeFixedSized
{-# DEPRECATED encodeSignedDSIGN "Use `encodeFixedSized` instead" #-}

decodeSignedDSIGN :: DSIGNAlgorithm v => Decoder s (SignedDSIGN v a)
decodeSignedDSIGN = decodeFixedSized
{-# INLINE decodeSignedDSIGN #-}
{-# DEPRECATED decodeSignedDSIGN "Use `decodeFixedSized` instead" #-}

--
-- Encoded 'Size' expressions for 'ToCBOR' instances
--

encodedVerKeyDSIGNSizeExpr :: forall v. DSIGNAlgorithm v => Proxy (VerKeyDSIGN v) -> Size
encodedVerKeyDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size (withWordSize (fixedSize (Proxy @(VerKeyDSIGN v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(VerKeyDSIGN v)))

encodedSignKeyDSIGNSizeExpr :: forall v. DSIGNAlgorithm v => Proxy (SignKeyDSIGN v) -> Size
encodedSignKeyDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size
    (withWordSize (fixedSize (Proxy @(SignKeyDSIGN v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(SignKeyDSIGN v)))

encodedSigDSIGNSizeExpr :: forall v. DSIGNAlgorithm v => Proxy (SigDSIGN v) -> Size
encodedSigDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size (withWordSize (fixedSize (Proxy @(SigDSIGN v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(SigDSIGN v)))

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
          expected = fromIntegral @Word @Int (fixedSize (Proxy @(SignKeyDSIGN v)))
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
  , FixedSizeCodec (PossessionProofDSIGN v)
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
  rawSerialisePossessionProofDSIGN = rawEncodeFixedSized

  -- | Deserialise a PoP from fixed-size raw bytes.
  rawDeserialisePossessionProofDSIGN :: ByteString -> Maybe (PossessionProofDSIGN v)
  rawDeserialisePossessionProofDSIGN = rawDecodeFixedSized

{-# DEPRECATED rawSerialisePossessionProofDSIGN "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialisePossessionProofDSIGN "Use `rawDecodeFixedSized` instead" #-}

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

possessionProofSizeDSIGN :: forall v proxy. DSIGNAggregatable v => proxy v -> Word
possessionProofSizeDSIGN _ = fixedSize $ Proxy @(PossessionProofDSIGN v)
{-# DEPRECATED possessionProofSizeDSIGN "Use `fixedSize` instead" #-}

-- | Encode a PoP into CBOR.
encodePossessionProofDSIGN :: DSIGNAggregatable v => PossessionProofDSIGN v -> Encoding
encodePossessionProofDSIGN = encodeFixedSized
{-# DEPRECATED encodePossessionProofDSIGN "Use `encodeFixedSized` instead" #-}

-- | Decode a PoP from CBOR.
decodePossessionProofDSIGN ::
  forall v s. DSIGNAggregatable v => Decoder s (PossessionProofDSIGN v)
decodePossessionProofDSIGN = decodeFixedSized
{-# INLINE decodePossessionProofDSIGN #-}
{-# DEPRECATED decodePossessionProofDSIGN "Use `decodeFixedSized` instead" #-}

encodedPossessionProofDSIGNSizeExpr ::
  forall v. DSIGNAggregatable v => Proxy (PossessionProofDSIGN v) -> Size
encodedPossessionProofDSIGNSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size (withWordSize (fixedSize (Proxy @(PossessionProofDSIGN v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(PossessionProofDSIGN v)))
