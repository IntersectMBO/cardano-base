{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeData #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module      : Cardano.Crypto.WalletHD.Encrypted
-- Description : Authenticated v2 encrypted root-key envelopes.
--
-- Keys are stored as CBOR-encoded v2 envelopes: a random 32-byte salt
-- and 24-byte nonce, Argon2id-derived 32-byte wrapping key, and the
-- 64-byte extended secret key encrypted with XChaCha20-Poly1305.
-- The public key and chain code are bound as AEAD additional data so
-- they cannot be silently swapped without detection.
--
-- The plaintext secret key is held exclusively in @sodium_malloc@'d memory
-- ('MLockedSizedBytes') which is locked against swapping and is never moved
-- by the GC.  All public operations are in 'IO'; callers must 'mlsbFinalize'
-- any 'MLockedSizedBytes' they receive when done with it.
module Cardano.Crypto.WalletHD.Encrypted (
  -- * Types
  EncryptedKey,
  XPrvFormat (..),
  XPrvError (..),
  Signature (..),
  DerivationScheme (..),
  DerivationIndex,

  -- ** PublicKey
  PublicKey,
  publicKeySize,
  mkPublicKey,
  publicKeyByteArray,
  publicKeyByteString,

  -- ** Encrypted SecretKey
  EncSecretKey,
  mkEncSecretKey,
  encSecretKeyByteArray,
  encSecretKeyByteString,

  -- ** ChainCode
  ChainCode,
  chainCodeSize,
  mkChainCode,
  chainCodeByteArray,
  chainCodeByteString,

  -- ** Salt
  Salt,
  saltSize,
  mkSalt,
  saltByteArray,
  saltByteString,

  -- ** Nonce
  Nonce,
  nonceSize,
  mkNonce,
  nonceByteArray,
  nonceByteString,

  -- ** Tag
  Tag,
  tagSize,
  mkTag,
  tagByteArray,
  tagByteString,

  -- ** Envelope
  Envelope (eSalt, eNonce, ePublicKey, eChainCode),
  encodeEnvelope,
  decodeEnvelope,

  -- * Construction & validation
  encryptedCreate,
  encryptedCreateDirectWithTweak,
  mkEncryptedKey,
  unEncryptedKey,
  encryptedKey,
  encryptedKeyFormat,

  -- * Passphrase operations
  encryptedValidatePassphrase,
  encryptedChangePassphrase,

  -- * Signing & derivation
  encryptedSign,
  encryptedDerivePrivate,
  encryptedDerivePublic,

  -- * Accessors
  encryptedPublic,
  encryptedChainCode,

  -- * Test helpers
  withFastKdfForTesting,
  withDeterministicRandomnessForTesting,
) where

import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreate,
  psbCreateResult,
  psbCreateResultLen,
  psbFromByteString,
  psbFromByteStringM,
  psbToByteArray,
  psbToByteString,
  psbUseAsCPtr,
 )
import Control.Arrow (first)
import Control.DeepSeq
import Control.Exception (bracket)
import Control.Monad (when)
import Control.Monad.Trans.Fail.String (errorFail)
import Data.Array.Byte (ByteArray)
import Data.Bits (shiftR)
import Data.ByteArray (ByteArrayAccess, withByteArray)
import qualified Data.ByteArray as B
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.Coerce (coerce)
import Data.IORef (
  IORef,
  newIORef,
  readIORef,
  writeIORef,
 )
import Data.Proxy (Proxy (..))
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import GHC.Stack (HasCallStack)
import GHC.TypeLits
import System.IO.Unsafe (unsafePerformIO)

import Cardano.Binary (toCBOR)
import Cardano.Crypto.Libsodium.MLockedBytes (
  MLockedSizedBytes,
  mlsbFinalize,
  mlsbNewZero,
  mlsbUseAsCPtr,
 )
import Codec.CBOR.Decoding (
  Decoder,
  decodeBytes,
  decodeListLenOf,
  decodeWord,
 )
import Codec.CBOR.Encoding (
  Encoding,
  encodeBytes,
  encodeInt,
  encodeListLen,
  encodeWord,
 )
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Write as CBOR

-- ---------------------------------------------------------------------------
-- Key derivation scheme
-- ---------------------------------------------------------------------------

type DerivationIndex = Word32

data DerivationScheme = DerivationScheme1 | DerivationScheme2
  deriving (Show, Eq, Ord, Enum, Bounded)

-- ---------------------------------------------------------------------------
-- Size constants
-- ---------------------------------------------------------------------------

signatureSize :: Int
signatureSize = 64

mlsbCreate :: KnownNat n => (MLockedSizedBytes n -> b) -> (b -> IO c) -> IO c
mlsbCreate mkType action = bracket mlsbNewZero mlsbFinalize (action . mkType)

------------------------------------------------------------------------------
-- SECRET_KEY
------------------------------------------------------------------------------

-- TODO: Derive from: `UNENCRYPTED_KEY_SIZE`
type SECRET_KEY_SIZE = 64

secretKeySize :: Int
secretKeySize = fromInteger (natVal (Proxy @SECRET_KEY_SIZE))

-- | Plaintext version of the secret key used for creating signatures
newtype SecretKey = SecretKey {_unSecretKey :: MLockedSizedBytes SECRET_KEY_SIZE}

newtype SecretKeyPtr = SecretKeyPtr (Ptr Word8)

withSecretKeyPtr :: SecretKey -> (SecretKeyPtr -> IO a) -> IO a
withSecretKeyPtr (SecretKey secretKey) action =
  mlsbUseAsCPtr secretKey (action . SecretKeyPtr)
{-# INLINE withSecretKeyPtr #-}

-- Encrypted version (same size as decrypted)

-- | Encrypted version of `SecretKey`
newtype EncSecretKey = EncSecretKey {unEncSecretKey :: PinnedSizedBytes SECRET_KEY_SIZE}
  deriving (Eq, Show)

newtype EncSecretKeyPtr = EncSecretKeyPtr (Ptr Word8)

withEncSecretKeyPtr :: EncSecretKey -> (EncSecretKeyPtr -> IO a) -> IO a
withEncSecretKeyPtr (EncSecretKey encSecretKey) action =
  psbUseAsCPtr encSecretKey (action . EncSecretKeyPtr)
{-# INLINE withEncSecretKeyPtr #-}

mkEncSecretKey :: MonadFail f => ByteString -> f EncSecretKey
mkEncSecretKey bs = EncSecretKey <$> psbFromByteStringM bs

encSecretKeyByteArray :: EncSecretKey -> ByteArray
encSecretKeyByteArray = psbToByteArray . unEncSecretKey

encSecretKeyByteString :: EncSecretKey -> ByteString
encSecretKeyByteString = psbToByteString . unEncSecretKey

encodeEncSecretKey :: EncSecretKey -> Encoding
encodeEncSecretKey = toCBOR . psbToByteArray . unEncSecretKey

decodeEncSecretKey :: Decoder s EncSecretKey
decodeEncSecretKey = do
  saltBytes <- decodeBytes
  case mkEncSecretKey saltBytes of
    Nothing -> failDecoder XPrvInvalidCiphertextLength
    Just salt -> pure salt

------------------------------------------------------------------------------
-- PUBLIC_KEY
------------------------------------------------------------------------------

type PUBLIC_KEY_SIZE = 32

publicKeySize :: Int
publicKeySize = fromInteger (natVal (Proxy @PUBLIC_KEY_SIZE))

newtype PublicKey = PublicKey {unPublicKey :: PinnedSizedBytes PUBLIC_KEY_SIZE}
  deriving (Eq, Show)
newtype PublicKeyPtr = PublicKeyPtr (Ptr Word8)

withPublicKeyPtr :: PublicKey -> (PublicKeyPtr -> IO a) -> IO a
withPublicKeyPtr (PublicKey publicKey) action =
  psbUseAsCPtr publicKey (action . PublicKeyPtr)
{-# INLINE withPublicKeyPtr #-}

mkPublicKey :: MonadFail f => ByteString -> f PublicKey
mkPublicKey bs = PublicKey <$> psbFromByteStringM bs

publicKeyByteArray :: PublicKey -> ByteArray
publicKeyByteArray = psbToByteArray . unPublicKey

publicKeyByteString :: PublicKey -> ByteString
publicKeyByteString = psbToByteString . unPublicKey

encodePublicKey :: PublicKey -> Encoding
encodePublicKey = toCBOR . psbToByteArray . unPublicKey

------------------------------------------------------------------------------
-- CHAIN_CODE
------------------------------------------------------------------------------

type CHAIN_CODE_SIZE = 32

chainCodeSize :: Int
chainCodeSize = fromInteger (natVal (Proxy @CHAIN_CODE_SIZE))

newtype ChainCode = ChainCode {unChainCode :: PinnedSizedBytes CHAIN_CODE_SIZE}
  deriving (Eq, Show)
newtype ChainCodePtr = ChainCodePtr (Ptr Word8)

withChainCodePtr :: ChainCode -> (ChainCodePtr -> IO a) -> IO a
withChainCodePtr (ChainCode publicKey) action =
  psbUseAsCPtr publicKey (action . ChainCodePtr)
{-# INLINE withChainCodePtr #-}

mkChainCode :: MonadFail f => ByteString -> f ChainCode
mkChainCode bs = ChainCode <$> psbFromByteStringM bs

chainCodeByteArray :: ChainCode -> ByteArray
chainCodeByteArray = psbToByteArray . unChainCode

chainCodeByteString :: ChainCode -> ByteString
chainCodeByteString = psbToByteString . unChainCode

encodeChainCode :: ChainCode -> Encoding
encodeChainCode = toCBOR . psbToByteArray . unChainCode

------------------------------------------------------------------------------
-- KEY_MATERIAL
------------------------------------------------------------------------------

type data Validity = Validated | Unchecked

-- | Key material with the secret key in @sodium_malloc@'d locked memory.
data KeyMaterial (v :: Validity) = KeyMaterial
  { kmSecretKey :: !SecretKey
  , kmPublicKey :: !PublicKey
  , kmChainCode :: !ChainCode
  }

type KEY_MATERIAL_SIZE = SECRET_KEY_SIZE + PUBLIC_KEY_SIZE + CHAIN_CODE_SIZE

keyMaterialSize :: Int
keyMaterialSize = fromInteger (natVal (Proxy @KEY_MATERIAL_SIZE))

newtype KeyMaterialBuffer = KeyMaterialBuffer (MLockedSizedBytes KEY_MATERIAL_SIZE)
newtype KeyMaterialPtr = KeyMaterialPtr (Ptr Word8)

allocaKeyMaterialBuffer :: (KeyMaterialPtr -> IO c) -> IO c
allocaKeyMaterialBuffer action =
  mlsbCreate KeyMaterialBuffer $ \(KeyMaterialBuffer keyMaterialBuffer) ->
    mlsbUseAsCPtr keyMaterialBuffer (action . KeyMaterialPtr)

-- ---------------------------------------------------------------------------
-- V2 envelope constants
-- ---------------------------------------------------------------------------

v2Version, argon2idId, xchacha20poly1305Id :: Word
v2Version = 2
argon2idId = 1
xchacha20poly1305Id = 1

-- ---------------------------------------------------------------------------
-- KDF parameters
-- ---------------------------------------------------------------------------

data KdfParams = KdfParams
  { kdfMemoryKiB :: !Word
  , kdfTimeCost :: !Word
  , kdfParallelism :: !Word
  }

productionKdfParams, fastTestKdfParams :: KdfParams
productionKdfParams = KdfParams 131072 3 4
fastTestKdfParams = KdfParams 4096 1 1

runtimeKdfParamsRef :: IORef KdfParams
runtimeKdfParamsRef = unsafePerformIO (newIORef productionKdfParams)
{-# NOINLINE runtimeKdfParamsRef #-}

productionArgonMemoryKiB
  , productionArgonTimeCost
  , productionArgonParallelism
  , productionArgonOutputLength ::
    Word
productionArgonMemoryKiB = kdfMemoryKiB productionKdfParams
productionArgonTimeCost = kdfTimeCost productionKdfParams
productionArgonParallelism = kdfParallelism productionKdfParams
productionArgonOutputLength = fromIntegral @Int @Word wrappingKeySize

-- ---------------------------------------------------------------------------
-- Random-mode override (for testing)
-- ---------------------------------------------------------------------------

data RandomMode = SystemRandom | DeterministicRandom !Word64

randomModeRef :: IORef RandomMode
randomModeRef = unsafePerformIO (newIORef SystemRandom)
{-# NOINLINE randomModeRef #-}

readRuntimeKdfParams :: IO KdfParams
readRuntimeKdfParams = readIORef runtimeKdfParamsRef

-- | Reduce Argon2id cost for fast tests while keeping all v2 envelope
-- structure intact.
withFastKdfForTesting :: IO a -> IO a
withFastKdfForTesting = bracket install restore . const
  where
    install = do
      original <- readIORef runtimeKdfParamsRef
      writeIORef runtimeKdfParamsRef fastTestKdfParams
      pure original
    restore original = writeIORef runtimeKdfParamsRef original

-- | Replace system randomness with a deterministic counter for reproducible
-- test output.
withDeterministicRandomnessForTesting :: IO a -> IO a
withDeterministicRandomnessForTesting = bracket install restore . const
  where
    install = do
      original <- readIORef randomModeRef
      writeIORef randomModeRef (DeterministicRandom 0)
      pure original
    restore original = writeIORef randomModeRef original

-- ---------------------------------------------------------------------------
-- Public types
-- ---------------------------------------------------------------------------

newtype Signature = Signature ByteString
  deriving (Eq, NFData, Show)

data XPrvFormat = LegacyV1 | EnvelopeV2
  deriving (Eq, Show)

data XPrvError
  = XPrvDecodeError
  | XPrvUnsupportedVersion
  | XPrvUnsupportedKdf
  | XPrvUnsupportedCipher
  | XPrvInvalidKdfParams
  | XPrvInvalidSaltLength
  | XPrvInvalidNonceLength
  | XPrvInvalidTagLength
  | XPrvInvalidCiphertextLength
  | XPrvAuthenticationFailed
  | XPrvInvalidSecretKey
  | XPrvInvalidPublicKey
  | XPrvInvalidChainCode
  | XPrvPublicKeyMismatch
  | XPrvInternalError
  deriving (Eq, Show)

newtype EncryptedKey = EncryptedKey ByteString
  deriving (Show, Eq, NFData, ByteArrayAccess)

-- ---------------------------------------------------------------------------
-- V2 envelope data
-- ---------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SALT
------------------------------------------------------------------------------

type SALT_SIZE = 32

saltSize :: Int
saltSize = fromInteger (natVal (Proxy @SALT_SIZE))

newtype Salt = Salt {unSalt :: PinnedSizedBytes SALT_SIZE}
  deriving (Eq, Show)
newtype SaltPtr = SaltPtr (Ptr Word8)

withSaltPtr :: Salt -> (SaltPtr -> IO a) -> IO a
withSaltPtr (Salt publicKey) action =
  psbUseAsCPtr publicKey (action . SaltPtr)
{-# INLINE withSaltPtr #-}

mkSalt :: MonadFail f => ByteString -> f Salt
mkSalt bs = Salt <$> psbFromByteStringM bs

saltByteArray :: Salt -> ByteArray
saltByteArray = psbToByteArray . unSalt

saltByteString :: Salt -> ByteString
saltByteString = psbToByteString . unSalt

encodeSalt :: Salt -> Encoding
encodeSalt = toCBOR . psbToByteArray . unSalt

decodeSalt :: Decoder s Salt
decodeSalt = do
  saltBytes <- decodeBytes
  case mkSalt saltBytes of
    Nothing -> failDecoder XPrvInvalidSaltLength
    Just salt -> pure salt

------------------------------------------------------------------------------
-- NONCE
------------------------------------------------------------------------------

-- TODO: Derive from `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES`
type NONCE_SIZE = 24

nonceSize :: Int
nonceSize = fromInteger (natVal (Proxy @NONCE_SIZE))

newtype Nonce = Nonce {unNonce :: PinnedSizedBytes NONCE_SIZE}
  deriving (Eq, Show)
newtype NoncePtr = NoncePtr (Ptr Word8)

withNoncePtr :: Nonce -> (NoncePtr -> IO a) -> IO a
withNoncePtr (Nonce publicKey) action =
  psbUseAsCPtr publicKey (action . NoncePtr)
{-# INLINE withNoncePtr #-}

mkNonce :: MonadFail f => ByteString -> f Nonce
mkNonce bs = Nonce <$> psbFromByteStringM bs

nonceByteArray :: Nonce -> ByteArray
nonceByteArray = psbToByteArray . unNonce

nonceByteString :: Nonce -> ByteString
nonceByteString = psbToByteString . unNonce

encodeNonce :: Nonce -> Encoding
encodeNonce = toCBOR . psbToByteArray . unNonce

decodeNonce :: Decoder s Nonce
decodeNonce = do
  nonceBytes <- decodeBytes
  case mkNonce nonceBytes of
    Nothing -> failDecoder XPrvInvalidNonceLength
    Just nonce -> pure nonce

------------------------------------------------------------------------------
-- TAG
------------------------------------------------------------------------------

-- TODO: Derive from: `crypto_aead_xchacha20poly1305_ietf_ABYTES`
type TAG_SIZE = 16

tagSize :: Int
tagSize = fromInteger (natVal (Proxy @TAG_SIZE))

newtype Tag = Tag {unTag :: PinnedSizedBytes TAG_SIZE}
  deriving (Eq, Show)
newtype TagPtr = TagPtr (Ptr Word8)

withTagPtr :: Tag -> (TagPtr -> IO a) -> IO a
withTagPtr (Tag publicKey) action =
  psbUseAsCPtr publicKey (action . TagPtr)
{-# INLINE withTagPtr #-}

mkTag :: MonadFail f => ByteString -> f Tag
mkTag bs = Tag <$> psbFromByteStringM bs

tagByteArray :: Tag -> ByteArray
tagByteArray = psbToByteArray . unTag

tagByteString :: Tag -> ByteString
tagByteString = psbToByteString . unTag

encodeTag :: Tag -> Encoding
encodeTag = toCBOR . psbToByteArray . unTag

decodeTag :: Decoder s Tag
decodeTag = do
  tagBytes <- decodeBytes
  case mkTag tagBytes of
    Nothing -> failDecoder XPrvInvalidTagLength
    Just tag -> pure tag

------------------------------------------------------------------------------
-- WRAPPING_KEY
------------------------------------------------------------------------------

-- TODO: Derive from: `crypto_aead_xchacha20poly1305_ietf_KEYBYTES`
type WRAPPING_KEY_SIZE = 32

-- | Plaintext version of the wrapping key used for creating signatures
newtype WrappingKey = WrappingKey {_unWrappingKey :: MLockedSizedBytes WRAPPING_KEY_SIZE}

newtype WrappingKeyPtr = WrappingKeyPtr (Ptr Word8)

wrappingKeySize :: Int
wrappingKeySize = fromInteger (natVal (Proxy @WRAPPING_KEY_SIZE))

withWrappingKeyPtr :: WrappingKey -> (WrappingKeyPtr -> IO a) -> IO a
withWrappingKeyPtr (WrappingKey wrappingKey) action =
  mlsbUseAsCPtr wrappingKey (action . WrappingKeyPtr)
{-# INLINE withWrappingKeyPtr #-}

data Envelope = Envelope
  { eSalt :: !Salt
  , eNonce :: !Nonce
  , ePublicKey :: !PublicKey
  , eChainCode :: !ChainCode
  , eEncSecretKey :: !EncSecretKey
  , eTag :: !Tag
  }
  deriving (Eq, Show)

-- FFI pointer newtypes
newtype MasterKeyPtr = MasterKeyPtr (Ptr Word8)
newtype SignaturePtr = SignaturePtr (Ptr Word8)
newtype PassPhrasePtr = PassPhrasePtr (Ptr Word8)

type CDerivationScheme = CInt

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

-- | Construct `EncryptedKey` from bytes.
mkEncryptedKey :: ByteString -> Either XPrvError EncryptedKey
mkEncryptedKey bs =
  let eKey = EncryptedKey bs
   in eKey <$ validateSerializedKey eKey

-- | In order to promote smoother migration from @cardano-crypto@. Use `mkEncryptedKey` instead
encryptedKey :: ByteString -> Either XPrvError EncryptedKey
encryptedKey = mkEncryptedKey
{-# DEPRECATED encryptedKey "In favor of `mkEncryptedKey`" #-}

validateSerializedKey :: EncryptedKey -> Either XPrvError ()
validateSerializedKey eKey =
  case encryptedKeyFormat eKey of
    LegacyV1 -> Right ()
    EnvelopeV2 -> () <$ decodeEncryptedKeyV2 eKey

encryptedKeyFormat :: EncryptedKey -> XPrvFormat
encryptedKeyFormat (EncryptedKey bs)
  | BS.length bs == keyMaterialSize = LegacyV1
  | otherwise = EnvelopeV2

unEncryptedKey :: EncryptedKey -> ByteString
unEncryptedKey (EncryptedKey e) = e

encryptedCreate ::
  (ByteArrayAccess passphrase, ByteArrayAccess secret, ByteArrayAccess cc) =>
  secret -> passphrase -> cc -> IO (Either XPrvError EncryptedKey)
encryptedCreate sec pass cc
  | B.length sec /= 32 = pure (Left XPrvInvalidSecretKey)
  | B.length cc /= chainCodeSize = pure (Left XPrvInvalidChainCode)
  | otherwise = legacyMaterialFromSecret sec cc (wrapKeyMaterial pass)

encryptedCreateDirectWithTweak ::
  (ByteArrayAccess passphrase, ByteArrayAccess secret) =>
  secret -> passphrase -> IO (Either XPrvError EncryptedKey)
encryptedCreateDirectWithTweak sec pass
  | B.length sec /= 96 = pure (Left XPrvInvalidSecretKey)
  | otherwise = legacyMaterialFromMasterKey sec (wrapKeyMaterial pass)

encryptedValidatePassphrase ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> IO (Either XPrvError ())
encryptedValidatePassphrase eKey pass =
  withDecryptedKeyMaterial eKey pass (\_ -> pure $ Right ())

encryptedChangePassphrase ::
  (ByteArrayAccess oldPassPhrase, ByteArrayAccess newPassPhrase) =>
  oldPassPhrase -> newPassPhrase -> EncryptedKey -> IO (Either XPrvError EncryptedKey)
encryptedChangePassphrase oldPass newPass eKey =
  withDecryptedKeyMaterial eKey oldPass (wrapKeyMaterial newPass)

encryptedSign ::
  (ByteArrayAccess passphrase, ByteArrayAccess msg) =>
  EncryptedKey -> passphrase -> msg -> IO (Either XPrvError Signature)
encryptedSign eKey pass msg =
  withDecryptedKeyMaterial eKey pass $ \keyMaterial ->
    withKeyMaterialPtr keyMaterial $ \keyMaterialPtr -> do
      (status, sig) <-
        B.allocRet signatureSize $ \outSig ->
          withByteArray msg $ \msgPtr ->
            wallet_sign
              keyMaterialPtr
              msgPtr
              (fromIntegral $ B.length msg)
              (coerce outSig)
      pure (if status /= 0 then Left XPrvInternalError else Right (Signature sig))

encryptedDerivePrivate ::
  ByteArrayAccess passphrase =>
  DerivationScheme ->
  EncryptedKey ->
  passphrase ->
  DerivationIndex ->
  IO (Either XPrvError EncryptedKey)
encryptedDerivePrivate dScheme eKey pass childIndex =
  withDecryptedKeyMaterial eKey pass $ \parentKeyMaterial ->
    legacyDerivePrivate dScheme parentKeyMaterial childIndex (wrapKeyMaterial pass)

encryptedDerivePublic ::
  DerivationScheme ->
  (PublicKey, ChainCode) ->
  DerivationIndex ->
  (PublicKey, ChainCode)
encryptedDerivePublic dscheme (publicKey, cc) childIndex
  | childIndex >= 0x80000000 =
      error "encryptedDerivePublic: cannot derive hardened key from public key"
  | otherwise = unsafePerformIO $ do
      fmap (first PublicKey) $ psbCreateResult $ \publicKeyPtrOut ->
        fmap ChainCode $ psbCreate $ \ccOutPtr ->
          withPublicKeyPtr publicKey $ \publicKeyPtr ->
            withChainCodePtr cc $ \chainCodePtr -> do
              r <-
                wallet_derive_public
                  publicKeyPtr
                  chainCodePtr
                  childIndex
                  (PublicKeyPtr publicKeyPtrOut)
                  (ChainCodePtr ccOutPtr)
                  (dschemeToC dscheme)
              if r /= 0
                then error "encryptedDerivePublic: hardened index check failed"
                else pure ()

encryptedPublic :: HasCallStack => EncryptedKey -> PublicKey
encryptedPublic eKey@(EncryptedKey eKeyBytes) =
  case encryptedKeyFormat eKey of
    LegacyV1 -> errorFail $ mkPublicKey $ sub secretKeySize publicKeySize eKeyBytes
    EnvelopeV2 -> either (const badEnvelope) ePublicKey (decodeEncryptedKeyV2 eKey)
  where
    badEnvelope = error "encryptedPublic: invalid v2 envelope"

encryptedChainCode :: HasCallStack => EncryptedKey -> ChainCode
encryptedChainCode eKey@(EncryptedKey eKeyBytes) =
  case encryptedKeyFormat eKey of
    LegacyV1 ->
      errorFail $ mkChainCode $ sub (secretKeySize + publicKeySize) chainCodeSize eKeyBytes
    EnvelopeV2 -> either (const badEnvelope) eChainCode (decodeEncryptedKeyV2 eKey)
  where
    badEnvelope = error "encryptedChainCode: invalid v2 envelope"

-- ---------------------------------------------------------------------------
-- Internal: CBOR V2 envelope codec
-- ---------------------------------------------------------------------------

decodeEncryptedKeyV2 :: EncryptedKey -> Either XPrvError Envelope
decodeEncryptedKeyV2 (EncryptedKey eKeyBytes) =
  case CBOR.deserialiseFromBytes decodeEnvelope (BL.fromStrict eKeyBytes) of
    Right (rest, envelope)
      | BL.null rest -> Right envelope
    _ -> Left XPrvDecodeError

decodeEnvelope :: Decoder s Envelope
decodeEnvelope = do
  decodeListLenOf 9
  version <- decodeWord
  when (version /= v2Version) (failDecoder XPrvUnsupportedVersion)
  kdfId <- decodeWord
  when (kdfId /= argon2idId) (failDecoder XPrvUnsupportedKdf)
  decodeListLenOf 4
  memoryKiB <- decodeWord
  timeCost <- decodeWord
  parallelism <- decodeWord
  outputLength <- decodeWord
  when
    ( memoryKiB /= productionArgonMemoryKiB
        || timeCost /= productionArgonTimeCost
        || parallelism /= productionArgonParallelism
        || outputLength /= productionArgonOutputLength
    )
    (failDecoder XPrvInvalidKdfParams)
  salt <- decodeSalt
  cipherId <- decodeWord
  when (cipherId /= xchacha20poly1305Id) (failDecoder XPrvUnsupportedCipher)
  nonce <- decodeNonce
  aad <- decodeBytes
  encSecretKey <- decodeEncSecretKey
  tag <- decodeTag
  (pub, cc) <- either failDecoder pure $ decodeAad aad
  pure $
    Envelope
      { eSalt = salt
      , eNonce = nonce
      , ePublicKey = pub
      , eChainCode = cc
      , eEncSecretKey = encSecretKey
      , eTag = tag
      }

encodeEnvelope :: Envelope -> ByteString
encodeEnvelope envelope =
  CBOR.toStrictByteString $
    mconcat
      [ encodeListLen 9
      , encodeWord v2Version
      , encodeWord argon2idId
      , encodeListLen 4
      , encodeWord productionArgonMemoryKiB
      , encodeWord productionArgonTimeCost
      , encodeWord productionArgonParallelism
      , encodeWord productionArgonOutputLength
      , encodeSalt (eSalt envelope)
      , encodeWord xchacha20poly1305Id
      , encodeNonce (eNonce envelope)
      , encodeBytes (encodeAad (ePublicKey envelope) (eChainCode envelope))
      , encodeEncSecretKey (eEncSecretKey envelope)
      , encodeTag (eTag envelope)
      ]

encodeAad :: PublicKey -> ChainCode -> ByteString
encodeAad publicKey cc =
  CBOR.toStrictByteString $
    mconcat
      [ encodeListLen 8
      , encodeWord v2Version
      , encodeWord argon2idId
      , encodeListLen 4
      , encodeWord productionArgonMemoryKiB
      , encodeWord productionArgonTimeCost
      , encodeWord productionArgonParallelism
      , encodeWord productionArgonOutputLength
      , encodeWord xchacha20poly1305Id
      , encodeWord 1
      , encodeInt secretKeySize
      , encodePublicKey publicKey
      , encodeChainCode cc
      ]

decodeAad :: ByteString -> Either XPrvError (PublicKey, ChainCode)
decodeAad bs =
  case CBOR.deserialiseFromBytes decodeAadFields (BL.fromStrict bs) of
    Right (rest, result)
      | BL.null rest -> Right result
    _ -> Left XPrvDecodeError

decodeAadFields :: Decoder s (PublicKey, ChainCode)
decodeAadFields = do
  decodeListLenOf 8
  version <- decodeWord
  when (version /= v2Version) (failDecoder XPrvUnsupportedVersion)
  kdfId <- decodeWord
  when (kdfId /= argon2idId) (failDecoder XPrvUnsupportedKdf)
  decodeListLenOf 4
  memoryKiB <- decodeWord
  timeCost <- decodeWord
  parallelism <- decodeWord
  outputLength <- decodeWord
  when
    ( memoryKiB /= productionArgonMemoryKiB
        || timeCost /= productionArgonTimeCost
        || parallelism /= productionArgonParallelism
        || outputLength /= productionArgonOutputLength
    )
    (failDecoder XPrvInvalidKdfParams)
  cipherId <- decodeWord
  when (cipherId /= xchacha20poly1305Id) (failDecoder XPrvUnsupportedCipher)
  payloadKind <- decodeWord
  when (payloadKind /= 1) (failDecoder XPrvDecodeError)
  payloadLen <- decodeWord
  when (payloadLen /= fromIntegral secretKeySize) (failDecoder XPrvInvalidCiphertextLength)
  pubKeyBytes <- decodeBytes
  chainCodeBytes <- decodeBytes
  case mkPublicKey pubKeyBytes of
    Nothing -> failDecoder XPrvInvalidPublicKey
    Just publicKey ->
      case mkChainCode chainCodeBytes of
        Nothing -> failDecoder XPrvInvalidChainCode
        Just chainCode -> pure (publicKey, chainCode)

-- ---------------------------------------------------------------------------
-- Internal: v2 encrypt / decrypt
-- ---------------------------------------------------------------------------

withDecryptedKeyMaterial ::
  ByteArrayAccess passphrase =>
  EncryptedKey ->
  passphrase ->
  (KeyMaterial Validated -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
withDecryptedKeyMaterial ekey pass action =
  case encryptedKeyFormat ekey of
    LegacyV1 -> pure (Left XPrvDecodeError)
    EnvelopeV2 ->
      mlsbCreate SecretKey $ \secretKey ->
        decryptKeyMaterialV2 secretKey ekey pass >>= \case
          Left err -> pure $ Left err
          Right uncheckedKeyMaterial ->
            validateKeyMaterial uncheckedKeyMaterial >>= \case
              Left err -> pure $ Left err
              Right keyMaterial -> action keyMaterial

decryptKeyMaterialV2 ::
  ByteArrayAccess passphrase =>
  -- | Empty SecretKey that will be populated from EncryptedKey
  SecretKey ->
  EncryptedKey ->
  passphrase ->
  IO (Either XPrvError (KeyMaterial Unchecked))
decryptKeyMaterialV2 secretKey eKey pass =
  case decodeEncryptedKeyV2 eKey of
    Left err -> pure (Left err)
    Right envelope -> do
      withWrappingKey pass (eSalt envelope) $ \wrappingKey -> do
        let aad = encodeAad (ePublicKey envelope) (eChainCode envelope)
        status <-
          withSecretKeyPtr secretKey $ \secretKeyPtr ->
            withEncSecretKeyPtr (eEncSecretKey envelope) $ \encSecretKeyPtr ->
              withTagPtr (eTag envelope) $ \tagPtr ->
                withByteArray aad $ \ad ->
                  withNoncePtr (eNonce envelope) $ \noncePtr ->
                    withWrappingKeyPtr wrappingKey $ \wrappingKeyPtr ->
                      wallet_xchacha20poly1305_decrypt
                        secretKeyPtr
                        encSecretKeyPtr
                        tagPtr
                        ad
                        (fromIntegral @Int @CULLong $ BS.length aad)
                        noncePtr
                        wrappingKeyPtr
        if status /= 0
          then
            pure $ Left XPrvAuthenticationFailed
          else
            pure $
              Right $
                KeyMaterial
                  { kmSecretKey = secretKey
                  , kmPublicKey = ePublicKey envelope
                  , kmChainCode = eChainCode envelope
                  }

wrapKeyMaterial ::
  ByteArrayAccess passphrase =>
  passphrase -> KeyMaterial Validated -> IO (Either XPrvError EncryptedKey)
wrapKeyMaterial pass KeyMaterial {kmSecretKey, kmPublicKey, kmChainCode} = do
  eSalt <- fmap Salt <$> randomBytesIO
  eNonce <- fmap Nonce <$> randomBytesIO
  case (,) <$> eSalt <*> eNonce of
    Left err -> pure (Left err)
    Right (salt, nonce) -> do
      withWrappingKey pass salt $ \wrappingKey -> do
        let aad = encodeAad kmPublicKey kmChainCode
        withSecretKeyPtr kmSecretKey $ \skPtr -> do
          (encSecretKey, (tag, status)) <-
            fmap (first EncSecretKey) $ psbCreateResult $ \outEncSecretKey ->
              fmap (first Tag) $ psbCreateResult $ \outTagPtr ->
                withByteArray aad $ \ad ->
                  withNoncePtr nonce $ \noncePtr ->
                    withWrappingKeyPtr wrappingKey $ \wrappingKeyPtr ->
                      wallet_xchacha20poly1305_encrypt
                        (EncSecretKeyPtr outEncSecretKey)
                        (TagPtr outTagPtr)
                        skPtr
                        ad
                        (fromIntegral @Int @CULLong $ BS.length aad)
                        noncePtr
                        wrappingKeyPtr
          if status /= 0
            then pure (Left XPrvInternalError)
            else
              pure $
                Right $
                  EncryptedKey $
                    encodeEnvelope $
                      Envelope
                        { eSalt = salt
                        , eNonce = nonce
                        , ePublicKey = kmPublicKey
                        , eChainCode = kmChainCode
                        , eEncSecretKey = encSecretKey
                        , eTag = tag
                        }

-- | Verify that associated public key matches the secret key in the `KeyMaterial`
validateKeyMaterial :: KeyMaterial Unchecked -> IO (Either XPrvError (KeyMaterial Validated))
validateKeyMaterial KeyMaterial {..} =
  withSecretKeyPtr kmSecretKey $ \secretKeyPtr -> do
    withPublicKeyPtr kmPublicKey $ \publicKeyPtr -> do
      r <- wallet_validate secretKeyPtr publicKeyPtr
      pure $
        if r /= 0
          then Left XPrvPublicKeyMismatch
          else Right (KeyMaterial {..})

-- ---------------------------------------------------------------------------
-- Internal: locked memory helpers
-- ---------------------------------------------------------------------------

-- | Build a temporary 128-byte locked buffer (ekey || pkey || cc) from
-- 'KeyMaterial' and pass a pointer to it to the action.  The buffer is zeroed
-- and freed when the action returns (normally or via exception).
withKeyMaterialPtr :: KeyMaterial v -> (KeyMaterialPtr -> IO r) -> IO r
withKeyMaterialPtr KeyMaterial {kmSecretKey, kmPublicKey, kmChainCode} action =
  allocaKeyMaterialBuffer $ \ptr@(KeyMaterialPtr keyMaterialPtr) -> do
    withSecretKeyPtr kmSecretKey $ \(SecretKeyPtr skPtr) ->
      copyBytes keyMaterialPtr skPtr secretKeySize
    withPublicKeyPtr kmPublicKey $ \(PublicKeyPtr pkPtr) ->
      copyBytes (keyMaterialPtr `plusPtr` secretKeySize) pkPtr publicKeySize
    withChainCodePtr kmChainCode $ \(ChainCodePtr ccPtr) ->
      copyBytes (keyMaterialPtr `plusPtr` (secretKeySize + publicKeySize)) ccPtr chainCodeSize
    action ptr

-- | Call a C function that writes a 128-byte @encrypted_key@ struct to the
-- pointer it receives, then split the result into 'KeyMaterial'.  On failure
-- (non-zero return) returns 'Left onFailure'.
withNewKeyMaterial ::
  XPrvError ->
  -- | Action that will use the newly populated `KeyMaterial`
  (KeyMaterial Validated -> IO (Either XPrvError a)) ->
  -- | Action that will populate `KeyMaterialPtr` on the C-side, after which it
  -- will usable in the `KeyMaterial` for the action above
  (KeyMaterialPtr -> IO CInt) ->
  IO (Either XPrvError a)
withNewKeyMaterial onFailure keyMaterialAction fillKeyMaterialPtrAction =
  allocaKeyMaterialBuffer $ \keyMaterialPtr@(KeyMaterialPtr inPtr) -> do
    r <- fillKeyMaterialPtrAction keyMaterialPtr
    if r /= 0
      then pure (Left onFailure)
      else mlsbCreate SecretKey $ \secretKey -> do
        withSecretKeyPtr secretKey $ \(SecretKeyPtr skPtr) -> copyBytes skPtr inPtr secretKeySize
        publicKey <-
          psbCreate $ \pkPtr ->
            copyBytes pkPtr (inPtr `plusPtr` secretKeySize) publicKeySize
        chainCode <-
          psbCreate $ \ccPtr ->
            copyBytes ccPtr (inPtr `plusPtr` (secretKeySize + publicKeySize)) chainCodeSize
        eKeyMaterial <-
          validateKeyMaterial $
            KeyMaterial
              { kmSecretKey = secretKey
              , kmPublicKey = PublicKey publicKey
              , kmChainCode = ChainCode chainCode
              }
        case eKeyMaterial of
          Left err -> pure $ Left err
          Right keyMaterial -> keyMaterialAction keyMaterial

-- ---------------------------------------------------------------------------
-- Internal: key-material construction (using C/ed25519)
-- ---------------------------------------------------------------------------

legacyMaterialFromSecret ::
  (ByteArrayAccess secret, ByteArrayAccess cc) =>
  secret ->
  cc ->
  (KeyMaterial Validated -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
legacyMaterialFromSecret sec cc action =
  withNewKeyMaterial XPrvInvalidSecretKey action $ \outPtr ->
    withByteArray sec $ \psec ->
      withByteArray cc $ \pcc ->
        wallet_from_secret (coerce psec) (coerce pcc) outPtr

legacyMaterialFromMasterKey ::
  ByteArrayAccess secret =>
  secret ->
  (KeyMaterial Validated -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
legacyMaterialFromMasterKey sec action =
  withNewKeyMaterial XPrvInvalidSecretKey action $ \outPtr ->
    withByteArray sec $ \psec ->
      wallet_new_from_mkg (MasterKeyPtr psec) outPtr

legacyDerivePrivate ::
  DerivationScheme ->
  KeyMaterial Validated ->
  DerivationIndex ->
  (KeyMaterial Validated -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
legacyDerivePrivate dscheme parent childIndex action =
  withKeyMaterialPtr parent $ \inPtr ->
    withNewKeyMaterial XPrvInternalError action $ \outPtr ->
      wallet_derive_private inPtr childIndex outPtr (dschemeToC dscheme)

-- ---------------------------------------------------------------------------
-- Internal: KDF and random bytes
-- ---------------------------------------------------------------------------

withWrappingKey ::
  ByteArrayAccess passphrase =>
  passphrase -> Salt -> (WrappingKey -> IO (Either XPrvError a)) -> IO (Either XPrvError a)
withWrappingKey pass salt action = do
  params <- readRuntimeKdfParams
  let memBytes = fromIntegral (kdfMemoryKiB params) * 1024 :: Word64
  mlsbCreate WrappingKey $ \wrappingKey ->
    withWrappingKeyPtr wrappingKey $ \outWrappingKeyPtr ->
      withByteArray pass $ \ppass ->
        withSaltPtr salt $ \saltPtr -> do
          status <-
            wallet_argon2id
              outWrappingKeyPtr
              (coerce ppass)
              (fromIntegral @Int @CULLong $ B.length pass)
              saltPtr
              (fromIntegral @Word @CULLong $ kdfTimeCost params)
              (fromIntegral @Word64 @CSize memBytes)
          if status == 0
            then
              action wrappingKey
            else
              pure $ Left XPrvInternalError

randomBytesIO :: KnownNat n => IO (Either XPrvError (PinnedSizedBytes n))
randomBytesIO = do
  mode <- readIORef randomModeRef
  case mode of
    SystemRandom -> do
      (bytes, status) <- psbCreateResultLen wallet_randombytes
      pure $ if status == 0 then Right bytes else Left XPrvInternalError
    DeterministicRandom counter -> do
      let
        len = fromInteger (natVal bytes)
        bytes = psbFromByteString (deterministicBytes len counter)
      writeIORef randomModeRef (DeterministicRandom (counter + 1))
      pure (Right bytes)

deterministicBytes :: Int -> Word64 -> ByteString
deterministicBytes len counter =
  BS.pack $
    take len $
      cycle
        [ fromIntegral counter
        , fromIntegral (counter `shiftR` 8)
        , fromIntegral (counter `shiftR` 16)
        , fromIntegral (counter `shiftR` 24)
        , fromIntegral (counter `shiftR` 32)
        , fromIntegral (counter `shiftR` 40)
        , fromIntegral (counter `shiftR` 48)
        , fromIntegral (counter `shiftR` 56)
        ]

-- ---------------------------------------------------------------------------
-- Misc helpers
-- ---------------------------------------------------------------------------

sub :: B.ByteArray c => Int -> Int -> c -> c
sub ofs sz = B.take sz . B.drop ofs

dschemeToC :: DerivationScheme -> CDerivationScheme
dschemeToC DerivationScheme1 = 1
dschemeToC DerivationScheme2 = 2

failDecoder :: XPrvError -> Decoder s a
failDecoder = fail . show

-- ---------------------------------------------------------------------------
-- FFI declarations
-- ---------------------------------------------------------------------------

foreign import ccall "cardano_crypto_wallet_from_secret"
  wallet_from_secret ::
    SecretKeyPtr ->
    ChainCodePtr ->
    KeyMaterialPtr ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_new_from_mkg"
  wallet_new_from_mkg ::
    MasterKeyPtr ->
    KeyMaterialPtr ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_validate"
  wallet_validate ::
    SecretKeyPtr ->
    PublicKeyPtr ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_sign"
  wallet_sign ::
    KeyMaterialPtr ->
    Ptr Word8 ->
    Word32 ->
    SignaturePtr ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_derive_private"
  wallet_derive_private ::
    KeyMaterialPtr ->
    DerivationIndex ->
    KeyMaterialPtr ->
    CDerivationScheme ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_derive_public"
  wallet_derive_public ::
    PublicKeyPtr ->
    ChainCodePtr ->
    DerivationIndex ->
    PublicKeyPtr ->
    ChainCodePtr ->
    CDerivationScheme ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_randombytes"
  wallet_randombytes :: Ptr a -> CSize -> IO CInt

foreign import ccall "cardano_crypto_wallet_argon2id"
  wallet_argon2id ::
    WrappingKeyPtr ->
    PassPhrasePtr ->
    CULLong ->
    SaltPtr ->
    CULLong ->
    CSize ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_xchacha20poly1305_encrypt"
  wallet_xchacha20poly1305_encrypt ::
    EncSecretKeyPtr ->
    TagPtr ->
    SecretKeyPtr ->
    Ptr Word8 ->
    CULLong ->
    NoncePtr ->
    WrappingKeyPtr ->
    IO CInt

foreign import ccall "cardano_crypto_wallet_xchacha20poly1305_decrypt"
  wallet_xchacha20poly1305_decrypt ::
    SecretKeyPtr ->
    EncSecretKeyPtr ->
    TagPtr ->
    Ptr Word8 ->
    CULLong ->
    NoncePtr ->
    WrappingKeyPtr ->
    IO CInt
