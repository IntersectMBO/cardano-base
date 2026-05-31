{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}

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
  mkPublicKey,
  fromPublicKey,

  -- * Construction & validation
  encryptedCreate,
  encryptedCreateDirectWithTweak,
  encryptedKey,
  unEncryptedKey,
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
  psbFromByteStringCheck,
  psbFromByteStringM,
  psbToByteArray,
  psbToByteString,
  psbUseAsCPtr,
 )
import Control.DeepSeq
import Control.Exception (bracket)
import Control.Monad (when)
import Control.Monad.Trans.Fail.String (errorFail)
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
import GHC.TypeLits (natVal)
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

legacyKeySize, ccSize, signatureSize :: Int
legacyKeySize = 64
ccSize = 32
signatureSize = 64

------------------------------------------------------------------------------
-- SECRET_KEY
------------------------------------------------------------------------------

type SECRET_KEY_SIZE = 64

secretKeySize :: Int
secretKeySize = fromInteger (natVal (Proxy @SECRET_KEY_SIZE))

newtype SecretKey = SecretKey {unSecretKey :: MLockedSizedBytes SECRET_KEY_SIZE}

withSecretKeyPtr :: SecretKey -> (SecretKeyPtr -> IO a) -> IO a
withSecretKeyPtr (SecretKey secretKey) action =
  mlsbUseAsCPtr secretKey (action . SecretKeyPtr)
{-# INLINE withSecretKeyPtr #-}

finalizeSecretKey :: SecretKey -> IO ()
finalizeSecretKey = mlsbFinalize . unSecretKey

------------------------------------------------------------------------------
-- PUBLIC_KEY
------------------------------------------------------------------------------

type PUBLIC_KEY_SIZE = 32

publicKeySize :: Int
publicKeySize = fromInteger (natVal (Proxy @PUBLIC_KEY_SIZE))

newtype PublicKey = PublicKey {unPublicKey :: PinnedSizedBytes PUBLIC_KEY_SIZE}
  deriving (Eq, Show)

withPublicKeyPtr :: PublicKey -> (PublicKeyPtr -> IO a) -> IO a
withPublicKeyPtr (PublicKey publicKey) action =
  psbUseAsCPtr publicKey (action . PublicKeyPtr)
{-# INLINE withPublicKeyPtr #-}

mkPublicKey :: MonadFail f => ByteString -> f PublicKey
mkPublicKey bs = PublicKey <$> psbFromByteStringM bs

fromPublicKey :: PublicKey -> ByteString
fromPublicKey = psbToByteString . unPublicKey

encodePublicKey :: PublicKey -> Encoding
encodePublicKey = toCBOR . psbToByteArray . unPublicKey

type ChainCode = ByteString
type Salt = ByteString
type Nonce = ByteString
type Ciphertext = ByteString
type AuthenticationTag = ByteString
type AadContext = ByteString

legacyTotalKeySize :: Int
legacyTotalKeySize = legacyKeySize + publicKeySize + ccSize

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
  , kdfOutputLength :: !Word
  }

productionKdfParams, fastTestKdfParams :: KdfParams
productionKdfParams = KdfParams 131072 3 4 32
fastTestKdfParams = KdfParams 4096 1 1 32

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
productionArgonOutputLength = kdfOutputLength productionKdfParams

saltSize, nonceSize, tagSize :: Int
saltSize = 32
nonceSize = 24
tagSize = 16

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

data V2Envelope = V2Envelope
  { v2Salt :: !Salt
  , v2Nonce :: !Nonce
  , v2PublicKey :: !PublicKey
  , v2ChainCode :: !ChainCode
  , v2Ciphertext :: !Ciphertext
  , v2Tag :: !AuthenticationTag
  }
  deriving (Eq, Show)

-- | Key material with the secret key in @sodium_malloc@'d locked memory.
data KeyMaterial = KeyMaterial
  { kmSecretKey :: !SecretKey
  , kmPublicKey :: !PublicKey
  , kmChainCode :: !ChainCode
  }

finalizeKeyMaterial :: KeyMaterial -> IO ()
finalizeKeyMaterial = finalizeSecretKey . kmSecretKey

-- FFI pointer newtypes
newtype SecretKeyPtr = SecretKeyPtr (Ptr Word8)
newtype MasterKeyPtr = MasterKeyPtr (Ptr Word8)
newtype PublicKeyPtr = PublicKeyPtr (Ptr Word8)
newtype ChainCodePtr = ChainCodePtr (Ptr Word8)
newtype EncryptedKeyPtr = EncryptedKeyPtr (Ptr Word8)
newtype SignaturePtr = SignaturePtr (Ptr Word8)
newtype PassPhrasePtr = PassPhrasePtr (Ptr Word8)
newtype SaltPtr = SaltPtr (Ptr Word8)
newtype NoncePtr = NoncePtr (Ptr Word8)
newtype TagPtr = TagPtr (Ptr Word8)
newtype CiphertextPtr = CiphertextPtr (Ptr Word8)
newtype WrappingKeyPtr = WrappingKeyPtr (Ptr Word8)

type CDerivationScheme = CInt

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

encryptedKey :: ByteString -> Either XPrvError EncryptedKey
encryptedKey bs = EncryptedKey bs <$ validateSerializedKey bs

encryptedKeyFormat :: EncryptedKey -> XPrvFormat
encryptedKeyFormat (EncryptedKey bs)
  | BS.length bs == legacyTotalKeySize = LegacyV1
  | otherwise = EnvelopeV2

unEncryptedKey :: EncryptedKey -> ByteString
unEncryptedKey (EncryptedKey e) = e

encryptedCreate ::
  (ByteArrayAccess passphrase, ByteArrayAccess secret, ByteArrayAccess cc) =>
  secret -> passphrase -> cc -> IO (Either XPrvError EncryptedKey)
encryptedCreate sec pass cc
  | B.length sec /= 32 = pure (Left XPrvInvalidSecretKey)
  | B.length cc /= ccSize = pure (Left XPrvInvalidChainCode)
  | otherwise = legacyMaterialFromSecret sec cc (wrapKeyMaterial pass)
{-# NOINLINE encryptedCreate #-}

encryptedCreateDirectWithTweak ::
  (ByteArrayAccess passphrase, ByteArrayAccess secret) =>
  secret -> passphrase -> IO (Either XPrvError EncryptedKey)
encryptedCreateDirectWithTweak sec pass
  | B.length sec /= 96 = pure (Left XPrvInvalidSecretKey)
  | otherwise = legacyMaterialFromMasterKey sec (wrapKeyMaterial pass)
{-# NOINLINE encryptedCreateDirectWithTweak #-}

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
    withLegacyStruct keyMaterial $ \legacyStructPtr -> do
      (status, sig) <-
        B.allocRet signatureSize $ \outSig ->
          withByteArray msg $ \msgPtr ->
            wallet_encrypted_sign
              (coerce legacyStructPtr)
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
      (newPublicKey, newCC) <-
        psbCreateResult $ \publicKeyPtrOut ->
          B.alloc ccSize $ \outCc ->
            withPublicKeyPtr publicKey $ \publicKeyPtr ->
              withByteArray cc $ \pcc -> do
                r <-
                  wallet_encrypted_derive_public
                    publicKeyPtr
                    (coerce pcc)
                    childIndex
                    (PublicKeyPtr publicKeyPtrOut)
                    (coerce outCc)
                    (dschemeToC dscheme)
                if r /= 0
                  then error "encryptedDerivePublic: hardened index check failed"
                  else pure ()
      pure (PublicKey newPublicKey, newCC)

encryptedPublic :: HasCallStack => EncryptedKey -> PublicKey
encryptedPublic (EncryptedKey ekey) =
  case encryptedKeyFormat (EncryptedKey ekey) of
    LegacyV1 -> errorFail $ mkPublicKey $ sub legacyKeySize publicKeySize ekey
    EnvelopeV2 -> either (const badEnvelope) v2PublicKey (decodeV2Envelope ekey)
  where
    badEnvelope = error "encryptedPublic: invalid v2 envelope"

encryptedChainCode :: EncryptedKey -> ByteString
encryptedChainCode (EncryptedKey ekey) =
  case encryptedKeyFormat (EncryptedKey ekey) of
    LegacyV1 -> sub (legacyKeySize + publicKeySize) ccSize ekey
    EnvelopeV2 -> either (const badEnvelope) v2ChainCode (decodeV2Envelope ekey)
  where
    badEnvelope = error "encryptedChainCode: invalid v2 envelope"

-- ---------------------------------------------------------------------------
-- Internal: serialization validation
-- ---------------------------------------------------------------------------

validateSerializedKey :: ByteString -> Either XPrvError ()
validateSerializedKey bs
  | BS.length bs == legacyTotalKeySize = Right ()
  | otherwise = decodeV2Envelope bs >> pure ()

-- ---------------------------------------------------------------------------
-- Internal: CBOR V2 envelope codec
-- ---------------------------------------------------------------------------

decodeV2Envelope :: ByteString -> Either XPrvError V2Envelope
decodeV2Envelope bs =
  case CBOR.deserialiseFromBytes decodeEnvelope (BL.fromStrict bs) of
    Right (rest, envelope)
      | BL.null rest -> Right envelope
    _ -> Left XPrvDecodeError

decodeEnvelope :: Decoder s V2Envelope
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
  salt <- decodeBytes
  when (BS.length salt /= saltSize) (failDecoder XPrvInvalidSaltLength)
  cipherId <- decodeWord
  when (cipherId /= xchacha20poly1305Id) (failDecoder XPrvUnsupportedCipher)
  nonce <- decodeBytes
  when (BS.length nonce /= nonceSize) (failDecoder XPrvInvalidNonceLength)
  aad <- decodeBytes
  ciphertext <- decodeBytes
  when (BS.length ciphertext /= legacyKeySize) (failDecoder XPrvInvalidCiphertextLength)
  tag <- decodeBytes
  when (BS.length tag /= tagSize) (failDecoder XPrvInvalidTagLength)
  (pub, cc) <- either failDecoder pure $ decodeAad aad
  pure $
    V2Envelope
      { v2Salt = salt
      , v2Nonce = nonce
      , v2PublicKey = pub
      , v2ChainCode = cc
      , v2Ciphertext = ciphertext
      , v2Tag = tag
      }

encodeV2Envelope :: V2Envelope -> ByteString
encodeV2Envelope envelope =
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
      , encodeBytes (v2Salt envelope)
      , encodeWord xchacha20poly1305Id
      , encodeBytes (v2Nonce envelope)
      , encodeBytes (encodeAad (v2PublicKey envelope) (v2ChainCode envelope))
      , encodeBytes (v2Ciphertext envelope)
      , encodeBytes (v2Tag envelope)
      ]

encodeAad :: PublicKey -> ChainCode -> AadContext
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
      , encodeWord (fromIntegral legacyKeySize)
      , encodePublicKey publicKey
      , encodeBytes cc
      ]

decodeAad :: AadContext -> Either XPrvError (PublicKey, ChainCode)
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
  when (payloadLen /= fromIntegral legacyKeySize) (failDecoder XPrvInvalidCiphertextLength)
  pubKeyBytes <- decodeBytes
  cc <- decodeBytes
  publicKey <- case psbFromByteStringCheck pubKeyBytes of
    Nothing -> failDecoder XPrvInvalidPublicKey
    Just pubKey -> pure $ PublicKey pubKey
  when (BS.length cc /= ccSize) (failDecoder XPrvInvalidChainCode)
  pure (publicKey, cc)

-- ---------------------------------------------------------------------------
-- Internal: v2 encrypt / decrypt
-- ---------------------------------------------------------------------------

withDecryptedKeyMaterial ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> (KeyMaterial -> IO (Either XPrvError a)) -> IO (Either XPrvError a)
withDecryptedKeyMaterial ekey pass action =
  case encryptedKeyFormat ekey of
    LegacyV1 -> pure (Left XPrvDecodeError)
    EnvelopeV2 ->
      bracket (decryptKeyMaterialV2 ekey pass) (mapM_ finalizeKeyMaterial) $ \case
        Left err -> pure $ Left err
        Right keyMaterial ->
          validateKeyMaterial keyMaterial >>= \case
            Left err -> pure $ Left err
            Right () -> action keyMaterial

-- | This function is unsafe and should not be exported. Whenver used it must have async exceptions
-- masked and resulting `KeyMaterial` must be finalized after the result served its use.
decryptKeyMaterialV2 ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> IO (Either XPrvError KeyMaterial)
decryptKeyMaterialV2 (EncryptedKey bs) pass =
  case decodeV2Envelope bs of
    Left err -> pure (Left err)
    Right envelope -> do
      eWrappingKey <- deriveWrappingKey pass (v2Salt envelope)
      case eWrappingKey of
        Left err -> pure (Left err)
        Right wrappingKey -> do
          let aad = encodeAad (v2PublicKey envelope) (v2ChainCode envelope)
          secretKey <- SecretKey <$> mlsbNewZero
          status <-
            withSecretKeyPtr secretKey $ \secretKeyPtr ->
              withByteArray (v2Ciphertext envelope) $ \ct ->
                withByteArray (v2Tag envelope) $ \tg ->
                  withByteArray aad $ \ad ->
                    withByteArray (v2Nonce envelope) $ \np ->
                      withByteArray wrappingKey $ \kp ->
                        wallet_sodium_xchacha20poly1305_decrypt
                          secretKeyPtr
                          (coerce ct)
                          (fromIntegral @Int @CULLong $ BS.length (v2Ciphertext envelope))
                          (coerce tg)
                          ad
                          (fromIntegral @Int @CULLong $ BS.length aad)
                          (coerce np)
                          (coerce kp)
          if status /= 0
            then do
              mlsbFinalize (unSecretKey secretKey)
              pure $ Left XPrvAuthenticationFailed
            else do
              pure $ Right $ KeyMaterial secretKey (v2PublicKey envelope) (v2ChainCode envelope)

wrapKeyMaterial ::
  ByteArrayAccess passphrase =>
  passphrase -> KeyMaterial -> IO (Either XPrvError EncryptedKey)
wrapKeyMaterial pass material = do
  eVal <- validateKeyMaterial material
  case eVal of
    Left err -> pure (Left err)
    Right () -> do
      eSalt <- randomBytesIO saltSize
      eNonce <- randomBytesIO nonceSize
      case (,) <$> eSalt <*> eNonce of
        Left err -> pure (Left err)
        Right (salt, nonce) -> do
          eWrappingKey <- deriveWrappingKey pass salt
          case eWrappingKey of
            Left err -> pure (Left err)
            Right wrappingKey -> do
              let aad = encodeAad (kmPublicKey material) (kmChainCode material)
              withSecretKeyPtr (kmSecretKey material) $ \skPtr -> do
                ((status, tag), ciphertext) <-
                  B.allocRet legacyKeySize $ \outCipher ->
                    B.allocRet tagSize $ \outTag ->
                      withByteArray aad $ \ad ->
                        withByteArray nonce $ \np ->
                          withByteArray wrappingKey $ \kp ->
                            wallet_sodium_xchacha20poly1305_encrypt
                              (coerce outCipher)
                              (coerce outTag)
                              skPtr
                              (fromIntegral @Int @CULLong legacyKeySize)
                              ad
                              (fromIntegral @Int @CULLong $ BS.length aad)
                              (coerce np)
                              (coerce kp)
                if status /= 0
                  then pure (Left XPrvInternalError)
                  else
                    pure $
                      Right $
                        EncryptedKey $
                          encodeV2Envelope $
                            V2Envelope salt nonce (kmPublicKey material) (kmChainCode material) ciphertext tag

validateKeyMaterial :: KeyMaterial -> IO (Either XPrvError ())
validateKeyMaterial mat =
  withLegacyStruct mat $ \inPtr ->
    bracket (mlsbNewZero :: IO (MLockedSizedBytes 128)) mlsbFinalize $ \outMlsb -> do
      r <-
        mlsbUseAsCPtr outMlsb $ \outPtr ->
          wallet_encrypted_decrypt (coerce inPtr) (coerce outPtr)
      pure (if r /= 0 then Left XPrvPublicKeyMismatch else Right ())

-- ---------------------------------------------------------------------------
-- Internal: locked memory helpers
-- ---------------------------------------------------------------------------

-- | Build a temporary 128-byte locked buffer (ekey || pkey || cc) from
-- 'KeyMaterial' and pass a pointer to it to the action.  The buffer is zeroed
-- and freed when the action returns (normally or via exception).
withLegacyStruct :: KeyMaterial -> (Ptr Word8 -> IO r) -> IO r
withLegacyStruct mat action =
  bracket (mlsbNewZero :: IO (MLockedSizedBytes 128)) mlsbFinalize $ \mlsb ->
    mlsbUseAsCPtr mlsb $ \base -> do
      withSecretKeyPtr (kmSecretKey mat) $ \(SecretKeyPtr skPtr) ->
        copyBytes base skPtr secretKeySize
      withPublicKeyPtr (kmPublicKey mat) $ \(PublicKeyPtr pkPtr) ->
        copyBytes (base `plusPtr` secretKeySize) (castPtr pkPtr) publicKeySize
      BS.useAsCStringLen (kmChainCode mat) $ \(ccPtr, _) ->
        copyBytes (base `plusPtr` (secretKeySize + publicKeySize)) (castPtr ccPtr) ccSize
      action base

-- | Call a C function that writes a 128-byte @encrypted_key@ struct to the
-- pointer it receives, then split the result into 'KeyMaterial'.  On failure
-- (non-zero return) returns 'Left onFailure'.  The caller owns the
-- 'MLockedSizedBytes 64' in the returned 'KeyMaterial' and must finalize it.
withEncryptedKeyOutput ::
  XPrvError ->
  (KeyMaterial -> IO (Either XPrvError a)) ->
  (Ptr Word8 -> IO CInt) ->
  IO (Either XPrvError a)
withEncryptedKeyOutput onFailure keyMaterialAction structPtrAction =
  bracket (mlsbNewZero :: IO (MLockedSizedBytes 128)) mlsbFinalize $ \tmpMlsb -> do
    r <- mlsbUseAsCPtr tmpMlsb structPtrAction
    if r /= 0
      then pure (Left onFailure)
      else mlsbUseAsCPtr tmpMlsb $ \tmpPtr -> do
        bracket mlsbNewZero mlsbFinalize $ \secretKey -> do
          mlsbUseAsCPtr secretKey $ \skPtr -> copyBytes skPtr tmpPtr secretKeySize
          publicKey <-
            psbCreate $ \pkPtr ->
              copyBytes pkPtr (tmpPtr `plusPtr` secretKeySize) publicKeySize
          cc <- BS.packCStringLen (castPtr (tmpPtr `plusPtr` (secretKeySize + publicKeySize)), 32)
          keyMaterialAction $
            KeyMaterial
              { kmSecretKey = SecretKey secretKey
              , kmPublicKey = PublicKey publicKey
              , kmChainCode = cc
              }

-- ---------------------------------------------------------------------------
-- Internal: key-material construction (using C/ed25519)
-- ---------------------------------------------------------------------------

legacyMaterialFromSecret ::
  (ByteArrayAccess secret, ByteArrayAccess cc) =>
  secret ->
  cc ->
  (KeyMaterial -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
legacyMaterialFromSecret sec cc action =
  withEncryptedKeyOutput XPrvInvalidSecretKey action $ \outPtr ->
    withByteArray sec $ \psec ->
      withByteArray cc $ \pcc ->
        wallet_encrypted_from_secret (coerce psec) (coerce pcc) (coerce outPtr)

legacyMaterialFromMasterKey ::
  ByteArrayAccess secret =>
  secret ->
  (KeyMaterial -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
legacyMaterialFromMasterKey sec action =
  withEncryptedKeyOutput XPrvInvalidSecretKey action $ \outPtr ->
    withByteArray sec $ \psec ->
      wallet_encrypted_new_from_mkg (MasterKeyPtr psec) (coerce outPtr)

legacyDerivePrivate ::
  DerivationScheme ->
  KeyMaterial ->
  DerivationIndex ->
  (KeyMaterial -> IO (Either XPrvError a)) ->
  IO (Either XPrvError a)
legacyDerivePrivate dscheme parent childIndex action =
  withLegacyStruct parent $ \inPtr ->
    withEncryptedKeyOutput XPrvInternalError action $ \outPtr ->
      wallet_encrypted_derive_private
        (coerce inPtr)
        childIndex
        (coerce outPtr)
        (dschemeToC dscheme)

-- ---------------------------------------------------------------------------
-- Internal: KDF and random bytes
-- ---------------------------------------------------------------------------

deriveWrappingKey ::
  ByteArrayAccess passphrase =>
  passphrase -> ByteString -> IO (Either XPrvError B.ScrubbedBytes)
deriveWrappingKey pass salt
  | BS.length salt /= saltSize = pure (Left XPrvInvalidSaltLength)
  | otherwise = do
      params <- readRuntimeKdfParams
      let outputLen = fromIntegral (kdfOutputLength params)
          memBytes = fromIntegral (kdfMemoryKiB params) * 1024 :: Word64
      (status, key) <-
        B.allocRet outputLen $ \out ->
          withByteArray pass $ \ppass ->
            withByteArray salt $ \psalt ->
              wallet_sodium_argon2id
                (coerce out)
                (fromIntegral @Int @CULLong outputLen)
                (coerce ppass)
                (fromIntegral @Int @CULLong $ B.length pass)
                (coerce psalt)
                (fromIntegral @Word @CULLong $ kdfTimeCost params)
                (fromIntegral @Word64 @CSize memBytes)
      pure (if status == 0 then Right key else Left XPrvInternalError)

randomBytesIO :: Int -> IO (Either XPrvError ByteString)
randomBytesIO len = do
  mode <- readIORef randomModeRef
  case mode of
    SystemRandom -> do
      (status, bytes) <- B.allocRet len $ \out ->
        wallet_sodium_randombytes out (fromIntegral @Int @CSize len)
      pure $ if status == 0 then Right bytes else Left XPrvInternalError
    DeterministicRandom counter -> do
      let bytes = deterministicBytes len counter
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

foreign import ccall "cardano_wallet_encrypted_from_secret"
  wallet_encrypted_from_secret ::
    SecretKeyPtr ->
    ChainCodePtr ->
    EncryptedKeyPtr ->
    IO CInt

foreign import ccall "cardano_wallet_encrypted_new_from_mkg"
  wallet_encrypted_new_from_mkg ::
    MasterKeyPtr ->
    EncryptedKeyPtr ->
    IO CInt

foreign import ccall "cardano_wallet_encrypted_decrypt"
  wallet_encrypted_decrypt ::
    EncryptedKeyPtr ->
    EncryptedKeyPtr ->
    IO CInt

foreign import ccall "cardano_wallet_encrypted_sign"
  wallet_encrypted_sign ::
    EncryptedKeyPtr ->
    Ptr Word8 ->
    Word32 ->
    SignaturePtr ->
    IO CInt

foreign import ccall "cardano_wallet_encrypted_derive_private"
  wallet_encrypted_derive_private ::
    EncryptedKeyPtr ->
    DerivationIndex ->
    EncryptedKeyPtr ->
    CDerivationScheme ->
    IO CInt

foreign import ccall "cardano_wallet_encrypted_derive_public"
  wallet_encrypted_derive_public ::
    PublicKeyPtr ->
    ChainCodePtr ->
    DerivationIndex ->
    PublicKeyPtr ->
    ChainCodePtr ->
    CDerivationScheme ->
    IO CInt

foreign import ccall "wallet_sodium_randombytes"
  wallet_sodium_randombytes :: Ptr a -> CSize -> IO CInt

foreign import ccall "wallet_sodium_argon2id"
  wallet_sodium_argon2id ::
    WrappingKeyPtr ->
    CULLong ->
    PassPhrasePtr ->
    CULLong ->
    SaltPtr ->
    CULLong ->
    CSize ->
    IO CInt

foreign import ccall "wallet_sodium_xchacha20poly1305_encrypt"
  wallet_sodium_xchacha20poly1305_encrypt ::
    CiphertextPtr ->
    TagPtr ->
    SecretKeyPtr ->
    CULLong ->
    Ptr Word8 ->
    CULLong ->
    NoncePtr ->
    WrappingKeyPtr ->
    IO CInt

foreign import ccall "wallet_sodium_xchacha20poly1305_decrypt"
  wallet_sodium_xchacha20poly1305_decrypt ::
    SecretKeyPtr ->
    CiphertextPtr ->
    CULLong ->
    TagPtr ->
    Ptr Word8 ->
    CULLong ->
    NoncePtr ->
    WrappingKeyPtr ->
    IO CInt
