{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

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

  -- * Construction & validation
  encryptedCreate,
  encryptedCreateDirectWithTweak,
  encryptedKey,
  unEncryptedKey,
  encryptedKeyFormat,

  -- * Passphrase operations
  encryptedValidatePassphrase,
  encryptedChangePass,

  -- * Signing & derivation
  encryptedSign,
  encryptedDerivePrivate,
  encryptedDerivePublic,

  -- * Accessors
  encryptedPublic,
  encryptedChainCode,
  encryptedKeyMaterial,

  -- * Test helpers
  withFastKdfForTesting,
  withDeterministicRandomnessForTesting,
) where

import Control.DeepSeq
import Control.Exception (bracket, finally, onException)
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
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

import Codec.CBOR.Decoding (
  Decoder,
  decodeBytes,
  decodeListLenOf,
  decodeWord,
 )
import Codec.CBOR.Encoding (
  encodeBytes,
  encodeListLen,
  encodeWord,
 )
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Write as CBOR

import Cardano.Crypto.Libsodium.MLockedBytes (
  MLockedSizedBytes,
  mlsbFinalize,
  mlsbNewZero,
  mlsbUseAsCPtr,
 )

-- ---------------------------------------------------------------------------
-- Key derivation scheme
-- ---------------------------------------------------------------------------

type DerivationIndex = Word32

data DerivationScheme = DerivationScheme1 | DerivationScheme2
  deriving (Show, Eq, Ord, Enum, Bounded)

-- ---------------------------------------------------------------------------
-- Size constants
-- ---------------------------------------------------------------------------

legacyKeySize, publicKeySize, ccSize, signatureSize :: Int
legacyKeySize = 64
publicKeySize = 32
ccSize = 32
signatureSize = 64

type PublicKey = ByteString
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
-- The caller who receives a 'KeyMaterial' from a 'decryptKeyMaterial'-style
-- call is responsible for calling 'mlsbFinalize' on 'kmSecretKey' when done.
data KeyMaterial = KeyMaterial
  { kmSecretKey :: !(MLockedSizedBytes 64)
  , kmPublicKey :: !PublicKey
  , kmChainCode :: !ChainCode
  }

-- FFI pointer newtypes
newtype SecretKeyPtr = SecretKeyPtr (Ptr Word8)
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
  | otherwise = do
      emat <- legacyMaterialFromSecret sec cc
      case emat of
        Left err -> pure (Left err)
        Right mat ->
          finally (wrapKeyMaterial pass mat) (mlsbFinalize (kmSecretKey mat))
{-# NOINLINE encryptedCreate #-}

encryptedCreateDirectWithTweak ::
  (ByteArrayAccess passphrase, ByteArrayAccess secret) =>
  secret -> passphrase -> IO (Either XPrvError EncryptedKey)
encryptedCreateDirectWithTweak sec pass
  | B.length sec /= 96 = pure (Left XPrvInvalidSecretKey)
  | otherwise = do
      emat <- legacyMaterialFromMasterKey sec
      case emat of
        Left err -> pure (Left err)
        Right mat ->
          finally (wrapKeyMaterial pass mat) (mlsbFinalize (kmSecretKey mat))
{-# NOINLINE encryptedCreateDirectWithTweak #-}

encryptedValidatePassphrase ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> IO (Either XPrvError ())
encryptedValidatePassphrase ekey pass = do
  emat <- decryptKeyMaterial ekey pass
  case emat of
    Left err -> pure (Left err)
    Right mat -> do
      mlsbFinalize (kmSecretKey mat)
      pure (Right ())

encryptedChangePass ::
  (ByteArrayAccess oldPassPhrase, ByteArrayAccess newPassPhrase) =>
  oldPassPhrase -> newPassPhrase -> EncryptedKey -> IO (Either XPrvError EncryptedKey)
encryptedChangePass oldPass newPass ekey = do
  emat <- decryptKeyMaterial ekey oldPass
  case emat of
    Left err -> pure (Left err)
    Right mat ->
      finally (wrapKeyMaterial newPass mat) (mlsbFinalize (kmSecretKey mat))

encryptedSign ::
  (ByteArrayAccess passphrase, ByteArrayAccess msg) =>
  EncryptedKey -> passphrase -> msg -> IO (Either XPrvError Signature)
encryptedSign ekey pass msg = do
  emat <- decryptKeyMaterial ekey pass
  case emat of
    Left err -> pure (Left err)
    Right mat ->
      finally
        ( withLegacyStruct mat $ \legPtr -> do
            (status, sig) <-
              B.allocRet signatureSize $ \outSig ->
                withByteArray msg $ \msgPtr ->
                  wallet_encrypted_sign
                    (coerce legPtr)
                    msgPtr
                    (fromIntegral $ B.length msg)
                    (coerce outSig)
            pure (if status /= 0 then Left XPrvInternalError else Right (Signature sig))
        )
        (mlsbFinalize (kmSecretKey mat))

encryptedDerivePrivate ::
  ByteArrayAccess passphrase =>
  DerivationScheme ->
  EncryptedKey ->
  passphrase ->
  DerivationIndex ->
  IO (Either XPrvError EncryptedKey)
encryptedDerivePrivate dscheme ekey pass childIndex = do
  emat <- decryptKeyMaterial ekey pass
  case emat of
    Left err -> pure (Left err)
    Right parentMat ->
      finally
        ( do
            echildMat <- legacyDerivePrivate dscheme parentMat childIndex
            case echildMat of
              Left err -> pure (Left err)
              Right childMat ->
                finally (wrapKeyMaterial pass childMat) (mlsbFinalize (kmSecretKey childMat))
        )
        (mlsbFinalize (kmSecretKey parentMat))

encryptedDerivePublic ::
  DerivationScheme ->
  (PublicKey, ChainCode) ->
  DerivationIndex ->
  (PublicKey, ChainCode)
encryptedDerivePublic dscheme (pub, cc) childIndex
  | childIndex >= 0x80000000 =
      error "encryptedDerivePublic: cannot derive hardened key from public key"
  | otherwise = unsafePerformIO $ do
      (newCC, newPub) <-
        B.allocRet publicKeySize $ \outPub ->
          B.alloc ccSize $ \outCc ->
            withByteArray pub $ \ppub ->
              withByteArray cc $ \pcc -> do
                r <-
                  wallet_encrypted_derive_public
                    (coerce ppub)
                    (coerce pcc)
                    childIndex
                    (coerce outPub)
                    (coerce outCc)
                    (dschemeToC dscheme)
                if r /= 0
                  then error "encryptedDerivePublic: hardened index check failed"
                  else pure ()
      pure (newPub, newCC)

encryptedPublic :: EncryptedKey -> ByteString
encryptedPublic (EncryptedKey ekey) =
  case encryptedKeyFormat (EncryptedKey ekey) of
    LegacyV1 -> sub legacyKeySize publicKeySize ekey
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

-- | Decrypt a v2 'EncryptedKey' and return the 64-byte extended ed25519
-- scalar in locked memory.  The caller must 'mlsbFinalize' the result when
-- done with it.
encryptedKeyMaterial ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> IO (Either XPrvError (MLockedSizedBytes 64))
encryptedKeyMaterial ekey pass = do
  emat <- decryptKeyMaterial ekey pass
  case emat of
    Left err -> pure (Left err)
    Right mat -> pure (Right (kmSecretKey mat))

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
decodeV2Envelope bs = do
  (rest, envelope) <-
    either (const $ Left XPrvDecodeError) Right $
      CBOR.deserialiseFromBytes decodeEnvelope (BL.fromStrict bs)
  if BL.null rest then pure envelope else Left XPrvDecodeError

decodeEnvelope :: Decoder s V2Envelope
decodeEnvelope = do
  decodeListLenOf 9
  version <- decodeWord
  if version /= v2Version then failDecoder XPrvUnsupportedVersion else pure ()
  kdfId <- decodeWord
  if kdfId /= argon2idId then failDecoder XPrvUnsupportedKdf else pure ()
  decodeListLenOf 4
  memoryKiB <- decodeWord
  timeCost <- decodeWord
  parallelism <- decodeWord
  outputLength <- decodeWord
  if (memoryKiB, timeCost, parallelism, outputLength)
    /= ( productionArgonMemoryKiB
       , productionArgonTimeCost
       , productionArgonParallelism
       , productionArgonOutputLength
       )
    then failDecoder XPrvInvalidKdfParams
    else pure ()
  salt <- decodeBytes
  if BS.length salt /= saltSize then failDecoder XPrvInvalidSaltLength else pure ()
  cipherId <- decodeWord
  if cipherId /= xchacha20poly1305Id then failDecoder XPrvUnsupportedCipher else pure ()
  nonce <- decodeBytes
  if BS.length nonce /= nonceSize then failDecoder XPrvInvalidNonceLength else pure ()
  aad <- decodeBytes
  ciphertext <- decodeBytes
  if BS.length ciphertext /= legacyKeySize
    then failDecoder XPrvInvalidCiphertextLength
    else pure ()
  tag <- decodeBytes
  if BS.length tag /= tagSize then failDecoder XPrvInvalidTagLength else pure ()
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
encodeAad pub cc =
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
      , encodeBytes pub
      , encodeBytes cc
      ]

decodeAad :: AadContext -> Either XPrvError (PublicKey, ChainCode)
decodeAad bs =
  case CBOR.deserialiseFromBytes decodeAadFields (BL.fromStrict bs) of
    Left _ -> Left XPrvDecodeError
    Right (rest, result)
      | BL.null rest -> Right result
      | otherwise -> Left XPrvDecodeError

decodeAadFields :: Decoder s (PublicKey, ChainCode)
decodeAadFields = do
  decodeListLenOf 8
  version <- decodeWord
  if version /= v2Version then failDecoder XPrvUnsupportedVersion else pure ()
  kdfId <- decodeWord
  if kdfId /= argon2idId then failDecoder XPrvUnsupportedKdf else pure ()
  decodeListLenOf 4
  memoryKiB <- decodeWord
  timeCost <- decodeWord
  parallelism <- decodeWord
  outputLength <- decodeWord
  if (memoryKiB, timeCost, parallelism, outputLength)
    /= ( productionArgonMemoryKiB
       , productionArgonTimeCost
       , productionArgonParallelism
       , productionArgonOutputLength
       )
    then failDecoder XPrvInvalidKdfParams
    else pure ()
  cipherId <- decodeWord
  if cipherId /= xchacha20poly1305Id then failDecoder XPrvUnsupportedCipher else pure ()
  payloadKind <- decodeWord
  if payloadKind /= 1 then failDecoder XPrvDecodeError else pure ()
  payloadLen <- decodeWord
  if payloadLen /= fromIntegral legacyKeySize
    then failDecoder XPrvInvalidCiphertextLength
    else pure ()
  pub <- decodeBytes
  cc <- decodeBytes
  if BS.length pub /= publicKeySize then failDecoder XPrvInvalidPublicKey else pure ()
  if BS.length cc /= ccSize then failDecoder XPrvInvalidChainCode else pure ()
  pure (pub, cc)

-- ---------------------------------------------------------------------------
-- Internal: v2 encrypt / decrypt
-- ---------------------------------------------------------------------------

decryptKeyMaterial ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> IO (Either XPrvError KeyMaterial)
decryptKeyMaterial ekey pass =
  case encryptedKeyFormat ekey of
    LegacyV1 -> pure (Left XPrvDecodeError)
    EnvelopeV2 -> v2Decrypt ekey pass

v2Decrypt ::
  ByteArrayAccess passphrase =>
  EncryptedKey -> passphrase -> IO (Either XPrvError KeyMaterial)
v2Decrypt (EncryptedKey bs) pass =
  case decodeV2Envelope bs of
    Left err -> pure (Left err)
    Right envelope -> do
      eWrappingKey <- deriveWrappingKey pass (v2Salt envelope)
      case eWrappingKey of
        Left err -> pure (Left err)
        Right wrappingKey -> do
          let aad = encodeAad (v2PublicKey envelope) (v2ChainCode envelope)
          ptextMlsb <- (mlsbNewZero :: IO (MLockedSizedBytes 64))
          status <-
            mlsbUseAsCPtr ptextMlsb $ \ptextPtr ->
              withByteArray (v2Ciphertext envelope) $ \ct ->
                withByteArray (v2Tag envelope) $ \tg ->
                  withByteArray aad $ \ad ->
                    withByteArray (v2Nonce envelope) $ \np ->
                      withByteArray wrappingKey $ \kp ->
                        wallet_sodium_xchacha20poly1305_decrypt
                          (coerce ptextPtr)
                          (coerce ct)
                          (fromIntegral $ BS.length (v2Ciphertext envelope))
                          (coerce tg)
                          ad
                          (fromIntegral $ BS.length aad)
                          (coerce np)
                          (coerce kp)
          if status /= 0
            then do
              mlsbFinalize ptextMlsb
              pure (Left XPrvAuthenticationFailed)
            else do
              let mat = KeyMaterial ptextMlsb (v2PublicKey envelope) (v2ChainCode envelope)
              eVal <- validateKeyMaterial mat `onException` mlsbFinalize ptextMlsb
              case eVal of
                Left err -> do
                  mlsbFinalize ptextMlsb
                  pure (Left err)
                Right () -> pure (Right mat)

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
              mlsbUseAsCPtr (kmSecretKey material) $ \skPtr -> do
                ((status, tag), ciphertext) <-
                  B.allocRet legacyKeySize $ \outCipher ->
                    B.allocRet tagSize $ \outTag ->
                      withByteArray aad $ \ad ->
                        withByteArray nonce $ \np ->
                          withByteArray wrappingKey $ \kp ->
                            wallet_sodium_xchacha20poly1305_encrypt
                              (coerce outCipher)
                              (coerce outTag)
                              (coerce skPtr)
                              (fromIntegral legacyKeySize)
                              ad
                              (fromIntegral $ BS.length aad)
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
      mlsbUseAsCPtr (kmSecretKey mat) $ \skPtr ->
        copyBytes base skPtr 64
      BS.useAsCStringLen (kmPublicKey mat) $ \(pkPtr, _) ->
        copyBytes (base `plusPtr` 64) (castPtr pkPtr) 32
      BS.useAsCStringLen (kmChainCode mat) $ \(ccPtr, _) ->
        copyBytes (base `plusPtr` 96) (castPtr ccPtr) 32
      action base

-- | Call a C function that writes a 128-byte @encrypted_key@ struct to the
-- pointer it receives, then split the result into 'KeyMaterial'.  On failure
-- (non-zero return) returns 'Left onFailure'.  The caller owns the
-- 'MLockedSizedBytes 64' in the returned 'KeyMaterial' and must finalize it.
withEncryptedKeyOutput ::
  XPrvError ->
  (Ptr Word8 -> IO CInt) ->
  IO (Either XPrvError KeyMaterial)
withEncryptedKeyOutput onFailure action =
  bracket (mlsbNewZero :: IO (MLockedSizedBytes 128)) mlsbFinalize $ \outMlsb -> do
    r <- mlsbUseAsCPtr outMlsb $ \ptr -> action ptr
    if r /= 0
      then pure (Left onFailure)
      else mlsbUseAsCPtr outMlsb $ \base -> do
             sk <- (mlsbNewZero :: IO (MLockedSizedBytes 64))
             mlsbUseAsCPtr sk $ \skPtr -> copyBytes skPtr base 64
             pub <- BS.packCStringLen (castPtr (base `plusPtr` 64), 32)
             cc <- BS.packCStringLen (castPtr (base `plusPtr` 96), 32)
             pure (Right (KeyMaterial sk pub cc))

-- ---------------------------------------------------------------------------
-- Internal: key-material construction (using C/ed25519)
-- ---------------------------------------------------------------------------

legacyMaterialFromSecret ::
  (ByteArrayAccess secret, ByteArrayAccess cc) =>
  secret -> cc -> IO (Either XPrvError KeyMaterial)
legacyMaterialFromSecret sec cc =
  withEncryptedKeyOutput XPrvInvalidSecretKey $ \outPtr ->
    withByteArray sec $ \psec ->
      withByteArray cc $ \pcc ->
        wallet_encrypted_from_secret (coerce psec) (coerce pcc) (coerce outPtr)

legacyMaterialFromMasterKey ::
  ByteArrayAccess secret => secret -> IO (Either XPrvError KeyMaterial)
legacyMaterialFromMasterKey sec =
  withEncryptedKeyOutput XPrvInvalidSecretKey $ \outPtr ->
    withByteArray sec $ \psec ->
      wallet_encrypted_new_from_mkg (coerce psec) (coerce outPtr)

legacyDerivePrivate ::
  DerivationScheme -> KeyMaterial -> DerivationIndex -> IO (Either XPrvError KeyMaterial)
legacyDerivePrivate dscheme parent childIndex =
  withLegacyStruct parent $ \inPtr ->
    withEncryptedKeyOutput XPrvInternalError $ \outPtr ->
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
                (fromIntegral outputLen)
                (coerce ppass)
                (fromIntegral $ B.length pass)
                (coerce psalt)
                (fromIntegral $ kdfTimeCost params)
                memBytes
      pure (if status == 0 then Right key else Left XPrvInternalError)

randomBytesIO :: Int -> IO (Either XPrvError ByteString)
randomBytesIO len = do
  mode <- readIORef randomModeRef
  case mode of
    SystemRandom -> do
      (status, bytes) <- B.allocRet len $ \out ->
        wallet_sodium_randombytes out (fromIntegral len)
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
    SecretKeyPtr ->
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
  wallet_sodium_randombytes :: Ptr Word8 -> Word32 -> IO CInt

foreign import ccall "wallet_sodium_argon2id"
  wallet_sodium_argon2id ::
    WrappingKeyPtr ->
    Word32 ->
    PassPhrasePtr ->
    Word32 ->
    SaltPtr ->
    Word32 ->
    Word64 ->
    IO CInt

foreign import ccall "wallet_sodium_xchacha20poly1305_encrypt"
  wallet_sodium_xchacha20poly1305_encrypt ::
    CiphertextPtr ->
    TagPtr ->
    SecretKeyPtr ->
    Word32 ->
    Ptr Word8 ->
    Word32 ->
    NoncePtr ->
    WrappingKeyPtr ->
    IO CInt

foreign import ccall "wallet_sodium_xchacha20poly1305_decrypt"
  wallet_sodium_xchacha20poly1305_decrypt ::
    SecretKeyPtr ->
    CiphertextPtr ->
    Word32 ->
    TagPtr ->
    Ptr Word8 ->
    Word32 ->
    NoncePtr ->
    WrappingKeyPtr ->
    IO CInt
