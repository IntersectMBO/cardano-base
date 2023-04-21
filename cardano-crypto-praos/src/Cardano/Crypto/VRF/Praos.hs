{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Verifiable Random Function (VRF) implemented as FFI wrappers around the
-- implementation in <https://github.com/input-output-hk/libsodium>
module Cardano.Crypto.VRF.Praos
  (
  -- * VRFAlgorithm API
    PraosVRF

  -- * Key sizes
  , certSizeVRF
  , signKeySizeVRF
  , verKeySizeVRF
  , vrfKeySizeVRF

  -- * Seed and key generation
  , Seed
  , genSeed
  , keypairFromSeed

  -- * Conversions
  , outputBytes
  , proofBytes
  , skBytes
  , vkBytes
  , skToVerKey
  , skToSeed

  , proofFromBytes
  , skFromBytes
  , vkFromBytes

  , vkToBatchCompat
  , skToBatchCompat
  , outputToBatchCompat


  -- * Core VRF operations
  , prove
  , verify

  , SignKeyVRF (..)
  , VerKeyVRF (..)
  , CertVRF (..)

  -- * Internal types
  , Proof
  , SignKey
  , VerKey
  , Output
  )
where

import Cardano.Binary
  ( FromCBOR (..)
  , ToCBOR (..)
  )
import Cardano.Crypto.RandomBytes (randombytes_buf)
import Cardano.Crypto.Seed (getBytesFromSeedT)
import Cardano.Crypto.Util (SignableRepresentation (..))
import Cardano.Crypto.VRF.Class
import qualified Cardano.Crypto.VRF.PraosBatchCompat as BC
import Control.DeepSeq (NFData (..))
import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Coerce (coerce)
import Data.Maybe (fromMaybe, isJust)
import Data.Proxy (Proxy (..))
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Ptr
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, OnlyCheckWhnf (..), OnlyCheckWhnfNamed (..))
import System.IO.Unsafe (unsafePerformIO)

-- Value types.
--
-- These are all transparent to the Haskell side of things, all we ever do
-- with these is pass pointers to them around. We don't want to know anything
-- about them, hence, we make them uninhabited.
--
-- The actual values are kept entirely in C memory, allocated when a value is
-- created, and freed when the value's finalizer runs.
--
-- The reason we have them at all, rather than duplicating C's void pointers,
-- is because we want to distinguish them at the type level.

data SeedValue
data SignKeyValue
data VerKeyValue
data ProofValue
data OutputValue

-- Type aliases for raw pointers
--
-- These will not leave this module, they are only here for our convenience,
-- so we can afford to not newtype them.

type SeedPtr = Ptr SeedValue
type SignKeyPtr = Ptr SignKeyValue
type VerKeyPtr = Ptr VerKeyValue
type ProofPtr = Ptr ProofValue
type OutputPtr = Ptr OutputValue

-- The exported (via the 'VRFAlgorithm' typeclass) types.
--
-- These are wrappers around 'ForeignPtr's; we don't export the constructors,
-- so callers have to go through our blessed API to create any of them. This
-- way we can make sure that we always allocate the correct sizes, and attach
-- finalizers that automatically free the memory for us.

-- | A random seed, used to derive a key pair.
newtype Seed = Seed { unSeed :: ForeignPtr SeedValue }
  deriving NoThunks via OnlyCheckWhnf Seed

-- | Signing key. In this implementation, the signing key is actually a 64-byte
-- value that contains both the 32-byte signing key and the corresponding
-- 32-byte verification key.
newtype SignKey = SignKey { unSignKey :: ForeignPtr SignKeyValue }
  deriving (Generic)
  deriving NoThunks via OnlyCheckWhnf SignKey

instance NFData SignKey where
  rnf a = seq a ()

-- | Verification key.
newtype VerKey = VerKey { unVerKey :: ForeignPtr VerKeyValue }
  deriving (Generic)
  deriving NoThunks via OnlyCheckWhnf VerKey

instance NFData VerKey where
  rnf a = seq a ()

-- | A proof, as constructed by the 'prove' function.
newtype Proof = Proof { unProof :: ForeignPtr ProofValue }
  deriving (Generic)
  deriving NoThunks via OnlyCheckWhnf Proof

instance NFData Proof where
  rnf a = seq a ()

-- | Hashed output of a proof verification, as returned by the 'verify'
-- function.
newtype Output = Output { unOutput :: ForeignPtr OutputValue }
  deriving (Generic)
  deriving NoThunks via OnlyCheckWhnf Output

-- Raw low-level FFI bindings.
--
foreign import ccall "crypto_vrf_ietfdraft03_bytes" crypto_vrf_bytes :: CSize

foreign import ccall "crypto_vrf_ietfdraft03_publickeybytes" crypto_vrf_publickeybytes :: CSize

foreign import ccall "crypto_vrf_ietfdraft03_secretkeybytes" crypto_vrf_secretkeybytes :: CSize

foreign import ccall "crypto_vrf_ietfdraft03_seedbytes" crypto_vrf_seedbytes :: CSize

foreign import ccall "crypto_vrf_ietfdraft03_outputbytes" crypto_vrf_outputbytes :: CSize

foreign import ccall "crypto_vrf_ietfdraft03_keypair_from_seed"
  crypto_vrf_keypair_from_seed :: VerKeyPtr -> SignKeyPtr -> SeedPtr -> IO CInt

foreign import ccall "crypto_vrf_ietfdraft03_sk_to_pk"
  crypto_vrf_sk_to_pk :: VerKeyPtr -> SignKeyPtr -> IO ()

foreign import ccall "crypto_vrf_ietfdraft03_sk_to_seed"
  crypto_vrf_sk_to_seed :: SeedPtr -> SignKeyPtr -> IO ()

foreign import ccall "crypto_vrf_ietfdraft03_prove"
  crypto_vrf_prove :: ProofPtr -> SignKeyPtr -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall "crypto_vrf_ietfdraft03_verify"
  crypto_vrf_verify :: OutputPtr -> VerKeyPtr -> ProofPtr -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall "crypto_vrf_ietfdraft03_proof_to_hash"
  crypto_vrf_proof_to_hash :: OutputPtr -> ProofPtr -> IO CInt

-- Key size constants

certSizeVRF :: Int
certSizeVRF = fromIntegral $! crypto_vrf_bytes

signKeySizeVRF :: Int
signKeySizeVRF = fromIntegral $! crypto_vrf_secretkeybytes

verKeySizeVRF :: Int
verKeySizeVRF = fromIntegral $! crypto_vrf_publickeybytes

vrfKeySizeVRF :: Int
vrfKeySizeVRF = fromIntegral $! crypto_vrf_outputbytes

-- | Allocate a 'Seed' and attach a finalizer. The allocated memory will not be initialized.
mkSeed :: IO Seed
mkSeed = do
  ptr <- mallocBytes (fromIntegral crypto_vrf_seedbytes)
  Seed <$> newForeignPtr finalizerFree ptr

-- | Generate a random seed.
-- Uses 'randombytes_buf' to create random data.
--
-- This function provides an alternative way of generating seeds specifically
-- for the 'PraosVRF' algorithm. Unlike the 'genKeyPairVRF' method, which uses
-- a 'ByteString'-based 'Cardano.Crypto.Seed.Seed', this seed generation method
-- bypasses the GHC heap, keeping the seed in C-allocated memory instead.
--
-- This provides two advantages:
-- 1. It avoids the overhead of unnecessary GHC-side heap allocations.
-- 2. It avoids leaking the seed via the GHC heap; the 'Seed' type itself
--    takes care of zeroing out its memory upon finalization.
genSeed :: IO Seed
genSeed = do
  seed <- mkSeed
  withForeignPtr (unSeed seed) $ \ptr ->
    randombytes_buf ptr crypto_vrf_seedbytes
  return seed

copyFromByteString :: Ptr a -> ByteString -> Int -> IO ()
copyFromByteString ptr bs lenExpected =
  BS.unsafeUseAsCStringLen bs $ \(cstr, lenActual) ->
    if lenActual >= lenExpected
      then copyBytes (castPtr ptr) cstr lenExpected
      else error $
           "Invalid input size, expected at least " <>
           show lenExpected <> ", but got " <> show lenActual

seedFromBytes :: ByteString -> Seed
seedFromBytes bs = unsafePerformIO $ do
  seed <- mkSeed
  withForeignPtr (unSeed seed) $ \ptr ->
    copyFromByteString ptr bs (fromIntegral crypto_vrf_seedbytes)
  return seed

-- | Convert a proof verification output hash into a 'ByteString' that we can
-- inspect.
outputBytes :: Output -> ByteString
outputBytes (Output op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, fromIntegral crypto_vrf_outputbytes)

-- | Convert a proof into a 'ByteString' that we can inspect.
proofBytes :: Proof -> ByteString
proofBytes (Proof op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, certSizeVRF)

-- | Convert a verification key into a 'ByteString' that we can inspect.
vkBytes :: VerKey -> ByteString
vkBytes (VerKey op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, verKeySizeVRF)

-- | Convert a signing key into a 'ByteString' that we can inspect.
skBytes :: SignKey -> ByteString
skBytes (SignKey op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, signKeySizeVRF)

instance Show Proof where
  show = show . proofBytes

instance Eq Proof where
  a == b = proofBytes a == proofBytes b

instance ToCBOR Proof where
  toCBOR = toCBOR . proofBytes
  encodedSizeExpr _ _ =
    encodedSizeExpr (\_ -> fromIntegral certSizeVRF) (Proxy :: Proxy ByteString)

instance FromCBOR Proof where
  fromCBOR = fromCBOR >>= proofFromBytes

instance Show SignKey where
  show = show . skBytes

instance Eq SignKey where
  a == b = skBytes a == skBytes b

instance ToCBOR SignKey where
  toCBOR = toCBOR . skBytes
  encodedSizeExpr _ _ =
    encodedSizeExpr (\_ -> fromIntegral signKeySizeVRF) (Proxy :: Proxy ByteString)

instance FromCBOR SignKey where
  fromCBOR = fromCBOR >>= skFromBytes

instance Show VerKey where
  show = show . vkBytes

instance Eq VerKey where
  a == b = vkBytes a == vkBytes b

instance ToCBOR VerKey where
  toCBOR = toCBOR . vkBytes
  encodedSizeExpr _ _ =
    encodedSizeExpr (\_ -> fromIntegral verKeySizeVRF) (Proxy :: Proxy ByteString)

instance FromCBOR VerKey where
  fromCBOR = fromCBOR >>= vkFromBytes

-- | Allocate a Verification Key and attach a finalizer. The allocated memory will
-- not be initialized.
mkVerKey :: IO VerKey
mkVerKey = fmap VerKey $ newForeignPtr finalizerFree =<< mallocBytes verKeySizeVRF

-- | Allocate a Signing Key and attach a finalizer. The allocated memory will
-- not be initialized.
mkSignKey :: IO SignKey
mkSignKey = fmap SignKey $ newForeignPtr finalizerFree =<< mallocBytes signKeySizeVRF

-- | Allocate a Proof and attach a finalizer. The allocated memory will
-- not be initialized.
mkProof :: IO Proof
mkProof = fmap Proof $ newForeignPtr finalizerFree =<< mallocBytes certSizeVRF

proofFromBytes :: MonadFail m => ByteString -> m Proof
proofFromBytes bs
  | bsLen /= certSizeVRF =
    fail $
      "Invalid proof length "
        <> show @Int bsLen
        <> ", expecting "
        <> show @Int certSizeVRF
  | otherwise = pure $! unsafePerformIO $ do
      proof <- mkProof
      withForeignPtr (unProof proof) $ \ptr ->
        copyFromByteString ptr bs certSizeVRF
      return proof
    where
      bsLen = BS.length bs


skFromBytes :: MonadFail m => ByteString -> m SignKey
skFromBytes bs = do
  if bsLen /= signKeySizeVRF
    then
      fail $
        "Invalid SignKey length "
          <> show @Int bsLen
          <> ", expecting "
          <> show @Int signKeySizeVRF
    else pure $! unsafePerformIO $ do
      sk <- mkSignKey
      withForeignPtr (unSignKey sk) $ \ptr ->
        copyFromByteString ptr bs signKeySizeVRF
      return sk
  where
    bsLen = BS.length bs

vkFromBytes :: MonadFail m => ByteString -> m VerKey
vkFromBytes bs = do
  if bsLen /= verKeySizeVRF
    then
      fail $
        "Invalid VerKey length "
          <> show @Int bsLen
          <> ", expecting "
          <> show @Int verKeySizeVRF
    else
      pure $! unsafePerformIO $ do
        pk <- mkVerKey
        withForeignPtr (unVerKey pk) $ \ptr ->
          copyFromByteString ptr bs verKeySizeVRF
        return pk
  where
    bsLen = BS.length bs

-- | Allocate an Output and attach a finalizer. The allocated memory will
-- not be initialized.
mkOutput :: IO Output
mkOutput = fmap Output $ newForeignPtr finalizerFree =<< mallocBytes (fromIntegral crypto_vrf_outputbytes)

-- | Derive a key pair (Sign + Verify) from a seed.
keypairFromSeed :: Seed -> (VerKey, SignKey)
keypairFromSeed seed =
  unsafePerformIO $ withForeignPtr (unSeed seed) $ \sptr -> do
    pk <- mkVerKey
    sk <- mkSignKey
    withForeignPtr (unVerKey pk) $ \pkPtr -> do
      withForeignPtr (unSignKey sk) $ \skPtr -> do
        void $ crypto_vrf_keypair_from_seed pkPtr skPtr sptr
    return $ pk `seq` sk `seq` (pk, sk)

-- | Derive a Verification Key from a Signing Key.
skToVerKey :: SignKey -> VerKey
skToVerKey sk =
  unsafePerformIO $ withForeignPtr (unSignKey sk) $ \skPtr -> do
    pk <- mkVerKey
    withForeignPtr (unVerKey pk) $ \pkPtr -> do
      crypto_vrf_sk_to_pk pkPtr skPtr
    return pk

-- | Get the seed used to generate a given Signing Key
skToSeed :: SignKey -> Seed
skToSeed sk =
  unsafePerformIO $ withForeignPtr (unSignKey sk) $ \skPtr -> do
    seed <- mkSeed
    withForeignPtr (unSeed seed) $ \seedPtr ->
      crypto_vrf_sk_to_seed seedPtr skPtr
    return seed

-- | Construct a proof from a Signing Key and a message.
-- Returns 'Just' the proof on success, 'Nothing' if the signing key could not
-- be decoded.
prove :: SignKey -> ByteString -> Maybe Proof
prove sk msg =
  unsafePerformIO $
    withForeignPtr (unSignKey sk) $ \skPtr -> do
      proof <- mkProof
      BS.useAsCStringLen msg $ \(m, mlen) -> do
        withForeignPtr (unProof proof) $ \proofPtr -> do
          crypto_vrf_prove proofPtr skPtr m (fromIntegral mlen) >>= \case
            0 -> return $ Just $! proof
            _ -> return Nothing

-- | Construct a BatchCompat vkey from praos, non-batchcompat
vkToBatchCompat :: VerKeyVRF PraosVRF -> VerKeyVRF BC.PraosBatchCompatVRF
vkToBatchCompat praosVk =
  case rawDeserialiseVerKeyVRF (rawSerialiseVerKeyVRF praosVk) of
    Just vk -> vk
    Nothing -> error "VerKeyVRF: Unable to convert PraosVK to BatchCompatVK."

-- | Construct a BatchCompat skey from praos, non-batchcompat
skToBatchCompat :: SignKeyVRF PraosVRF -> SignKeyVRF BC.PraosBatchCompatVRF
skToBatchCompat praosSk =
  case rawDeserialiseSignKeyVRF (rawSerialiseSignKeyVRF praosSk) of
    Just sk -> sk
    Nothing -> error "SignKeyVRF: Unable to convert PraosSK to BatchCompatSK."

-- | Construct a BatchCompat output from praos, non-batchcompat
outputToBatchCompat :: OutputVRF PraosVRF -> OutputVRF BC.PraosBatchCompatVRF
outputToBatchCompat praosOutput =
  if vrfKeySizeVRF /= BC.vrfKeySizeVRF
  then error "OutputVRF: Unable to convert PraosSK to BatchCompatSK."
  else
  OutputVRF (getOutputVRFBytes praosOutput)


-- | Verify a VRF proof and validate the Verification Key. Returns 'Just' a hash of
-- the verification result on success, 'Nothing' if the verification did not
-- succeed.
--
-- For a given verification key and message, there are many possible proofs but only
-- one possible output hash.
verify :: VerKey -> Proof -> ByteString -> Maybe Output
verify pk proof msg =
  unsafePerformIO $
    withForeignPtr (unVerKey pk) $ \pkPtr -> do
      withForeignPtr (unProof proof) $ \proofPtr -> do
        output <- mkOutput
        BS.useAsCStringLen msg $ \(m, mlen) -> do
          withForeignPtr (unOutput output) $ \outputPtr -> do
            crypto_vrf_verify outputPtr pkPtr proofPtr m (fromIntegral mlen) >>= \case
              0 -> return $ Just $! output
              _ -> return Nothing
{-# INLINE verify #-}

outputFromProof :: Proof -> Maybe Output
outputFromProof (Proof p) =
  unsafePerformIO $
    withForeignPtr p $ \ptr -> do
      output <- mkOutput
      withForeignPtr (unOutput output) $ \outputPtr -> do
        crypto_vrf_proof_to_hash outputPtr ptr >>= \case
          0 -> return $ Just $! output
          _ -> return Nothing

data PraosVRF

instance VRFAlgorithm PraosVRF where
  newtype VerKeyVRF PraosVRF = VerKeyPraosVRF VerKey
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoThunks via OnlyCheckWhnfNamed "VerKeyVRF PraosVRF" VerKey
    deriving newtype (NFData)

  newtype SignKeyVRF PraosVRF = SignKeyPraosVRF SignKey
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoThunks via OnlyCheckWhnfNamed "SignKeyVRF PraosVRF" SignKey
    deriving newtype (NFData)

  newtype CertVRF PraosVRF = CertPraosVRF Proof
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoThunks via OnlyCheckWhnfNamed "CertKeyVRF PraosVRF" Proof
    deriving newtype (NFData)

  type Signable PraosVRF = SignableRepresentation

  algorithmNameVRF = const "PraosVRF"

  deriveVerKeyVRF = coerce skToVerKey

  evalVRF = \_ msg (SignKeyPraosVRF sk) ->
    let msgBS = getSignableRepresentation msg
        !proof = fromMaybe (error "Invalid Key") $ prove sk msgBS
        !output = maybe (error "Invalid Proof") outputBytes $ outputFromProof proof
     in (OutputVRF output, CertPraosVRF proof)

  verifyVRF = \_ (VerKeyPraosVRF pk) msg (_, CertPraosVRF proof) ->
    isJust $! verify pk proof (getSignableRepresentation msg)
  {-# INLINE verifyVRF #-}

  sizeOutputVRF _ = fromIntegral crypto_vrf_outputbytes
  seedSizeVRF _ = fromIntegral crypto_vrf_seedbytes

  genKeyPairVRF = \cryptoseed ->
    let seed = seedFromBytes . fst . getBytesFromSeedT (fromIntegral crypto_vrf_seedbytes) $ cryptoseed
        !(!pk, !sk) = keypairFromSeed seed
     in (SignKeyPraosVRF sk, VerKeyPraosVRF pk)

  rawSerialiseVerKeyVRF (VerKeyPraosVRF pk) = vkBytes pk
  rawSerialiseSignKeyVRF (SignKeyPraosVRF sk) = skBytes sk
  rawSerialiseCertVRF (CertPraosVRF proof) = proofBytes proof
  rawDeserialiseVerKeyVRF = fmap VerKeyPraosVRF . vkFromBytes
  {-# INLINE rawDeserialiseVerKeyVRF #-}
  rawDeserialiseSignKeyVRF = fmap SignKeyPraosVRF . skFromBytes
  rawDeserialiseCertVRF = fmap CertPraosVRF . proofFromBytes

  sizeVerKeyVRF _ = fromIntegral verKeySizeVRF
  sizeSignKeyVRF _ = fromIntegral signKeySizeVRF
  sizeCertVRF _ = fromIntegral certSizeVRF
