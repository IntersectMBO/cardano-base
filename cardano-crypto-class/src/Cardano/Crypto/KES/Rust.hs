{-# OPTIONS_GHC -fno-warn-orphans  -Wno-unused-binds  -Wno-unused-imports #-}
{-# LANGUAGE StandaloneDeriving  #-}
{-# LANGUAGE TypeApplications    #-}  --  :set -XTypeApplications  to set inside GHCi
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE DeriveAnyClass      #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE DerivingStrategies  #-}
{-# LANGUAGE DerivingVia         #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PatternSynonyms     #-}
{-# LANGUAGE FlexibleContexts    #-}


module Cardano.Crypto.KES.Rust (
   -- Local datatype used in the KESAlgorithm class
   Seed,PublicKey, SecretKey, Signature,
   -- Local functions used in thr KESAlgorihm class
   generate, verify, sign, update, period_from, compute_public,
   -- IO version tah call the foreign functions, used in the tests
   generateIO, verifyIO, signIO, updateIO, period_fromIO, compute_publicIO, createSeedIO,
   RustKES
   )  where

-- ==========================================================
-- Some Haskell Control operations

import Control.Exception (assert)
import System.IO.Unsafe(unsafePerformIO)  -- Need this to get around calls in IO to C code.


-- ==========================================================
-- import pointers and words to interface with C code

import Data.Word(Word,Word8,Word32)
import Foreign(Ptr)
import Foreign.ForeignPtr(mallocForeignPtrBytes,ForeignPtr)
import Foreign.Storable(pokeElemOff)
import Data.Char(ord)

-- ==========================================================
-- import the KES wrappers that are just C-calls

import qualified KES as CWrap -- (verify, generate, sign, t, update)


-- ===========================================================
-- import different kinds of Byte Strings and operations

import Data.ByteArray(ScrubbedBytes,convert,allocRet,withByteArray,copyByteArrayToPtr,pack,copy)
import qualified Data.ByteString as BS
import Data.ByteString(ByteString,copy)

-- ===========================================================
-- Cardano-Node imports

import Cardano.Crypto.KES.Class(KESAlgorithm(..),Period)
import Cardano.Prelude(NoUnexpectedThunks(),UseIsNormalForm(..))
import Cardano.Binary(ToCBOR(),serialize')
import Cardano.Crypto.Seed(Seed,getSeedBytes,mkSeedFromBytes)

-- ===============================================================================
-- General purpose GHC type class wizardry for Nat as index, and Generic functions

import GHC.TypeNats (Nat, KnownNat, natVal)
import Data.Proxy (Proxy(..))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)

-- ===========================================================
-- Sizes and Types

-- These are Defined in CWrap
-- pattern SIGNATURE_SIZE = 484
-- pattern SECRET_KEY_SIZE = 1220
-- pattern PUBLIC_KEY_SIZE = 32
pattern SEED_SIZE = 32

newtype PublicKey = PublicKey BS.ByteString deriving Show
newtype SecretKey = SecretKey ScrubbedBytes deriving Show
newtype Signature = Signature BS.ByteString deriving Show
-- Seed is imported from Cardano.Crypto.Seed



-- ============================================================
-- Higher level wrappers that call the C language wrappers
-- These necessarily return values in the IO monad.

createSeedIO :: IO Seed
createSeedIO = do
  (_,seed) <- allocRet SEED_SIZE $ \seed_ptr -> do
    mapM_ (\i -> pokeElemOff seed_ptr i ((fromIntegral i) :: Word8)) [0..31]
  pure $ mkSeedFromBytes seed


generateIO :: Seed -> IO (PublicKey, SecretKey)
generateIO  seed = do
  withByteArray (getSeedBytes seed) $ \seed_ptr -> do
    (public, secret) <- allocRet CWrap.SECRET_KEY_SIZE $ \secret -> do
      (_,public) <- allocRet CWrap.PUBLIC_KEY_SIZE $ \public_ptr -> do
        CWrap.generate seed_ptr secret public_ptr
      pure $ PublicKey public
    pure (public, SecretKey secret)


verifyIO :: PublicKey -> BS.ByteString -> Signature -> IO Bool
verifyIO (PublicKey pub) message (Signature sig) = do
  withByteArray pub $ \pub_ptr -> do
    withByteArray message $ \msg_ptr -> do
      withByteArray sig $ \sig_ptr -> do
        pure $ CWrap.verify pub_ptr msg_ptr (fromIntegral $ BS.length message) sig_ptr


signIO :: SecretKey -> BS.ByteString -> IO Signature
signIO (SecretKey sec) message = do
  withByteArray sec $ \sec_ptr -> do
    withByteArray message $ \msg_ptr -> do
      (_, sig) <- allocRet CWrap.SIGNATURE_SIZE $ \sig_ptr -> do
        CWrap.sign sec_ptr msg_ptr (fromIntegral $ BS.length message) sig_ptr
      pure $ Signature sig


updateIO :: SecretKey -> IO ()
updateIO (SecretKey sec) = do
  withByteArray sec $ \sec_ptr -> do
    CWrap.update sec_ptr


compute_publicIO :: SecretKey -> IO PublicKey
compute_publicIO (SecretKey secret) = do
  withByteArray secret $ \ secret_ptr -> do
    (_,public) <- allocRet CWrap.PUBLIC_KEY_SIZE $ \public_ptr -> CWrap.compute_public secret_ptr public_ptr
    pure (PublicKey public)


period_fromIO :: SecretKey -> IO Word32
period_fromIO (SecretKey secret) = do
  withByteArray secret $ \ secret_ptr -> pure(CWrap.t secret_ptr)


-- ============================================================
-- Pure versions that use unsafePerformIO



{-# NOINLINE generate #-}
generate :: Seed -> (PublicKey, SecretKey)
generate seed = unsafePerformIO (generateIO seed)


-- Cardano's notion of a Seed (see  Cardano.Crypto.Seed (a ByteString)) does not align with Rust's notion of a Seed (ScrubbedBytes)
-- To convert we must make a ScrubbedBytes from a BS.ByteString

scrub:: BS.ByteString -> ScrubbedBytes
scrub bs = convert bs
-- seedToSeed xs = Seed(scrub (getSeedBytes xs))


{-# NOINLINE verify #-}
verify :: ToCBOR obj => PublicKey -> obj -> Signature -> Bool
verify publickey object sig =  unsafePerformIO (verifyIO publickey (serialize' object) sig)

{-# NOINLINE sign #-}
sign  :: ToCBOR a => SecretKey -> a -> Signature
sign secretkey bytes = unsafePerformIO(signIO secretkey (serialize' bytes))


{-# NOINLINE update #-}
update :: SecretKey -> SecretKey
update (SecretKey scrubbed) = unsafePerformIO $ (
    (do new_scrubbed <- Data.ByteArray.copy scrubbed (\ _ -> pure())
        updateIO (SecretKey new_scrubbed)  -- This is altered in place, that is why we pass a copy
        pure (SecretKey new_scrubbed)
    ))

{-# NOINLINE period_from #-}
period_from :: SecretKey -> Period
period_from secret = fromIntegral (unsafePerformIO (period_fromIO secret))


{-# NOINLINE compute_public #-}
compute_public:: SecretKey -> PublicKey
compute_public secret = unsafePerformIO (compute_publicIO secret)

-- ===================================================================================================================
-- Make a instance of the KESAlgorithm class, this is the whole point of this module
-- ===================================================================================================================

-- =====================================================================
-- First, We are going to need some instances of the Key Types

deriving instance Eq Signature
deriving instance Eq PublicKey
deriving instance Eq SecretKey

deriving instance Generic Signature
deriving instance Generic PublicKey
deriving instance Generic SecretKey

deriving instance NoUnexpectedThunks Signature
deriving instance NoUnexpectedThunks PublicKey
deriving instance NoUnexpectedThunks SecretKey
deriving via UseIsNormalForm ScrubbedBytes instance NoUnexpectedThunks ScrubbedBytes


-- ======================================================
-- This type is used as the name of KESAlgorithm instance. The index `t` stands for the the number of evolutions
-- This Natural number type index, exposes in the name of the instance how large it is.

data RustKES (t :: Nat)


instance KnownNat t => KESAlgorithm (RustKES t) where

    newtype VerKeyKES (RustKES t) = Verify PublicKey
        deriving stock   (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    data SignKeyKES (RustKES t) = Sign SecretKey
        deriving stock    (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    data SigKES (RustKES t) = Sig Signature
        deriving stock    (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    totalPeriodsKES _ = fromIntegral (natVal (Proxy @ t))               -- requires ScopedTypeVariables

    algorithmNameKES proxy = "Rust_" ++ show (totalPeriodsKES proxy)

    sizeVerKeyKES  _ = CWrap.PUBLIC_KEY_SIZE    -- 32
    sizeSignKeyKES _ = CWrap.SECRET_KEY_SIZE    -- 1220
    sizeSigKES     _ = CWrap.SIGNATURE_SIZE     -- 484
    seedSizeKES    _ = SEED_SIZE                -- 32

    type Signable (RustKES t) = ToCBOR

    -- | Produce valid signature only with correct key, i.e., same iteration and allowed KES period.
    signKES () period object (Sign secret) =
        let period' = period_from(secret) in assert (period == period') $ Sig (sign secret object)

    deriveVerKeyKES (Sign secret) = Verify(compute_public secret)

    verifyKES () (Verify public) _period object (Sig signature) =
        if verify public object signature then Right() else Left "KES verification failed"

    updateKES () (Sign secret) period =
       let period' = period_from(secret)
       in assert (period == period') $
             (if period +1 < (totalPeriodsKES (Proxy @ (RustKES t)))
                 then Just (Sign (update secret))
                 else Nothing)

    genKeyKES seed = Sign secret
       where (public,secret) = generate seed

    rawSerialiseVerKeyKES (Verify (PublicKey public)) = public
    rawSerialiseSignKeyKES (Sign (SecretKey secret)) = convert secret
    rawSerialiseSigKES (Sig (Signature s)) = s

    rawDeserialiseVerKeyKES bs = Just(Verify (PublicKey bs))
    rawDeserialiseSignKeyKES bs = Just(Sign (SecretKey (convert secret)))
       where (secret,public) = BS.splitAt 1220 bs
    rawDeserialiseSigKES bs = Just(Sig (Signature bs))


-- =========================================================
