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


module Rust(go) where


-- ==========================================================
-- import pointers and words to interface with C code

import Data.Word(Word8)
import Foreign(Ptr)
import Foreign.ForeignPtr(mallocForeignPtrBytes,ForeignPtr)
import Foreign.Storable(pokeElemOff)


-- ==========================================================
-- import the KES wrappers that are just C-calls

import qualified KES as CWrap -- (verify, generate, sign, t, update)


-- ===========================================================
-- import different kinds of Byte Strings and operations

import Data.ByteArray(ScrubbedBytes,convert,allocRet,withByteArray,copyByteArrayToPtr,pack)
import qualified Data.ByteString as BS
import Data.ByteString(ByteString,copy)


-- ===========================================================
-- Sizes and Types


pattern SIGNATURE_SIZE = 484
pattern SECRET_KEY_SIZE = 1220
pattern PUBLIC_KEY_SIZE = 32
pattern SEED_SIZE = 32

newtype PublicKey = PublicKey BS.ByteString deriving Show
newtype SecretKey = SecretKey ScrubbedBytes deriving Show
newtype Signature = Signature BS.ByteString deriving Show
newtype Seed = Seed { unSeed :: ScrubbedBytes } deriving Show




-- ============================================================
-- Higher level wrappers that call the C language wrappers

createSeed :: IO Seed
createSeed = do
  (_,seed) <- allocRet SEED_SIZE $ \seed_ptr -> do
    mapM_ (\i -> pokeElemOff seed_ptr i ((fromIntegral i) :: Word8)) [0..31]
  pure $ Seed seed


generate :: Seed -> IO (PublicKey, SecretKey)
generate  seed = do
  withByteArray (unSeed seed) $ \seed_ptr -> do
    (public, secret) <- allocRet SECRET_KEY_SIZE $ \secret -> do
      (_,public) <- allocRet PUBLIC_KEY_SIZE $ \public_ptr -> do
        CWrap.generate seed_ptr secret public_ptr
      pure $ PublicKey public
    pure (public, SecretKey secret)


verify :: PublicKey -> BS.ByteString -> Signature -> IO Bool
verify (PublicKey pub) message (Signature sig) = do
  withByteArray pub $ \pub_ptr -> do
    withByteArray message $ \msg_ptr -> do
      withByteArray sig $ \sig_ptr -> do
        pure $ CWrap.verify pub_ptr msg_ptr (fromIntegral $ BS.length message) sig_ptr


sign :: SecretKey -> BS.ByteString -> IO Signature
sign (SecretKey sec) message = do
  withByteArray sec $ \sec_ptr -> do
    withByteArray message $ \msg_ptr -> do
      (_, sig) <- allocRet SIGNATURE_SIZE $ \sig_ptr -> do
        CWrap.sign sec_ptr msg_ptr (fromIntegral $ BS.length message) sig_ptr
      pure $ Signature sig


update :: SecretKey -> IO ()
update (SecretKey sec) = do
  withByteArray sec $ \sec_ptr -> do
    CWrap.update sec_ptr

compute_public :: SecretKey -> IO PublicKey
compute_public secret = do
  withByteArray secret $ \ secret_ptr -> do
    (_,public) <- allocRet PUBLIC_KEY_SIZE $ \public_ptr -> CWrap.compute_public secret_ptr public_ptr
    pure public






go:: IO()
go = putStrLn "DONE"
