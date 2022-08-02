{-# LANGUAGE DerivingVia                #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE MagicHash                  #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeApplications           #-}

module Cardano.Crypto.PinnedSizedBytes
  (
    PinnedSizedBytes,
    -- * Quasiquoter
    psbHex,
    -- * Conversions
    psbToBytes,
    psbFromByteStringCheck,
    psbToByteString,
    -- * C usage
    psbUseAsCPtr,
    psbUseAsCPtrLen,
    psbUseAsSizedPtr,
    psbCreate,
    psbCreateLen,
    psbCreateSized,
    psbCreateResult,
    psbCreateResultLen,
    psbCreateSizedResult,
    ptrPsbToSizedPtr,
  ) where

import Cardano.Crypto.PinnedSizedBytes.Internal (
  PinnedSizedBytes (PSB),
  runAndTouch,
  psbUseAsCPtr,
  )
import Cardano.Crypto.PinnedSizedBytes.TH (psbHex)
import Data.Kind (Type)
import Control.Monad.Primitive  (primitive_, touch)
import Data.Primitive.ByteArray
          ( MutableByteArray (MutableByteArray)
          , newPinnedByteArray
          , unsafeFreezeByteArray
          , foldrByteArray
          , byteArrayContents
          , mutableByteArrayContents
          )
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Foreign.C.Types (CSize)
import Foreign.Ptr (castPtr)
import GHC.TypeLits (KnownNat, Nat, natVal)
import System.IO.Unsafe (unsafeDupablePerformIO)
import GHC.Exts (Int (I#))
import GHC.Prim (copyAddrToByteArray#)
import GHC.Ptr (Ptr (Ptr))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Cardano.Foreign (SizedPtr (SizedPtr))

{- HLINT ignore "Reduce duplication" -}

-- $setup
-- >>> :set -XDataKinds -XTypeApplications -XOverloadedStrings
-- >>> import Cardano.Crypto.PinnedSizedBytes

psbToBytes :: PinnedSizedBytes n -> [Word8]
psbToBytes (PSB ba) = foldrByteArray (:) [] ba

psbToByteString :: PinnedSizedBytes n -> ByteString
psbToByteString = BS.pack . psbToBytes

psbFromByteStringCheck :: forall (n :: Nat) . 
  (KnownNat n) => ByteString -> Maybe (PinnedSizedBytes n)
psbFromByteStringCheck bs 
    | BS.length bs == size = Just $ unsafeDupablePerformIO $
        BS.useAsCStringLen bs $ \(Ptr addr#, _) -> do
            marr@(MutableByteArray marr#) <- newPinnedByteArray size
            primitive_ $ copyAddrToByteArray# addr# marr# 0# (case size of I# s -> s)
            arr <- unsafeFreezeByteArray marr
            return (PSB arr)
    | otherwise            = Nothing
  where
    size :: Int
    size = fromInteger (natVal (Proxy :: Proxy n))

-- | As 'psbUseAsCPtr', but also gives the function argument the size we are
-- allowed to use as a 'CSize'.
--
-- This is mostly boilerplate removal, as it is quite common for C APIs to take
-- a combination of a pointer to some data and its length. A possible use case
-- (and one we run into) is where we know that we can expect a certain data
-- length (using 'PinnedSizedBytes' as its representation), but the C API allows
-- any length we like, provided we give the right argument to indicate this.
-- Therefore, having a helper like this one allows us to avoid having to
-- manually 'natVal' a 'Proxy', as well as ensuring we don't get mismatches
-- accidentally.
--
-- The same caveats apply to the use of this function as to the use of
-- 'psbUseAsCPtr'.
psbUseAsCPtrLen :: 
  forall (n :: Nat) (r :: Type) . 
  (KnownNat n) => 
  PinnedSizedBytes n ->
  (Ptr Word8 -> CSize -> IO r) -> 
  IO r
psbUseAsCPtrLen (PSB ba) f = do
  let len :: CSize = fromIntegral . natVal $ Proxy @n
  runAndTouch ba (`f` len)

-- | As 'psbUseAsCPtr', but does not \'forget\' the size.
--
-- The same caveats apply to this use of this function as to the use of
-- 'psbUseAsCPtr'.
psbUseAsSizedPtr :: 
  forall (n :: Nat) (r :: Type) . 
  PinnedSizedBytes n -> 
  (SizedPtr n -> IO r) -> 
  IO r
psbUseAsSizedPtr (PSB ba) k = do
    r <- k (SizedPtr $ castPtr $ byteArrayContents ba)
    r <$ touch ba

-- | As 'psbCreateResult', but presumes that no useful value is produced: that
-- is, the function argument is run only for its side effects.
psbCreate :: 
  forall (n :: Nat) . 
  (KnownNat n) => 
  (Ptr Word8 -> IO ()) -> 
  IO (PinnedSizedBytes n)
psbCreate f = fst <$> psbCreateResult f

-- | As 'psbCreateResultLen', but presumes that no useful value is produced:
-- that is, the function argument is run only for its side effects.
psbCreateLen :: 
  forall (n :: Nat) . 
  (KnownNat n) => 
  (Ptr Word8 -> CSize -> IO ()) -> 
  IO (PinnedSizedBytes n)
psbCreateLen f = fst <$> psbCreateResultLen f

-- | Given an \'initialization action\', which also produces some result, allocate
-- new pinned memory of the specified size, perform the action, then return the
-- result together with the initialized pinned memory (as a 'PinnedSizedBytes').
--
-- = Note
--
-- It is essential that @r@ is not the 'Ptr' given to the function argument.
-- Returning this 'Ptr' is /extremely/ unsafe:
--
-- * It breaks referential transparency guarantees by aliasing supposedly
-- immutable memory; and
-- * This 'Ptr' could refer to memory which has already been garbage collected,
-- which can lead to segfaults or out-of-bounds reads.
--
-- This poses both correctness /and/ security risks, so please don't do it.
psbCreateResult :: 
  forall (n :: Nat) (r :: Type) . 
  (KnownNat n) => 
  (Ptr Word8 -> IO r) -> 
  IO (PinnedSizedBytes n, r)
psbCreateResult f = psbCreateResultLen (\p _ -> f p)

-- | As 'psbCreateResult', but also gives the number of bytes we are allowed to
-- operate on as a 'CSize'.
--
-- This function is provided for two reasons:
--
-- * It is a common practice in C libraries to pass a pointer to data plus a
-- length. While /our/ use case might know the size we expect, the C function we
-- are calling might be more general. This simplifies calling such functions.
-- * We avoid 'natVal'ing a 'Proxy' /twice/, since we have to do it anyway.
--
-- The same caveats apply to this function as to 'psbCreateResult': the 'Ptr'
-- given to the function argument /must not/ be returned as @r@.
psbCreateResultLen :: 
  forall (n :: Nat) (r :: Type) . 
  (KnownNat n) => 
  (Ptr Word8 -> CSize -> IO r) -> 
  IO (PinnedSizedBytes n, r)
psbCreateResultLen f = do
  let len :: Int = fromIntegral . natVal $ Proxy @n
  mba <- newPinnedByteArray len
  res <- f (mutableByteArrayContents mba) (fromIntegral len)
  arr <- unsafeFreezeByteArray mba
  pure (PSB arr, res)

-- | As 'psbCreateSizedResult', but presumes that no useful value is produced:
-- that is, the function argument is run only for its side effects.
psbCreateSized :: 
  forall (n :: Nat). 
  (KnownNat n) => 
  (SizedPtr n -> IO ()) -> 
  IO (PinnedSizedBytes n)
psbCreateSized k = psbCreate (k . SizedPtr . castPtr)

-- | As 'psbCreateResult', but gives a 'SizedPtr' to the function argument. The
-- same caveats apply to this function as to 'psbCreateResult': the 'SizedPtr'
-- given to the function argument /must not/ be resulted as @r@.
psbCreateSizedResult :: 
  forall (n :: Nat) (r :: Type) . 
  (KnownNat n) => 
  (SizedPtr n -> IO r) -> 
  IO (PinnedSizedBytes n, r)
psbCreateSizedResult f = psbCreateResult (f . SizedPtr . castPtr)

ptrPsbToSizedPtr :: Ptr (PinnedSizedBytes n) -> SizedPtr n
ptrPsbToSizedPtr = SizedPtr . castPtr
