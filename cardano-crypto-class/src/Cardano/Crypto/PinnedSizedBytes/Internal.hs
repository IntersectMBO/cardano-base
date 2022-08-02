{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MagicHash #-}

module Cardano.Crypto.PinnedSizedBytes.Internal (
  PinnedSizedBytes (..),
  psbUseAsCPtr,
  runAndTouch,
  ) where

import Data.Kind (Type)
import Data.Primitive.ByteArray (
  ByteArray,
  MutableByteArray (MutableByteArray),
  foldrByteArray,
  byteArrayContents,
  newPinnedByteArray,
  unsafeFreezeByteArray,
  copyByteArrayToAddr,
  )
import GHC.TypeNats (Nat, KnownNat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (OnlyCheckWhnfNamed))
import Control.DeepSeq (NFData)
import Data.Word (Word8)
import Foreign.C.Types (CSize)
import Data.Proxy (Proxy (Proxy))
import Numeric (showHex)
import System.IO.Unsafe (unsafeDupablePerformIO)
import GHC.Exts (Ptr (Ptr), Int (I#), copyAddrToByteArray#)
import Foreign.Ptr (FunPtr, castPtr)
import Foreign.Storable (Storable (sizeOf, alignment, peek, poke))
import Cardano.Crypto.Libsodium.C (c_sodium_compare)
import Control.Monad.Primitive (touch, primitive_)

-- | @n@ bytes. 'Storable'.
--
-- We have two @*Bytes@ types:
--
-- * @PinnedSizedBytes@ is backed by pinned ByteArray.
-- * @MLockedSizedBytes@ is backed by ForeignPtr to @mlock@-ed memory region.
--
-- The 'ByteString' is pinned datatype, but it's represented by
-- 'ForeignPtr' + offset (and size).
--
-- I'm sorry for adding more types for bytes. :(
--
newtype PinnedSizedBytes (n :: Nat) = PSB ByteArray
  deriving NoThunks via OnlyCheckWhnfNamed "PinnedSizedBytes" (PinnedSizedBytes n)
  deriving NFData via ByteArray

instance Show (PinnedSizedBytes n) where
    showsPrec _ (PSB ba)
        = showChar '"'
        . foldrByteArray (\w acc -> show8 w . acc) id ba
        . showChar '"'
      where
        show8 :: Word8 -> ShowS
        show8 w | w < 16    = showChar '0' . showHex w
                | otherwise = showHex w

-- | The comparison is done in constant time for a given size @n@.
instance KnownNat n => Eq (PinnedSizedBytes n) where
    x == y = compare x y == EQ

instance KnownNat n => Ord (PinnedSizedBytes n) where
    compare x y =
        unsafeDupablePerformIO $
            psbUseAsCPtr x $ \xPtr ->
                psbUseAsCPtr y $ \yPtr -> do
                    res <- c_sodium_compare xPtr yPtr size
                    return (compare res 0)
      where
        size :: CSize
        size = fromIntegral (natVal (Proxy :: Proxy n))

instance KnownNat n => Storable (PinnedSizedBytes n) where
    sizeOf _          = fromIntegral (natVal (Proxy :: Proxy n))
    alignment _       = alignment (undefined :: FunPtr (Int -> Int))
    peek (Ptr addr#) = do
        let size :: Int
            size = fromIntegral (natVal (Proxy :: Proxy n))
        marr@(MutableByteArray marr#) <- newPinnedByteArray size
        primitive_ $ copyAddrToByteArray# addr# marr# 0# (case size of I# s -> s)
        arr <- unsafeFreezeByteArray marr
        return (PSB arr)
    poke p (PSB arr) = do
        let size :: Int
            size = fromIntegral (natVal (Proxy :: Proxy n))
        copyByteArrayToAddr (castPtr p) arr 0 size

-- | Use a 'PinnedSizedBytes' in a setting where its size is \'forgotten\'
-- temporarily.
--
-- = Note
--
-- The 'Ptr' given to the function argument /must not/ be used as the result of
-- type @r@.
psbUseAsCPtr :: 
  forall (n :: Nat) (r :: Type) .
  PinnedSizedBytes n -> 
  (Ptr Word8 -> IO r) -> 
  IO r
psbUseAsCPtr (PSB ba) = runAndTouch ba

-- Wrapper that combines applying a function, then touching
runAndTouch :: 
  forall (a :: Type) . 
  ByteArray -> 
  (Ptr Word8 -> IO a) ->
  IO a
runAndTouch ba f = do
  r <- f (byteArrayContents ba)
  r <$ touch ba
