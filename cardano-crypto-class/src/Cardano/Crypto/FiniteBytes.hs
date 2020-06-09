{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE MagicHash           #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UnboxedTuples       #-}
module Cardano.Crypto.FiniteBytes
  (
    FiniteBytes,
    -- * Conversions
    fromBytes,
    toBytes,
  ) where


import Control.Monad.Primitive  (primitive_)
import Data.Char (ord)
import Data.Primitive.ByteArray (ByteArray (..), MutableByteArray (..), byteArrayFromListN, copyByteArrayToAddr, newByteArray, unsafeFreezeByteArray, foldrByteArray)
import Data.Proxy (Proxy (..))
import Data.String (IsString (..))
import Data.Word (Word8)
import Foreign.Ptr (FunPtr, castPtr)
import Foreign.Storable (Storable (..))
import GHC.TypeLits (KnownNat, Nat, natVal)
import Numeric (showHex)

import GHC.Exts (Int (..))
import GHC.Prim (copyAddrToByteArray#)
import GHC.Ptr (Ptr (..))

-- $setup
-- >>> :set -XDataKinds -XTypeApplications -XOverloadedStrings
-- >>> import Cardano.Crypto.FiniteBytes

-- | @n@ bytes. 'Storable'.
data FiniteBytes (n :: Nat) = FiniteBytes ByteArray

instance Show (FiniteBytes n) where
    showsPrec _ (FiniteBytes ba)
        = showChar '"'
        . foldrByteArray (\w acc -> show8 w . acc) id ba
        . showChar '"'
      where
        show8 :: Word8 -> ShowS
        show8 w | w < 16    = showChar '0' . showHex w
                | otherwise = showHex w

-- |
--
-- If given 'String' is too long, it is truncated,
-- If it is too short, it is padded with zeros.
--
-- Padding and truncation make it behave like an integer mod @n*8@.
--
-- >>> "abcdef" :: FiniteBytes 4
-- "63646566"
--
-- >>> "foo" :: FiniteBytes 8
-- "0000000000666f6f"
--
-- Non-ASCII codepoints are silently truncated to 0..255 range.
--
-- >>> "\x1234\x5678" :: FiniteBytes 2
-- "3478"
--
-- 'FiniteBytes' created with 'fromString' contains /unpinned/
-- 'ByteArray'.
--
instance KnownNat n => IsString (FiniteBytes n) where
    fromString s = fromBytes (map (fromIntegral . ord) s)

-- | See 'fromBytes'.
toBytes :: FiniteBytes n -> [Word8]
toBytes (FiniteBytes ba) = foldrByteArray (:) [] ba

-- | See @'IsString' ('FiniteBytes' n)@ instance.
--
-- >>> toBytes . (id @(FiniteBytes 4)) . fromBytes $ [1,2,3,4]
-- [1,2,3,4]
--
-- >>> toBytes . (id @(FiniteBytes 4)) . fromBytes $ [1,2]
-- [0,0,1,2]
--
-- >>> toBytes . (id @(FiniteBytes 4)) . fromBytes $ [1,2,3,4,5,6]
-- [3,4,5,6]
-- 
fromBytes :: forall n. KnownNat n => [Word8] -> FiniteBytes n
fromBytes ws0 = FiniteBytes (byteArrayFromListN size ws)
  where
    size :: Int
    size = fromInteger (natVal (Proxy :: Proxy n))

    ws :: [Word8]
    ws = reverse
        $ take size
        $ (++ repeat 0)
        $ reverse ws0

instance KnownNat n => Storable (FiniteBytes n) where
    sizeOf _          = fromInteger (natVal (Proxy :: Proxy n))
    alignment _       = alignment (undefined :: FunPtr (Int -> Int))

    peek (Ptr addr#) = do
        let size :: Int
            size = fromInteger (natVal (Proxy :: Proxy n))
        marr@(MutableByteArray marr#) <- newByteArray size
        primitive_ $ copyAddrToByteArray# addr# marr# 0# (case size of I# s -> s)
        arr <- unsafeFreezeByteArray marr
        return (FiniteBytes arr)

    poke p (FiniteBytes arr) = do
        let size :: Int
            size = fromInteger (natVal (Proxy :: Proxy n))
        copyByteArrayToAddr (castPtr p) arr 0 size
