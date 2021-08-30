{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeFamilyDependencies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE UndecidableInstances #-}

module Cardano.Crypto.PackedBytes
  ( PackedBytes
  , CanUnpack
  , packBytes
  , unpackBytes
  , applyOrdPackedBytes
  ) where

import Control.DeepSeq
import Control.Monad
import Data.ByteString.Short
import Data.ByteString.Short.Internal
import Data.Maybe
import Data.Primitive.ByteArray
import Data.Typeable
import Data.Word
import GHC.Exts
import GHC.ST
import GHC.TypeLits
import NoThunks.Class
#if WORD_SIZE_IN_BITS == 32
import GHC.Word (byteSwap32)
#endif

#include "MachDeps.h"


data PackedBytes28 = PackedBytes28# Word16# Word16# Word16# Word16#
                                    Word16# Word16# Word16# Word16#
                                    Word16# Word16# Word16# Word16#
                                    Word16# Word16#
  deriving (Eq, Ord)
deriving via OnlyCheckWhnfNamed "PackedBytes28" PackedBytes28 instance NoThunks PackedBytes28

instance NFData PackedBytes28 where
  rnf PackedBytes28# {}  = ()

indexWord32BE# :: ByteArray# -> Int# -> Word#
#ifdef WORDS_BIGENDIAN
indexWord32BE# ba# i# = indexWord8ArrayAsWord32# ba# i#
#else
indexWord32BE# ba# i# = byteSwap32# (indexWord8ArrayAsWord32# ba# i#)
#endif
{-# INLINE indexWord32BE# #-}

writeWord32BE# ::
     MutableByteArray# s
  -> Int#
  -> Word#
  -> State# s
  -> State# s
writeWord32BE# mba# i# w# = writeWord8ArrayAsWord32# mba# i# wbe#
  where
#ifdef WORDS_BIGENDIAN
    !wbe# = w#
#else
    !wbe# = byteSwap32# w#
#endif
{-# INLINE writeWord32BE# #-}


index64BitWord16sBE# :: ByteArray# -> Int# -> (# Word16#, Word16#, Word16#, Word16# #)
index64BitWord16sBE# ba# i# =
#if WORD_SIZE_IN_BITS == 64
  let w# = indexWordBE# ba# i#
  in (# narrowWord16# (shiftRL# w# 48#)
     ,  narrowWord16# (shiftRL# w# 32#)
     ,  narrowWord16# (shiftRL# w# 16#)
     ,  narrowWord16# w#
     #)
#elif WORD_SIZE_IN_BITS == 32
  let w1# = indexWord32BE# ba# i#
      w2# = indexWord32BE# ba# (i# +# 4#)
  in (# narrowWord16# (shiftRL# w1# 16#)
     ,  narrowWord16# w1#
     ,  narrowWord16# (shiftRL# w2# 16#)
     ,  narrowWord16# w2#
     #)
#else
#error "Unsupported architecture"
#endif
{-# INLINE index64BitWord16sBE# #-}

write32BitWord16sBE# ::
     MutableByteArray# s
  -> Int#
  -> Word16#
  -> Word16#
  -> State# s
  -> State# s
write32BitWord16sBE# mba# i# w1# w2# =
  writeWord32BE# mba# i# (narrow32Word# (shiftL# (extendWord16# w1#) 16# `or#` extendWord16# w2#))
{-# INLINE write32BitWord16sBE# #-}


write64BitWord16sBE# ::
     MutableByteArray# s
  -> Int#
  -> Word16#
  -> Word16#
  -> Word16#
  -> Word16#
  -> State# s
  -> State# s
write64BitWord16sBE# mba# i# w1# w2# w3# w4# s# =
#if WORD_SIZE_IN_BITS == 64
  writeWordBE# mba# i# (shiftL# (extendWord16# w1#) 48# `or#`
                        shiftL# (extendWord16# w2#) 32# `or#`
                        shiftL# (extendWord16# w3#) 16# `or#`
                        extendWord16# w4#) s#
#elif WORD_SIZE_IN_BITS == 32
  writeWord32BE# mba# (i# +# 4#) (shiftL# (extendWord16# w3#) 16# `or#` extendWord16# w4#)
  (writeWord32BE# mba# i# (shiftL# (extendWord16# w1#) 16# `or#` extendWord16# w2#) s#)
#else
#error "Unsupported architecture"
#endif

packBytes28 :: ShortByteString -> PackedBytes28
packBytes28 (SBS ba#) =
  let !(# w01#, w02#, w03#, w04# #) = index64BitWord16sBE# ba# 0#
      !(# w11#, w12#, w13#, w14# #) = index64BitWord16sBE# ba# 8#
      !(# w21#, w22#, w23#, w24# #) = index64BitWord16sBE# ba# 16#
      !w# = indexWord32BE# ba# 24#
      !w31# = narrowWord16# (shiftRL# w# 16#)
      !w32# = narrowWord16# w#
  in PackedBytes28# w01# w02# w03# w04# w11# w12# w13# w14# w21# w22# w23# w24# w31# w32#
{-# INLINE packBytes28 #-}

unpackBytes28 :: PackedBytes28 -> ShortByteString
unpackBytes28
  (PackedBytes28# w00# w01# w02# w03# w04# w05# w06# w07# w08# w09# w10# w11# w12# w13#) =
  runST $ ST $ \s0# ->
    case newByteArray# 28# s0# of
      (# s1#, mba# #) ->
        let s2# = write32BitWord16sBE# mba# 24# w12# w13#
                   (write64BitWord16sBE# mba# 16# w08# w09# w10# w11#
                    (write64BitWord16sBE# mba# 8# w04# w05# w06# w07#
                     (write64BitWord16sBE# mba# 0# w00# w01# w02# w03# s1#)))
        in case unsafeFreezeByteArray# mba# s2# of
          (# s3#, ba# #) -> (# s3#, SBS ba# #)
{-# INLINE unpackBytes28 #-}

#if WORD_SIZE_IN_BITS == 64


indexWordBE# :: ByteArray# -> Int# -> Word#
#ifdef WORDS_BIGENDIAN
indexWordBE# ba# i# = indexWord8ArrayAsWord# ba# i#
#else
indexWordBE# ba# i# = byteSwap# (indexWord8ArrayAsWord# ba# i#)
#endif
{-# INLINE indexWordBE# #-}


writeWordBE# ::
     MutableByteArray# s
  -> Int#
  -> Word#
  -> State# s
  -> State# s
writeWordBE# mba# i# w# = writeWord8ArrayAsWord# mba# i# wbe#
  where
#ifdef WORDS_BIGENDIAN
    !wbe# = w#
#else
    !wbe# = byteSwap# w#
#endif
{-# INLINE writeWordBE# #-}




data PackedBytes32 =
  PackedBytes32
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
    {-# UNPACK #-} !Word64
  deriving (Eq, Ord)
deriving via OnlyCheckWhnfNamed "PackedBytes32" PackedBytes32 instance NoThunks PackedBytes32

instance NFData PackedBytes32 where
  rnf PackedBytes32 {}  = ()

unpackBytes32 :: PackedBytes32 -> ShortByteString
unpackBytes32 (PackedBytes32 w0 w1 w2 w3) =
  runST $ do
    mba <- newByteArray 32
    writeByteArray mba 0 $ byteSwap64 w0
    writeByteArray mba 1 $ byteSwap64 w1
    writeByteArray mba 2 $ byteSwap64 w2
    writeByteArray mba 3 $ byteSwap64 w3
    ByteArray ba# <- unsafeFreezeByteArray mba
    pure $ SBS ba#
{-# INLINE unpackBytes32 #-}

packBytes32 :: ShortByteString -> PackedBytes32
packBytes32 (SBS ba#) =
  let ba = ByteArray ba#
  in PackedBytes32
       (byteSwap64 (indexByteArray ba 0))
       (byteSwap64 (indexByteArray ba 1))
       (byteSwap64 (indexByteArray ba 2))
       (byteSwap64 (indexByteArray ba 3))
{-# INLINE packBytes32 #-}


#elif WORD_SIZE_IN_BITS == 32

data PackedBytes32 =
  PackedBytes32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
    {-# UNPACK #-} !Word32
  deriving (Eq, Ord)
deriving via OnlyCheckWhnfNamed "PackedBytes32" PackedBytes32 instance NoThunks PackedBytes32

instance NFData PackedBytes32 where
  rnf PackedBytes32 {}  = ()

unpackBytes32 :: PackedBytes32 -> ShortByteString
unpackBytes32 (PackedBytes32 w0 w1 w2 w3 w4 w5 w6 w7) =
  runST $ do
    mba <- newByteArray 32
    writeByteArray mba 0 $ byteSwap32 w0
    writeByteArray mba 1 $ byteSwap32 w1
    writeByteArray mba 2 $ byteSwap32 w2
    writeByteArray mba 3 $ byteSwap32 w3
    writeByteArray mba 4 $ byteSwap32 w4
    writeByteArray mba 5 $ byteSwap32 w5
    writeByteArray mba 6 $ byteSwap32 w6
    writeByteArray mba 7 $ byteSwap32 w7
    ByteArray ba# <- unsafeFreezeByteArray mba
    pure $ SBS ba#
{-# INLINE unpackBytes32 #-}

packBytes32 :: ShortByteString -> PackedBytes32
packBytes32 (SBS ba#) =
  let ba = ByteArray ba#
  in PackedBytes32
       (byteSwap32 (indexByteArray ba 0))
       (byteSwap32 (indexByteArray ba 1))
       (byteSwap32 (indexByteArray ba 2))
       (byteSwap32 (indexByteArray ba 3))
       (byteSwap32 (indexByteArray ba 4))
       (byteSwap32 (indexByteArray ba 5))
       (byteSwap32 (indexByteArray ba 6))
       (byteSwap32 (indexByteArray ba 7))
{-# INLINE packBytes32 #-}
#else
#error "Unsupported architecture"
#endif


newtype UnpackedBytes (n :: Nat) = UnpackedBytes { getUnpackedBytes :: ShortByteString }
  deriving (Eq, Ord)

type family PackedBytes (n :: Nat) = pb | pb -> n where
  PackedBytes 28 = PackedBytes28
  PackedBytes 32 = PackedBytes32
  PackedBytes n  = UnpackedBytes n

type family CanUnpack (n :: Nat) :: Constraint where
  CanUnpack n = CanUnpackError n (CmpNat n 32)


type family CanUnpackError (n :: Nat) (c :: Ordering) :: Constraint where
  CanUnpackError n 'LT = ()
  CanUnpackError n 'EQ = ()
  CanUnpackError n 'GT = TypeError ('Text "Unpackable number of bytes: " ':<>: 'ShowType n)

packBytesN ::
     forall n m. (Typeable n, Typeable m)
  => (ShortByteString -> PackedBytes m)
  -> ShortByteString
  -> Maybe (PackedBytes n)
packBytesN p sbs =
  case eqT :: Maybe (Proxy n :~: Proxy m) of
    Just Refl -> Just $ p sbs
    Nothing   -> Nothing

packBytes :: forall n . Typeable n => ShortByteString -> PackedBytes n
packBytes sbs =
  fromMaybe (error "Unpackable bytes") $
    msum [ packBytesN @n (UnpackedBytes @0) sbs
         , packBytesN @n (UnpackedBytes @1) sbs
         , packBytesN @n (UnpackedBytes @2) sbs
         , packBytesN @n (UnpackedBytes @3) sbs
         , packBytesN @n (UnpackedBytes @4) sbs
         , packBytesN @n (UnpackedBytes @5) sbs
         , packBytesN @n (UnpackedBytes @6) sbs
         , packBytesN @n (UnpackedBytes @7) sbs
         , packBytesN @n (UnpackedBytes @8) sbs
         , packBytesN @n (UnpackedBytes @9) sbs
         , packBytesN @n (UnpackedBytes @10) sbs
         , packBytesN @n (UnpackedBytes @11) sbs
         , packBytesN @n (UnpackedBytes @12) sbs
         , packBytesN @n (UnpackedBytes @13) sbs
         , packBytesN @n (UnpackedBytes @14) sbs
         , packBytesN @n (UnpackedBytes @15) sbs
         , packBytesN @n (UnpackedBytes @16) sbs
         , packBytesN @n (UnpackedBytes @17) sbs
         , packBytesN @n (UnpackedBytes @18) sbs
         , packBytesN @n (UnpackedBytes @19) sbs
         , packBytesN @n (UnpackedBytes @20) sbs
         , packBytesN @n (UnpackedBytes @21) sbs
         , packBytesN @n (UnpackedBytes @22) sbs
         , packBytesN @n (UnpackedBytes @23) sbs
         , packBytesN @n (UnpackedBytes @24) sbs
         , packBytesN @n (UnpackedBytes @25) sbs
         , packBytesN @n (UnpackedBytes @26) sbs
         , packBytesN @n (UnpackedBytes @27) sbs
         , packBytesN @n packBytes28 sbs
         , packBytesN @n (UnpackedBytes @29) sbs
         , packBytesN @n (UnpackedBytes @30) sbs
         , packBytesN @n (UnpackedBytes @31) sbs
         , packBytesN @n packBytes32 sbs
         ]
{-# INLINE[1] packBytes #-}

unpackBytesN ::
     forall n m. (Typeable n, Typeable m)
  => (PackedBytes m -> ShortByteString)
  -> PackedBytes n
  -> Maybe ShortByteString
unpackBytesN p sbs =
  case eqT :: Maybe (n :~: m) of
    Just Refl -> Just $ p sbs
    Nothing   -> Nothing


unpackBytes :: forall n . Typeable n => PackedBytes n -> ShortByteString
unpackBytes pb =
  fromMaybe (error "Unpackable bytes") $
    msum [ unpackBytesN @n (getUnpackedBytes @0) pb
         , unpackBytesN @n (getUnpackedBytes @1) pb
         , unpackBytesN @n (getUnpackedBytes @2) pb
         , unpackBytesN @n (getUnpackedBytes @3) pb
         , unpackBytesN @n (getUnpackedBytes @4) pb
         , unpackBytesN @n (getUnpackedBytes @5) pb
         , unpackBytesN @n (getUnpackedBytes @6) pb
         , unpackBytesN @n (getUnpackedBytes @7) pb
         , unpackBytesN @n (getUnpackedBytes @8) pb
         , unpackBytesN @n (getUnpackedBytes @9) pb
         , unpackBytesN @n (getUnpackedBytes @10) pb
         , unpackBytesN @n (getUnpackedBytes @11) pb
         , unpackBytesN @n (getUnpackedBytes @12) pb
         , unpackBytesN @n (getUnpackedBytes @13) pb
         , unpackBytesN @n (getUnpackedBytes @14) pb
         , unpackBytesN @n (getUnpackedBytes @15) pb
         , unpackBytesN @n (getUnpackedBytes @16) pb
         , unpackBytesN @n (getUnpackedBytes @17) pb
         , unpackBytesN @n (getUnpackedBytes @18) pb
         , unpackBytesN @n (getUnpackedBytes @19) pb
         , unpackBytesN @n (getUnpackedBytes @20) pb
         , unpackBytesN @n (getUnpackedBytes @21) pb
         , unpackBytesN @n (getUnpackedBytes @22) pb
         , unpackBytesN @n (getUnpackedBytes @23) pb
         , unpackBytesN @n (getUnpackedBytes @24) pb
         , unpackBytesN @n (getUnpackedBytes @25) pb
         , unpackBytesN @n (getUnpackedBytes @26) pb
         , unpackBytesN @n (getUnpackedBytes @27) pb
         , unpackBytesN @n unpackBytes28 pb
         , unpackBytesN @n (getUnpackedBytes @29) pb
         , unpackBytesN @n (getUnpackedBytes @30) pb
         , unpackBytesN @n (getUnpackedBytes @31) pb
         , unpackBytesN @n unpackBytes32 pb
         ]
{-# INLINE[1] unpackBytes #-}

{-# RULES
"packBytes28" packBytes = packBytes28
"packBytes32" packBytes = packBytes32
"unpackBytes28" unpackBytes = unpackBytes28
"unpackBytes32" unpackBytes = unpackBytes32
  #-}


applyOrdPackedBytes ::
     forall n b. Typeable n
  => (forall a. Ord a => a -> a -> b)
  -> PackedBytes n
  -> PackedBytes n
  -> b
applyOrdPackedBytes f x1 x2 =
  case eqT :: Maybe (n :~: 28) of
    Just Refl -> f x1 x2
    Nothing -> case eqT :: Maybe (n :~: 32) of
      Just Refl -> f x1 x2
      Nothing   -> f (unpackBytes x1) (unpackBytes x2)
{-# INLINE applyOrdPackedBytes #-}
