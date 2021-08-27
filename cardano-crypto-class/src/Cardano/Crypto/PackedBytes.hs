{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE MagicHash #-}
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


data PackedBytes28 = PackedBytes28# Word16# Word16# Word16# Word16#
                                    Word16# Word16# Word16# Word16#
                                    Word16# Word16# Word16# Word16#
                                    Word16# Word16#
  deriving (Eq, Ord)
deriving via OnlyCheckWhnfNamed "PackedBytes28" PackedBytes28 instance NoThunks PackedBytes28

instance NFData PackedBytes28 where
  rnf PackedBytes28# {}  = ()

unpackBytes28 :: PackedBytes28 -> ShortByteString
unpackBytes28 (PackedBytes28# w00# w01# w02# w03# w04# w05# w06# w07# w08# w09# w10# w11# w12# w13#) =
  runST $ ST $ \s0# ->
    case newByteArray# 28# s0# of
      (# s1#, mba# #) ->
        let s2# = writeWord16Array# mba# 13# (extendWord16# w13#)
                  (writeWord16Array# mba# 12# (extendWord16# w12#)
                   (writeWord16Array# mba# 11# (extendWord16# w11#)
                    (writeWord16Array# mba# 10# (extendWord16# w10#)
                     (writeWord16Array# mba#  9# (extendWord16# w09#)
                      (writeWord16Array# mba#  8# (extendWord16# w08#)
                       (writeWord16Array# mba#  7# (extendWord16# w07#)
                        (writeWord16Array# mba#  6# (extendWord16# w06#)
                         (writeWord16Array# mba#  5# (extendWord16# w05#)
                          (writeWord16Array# mba#  4# (extendWord16# w04#)
                           (writeWord16Array# mba#  3# (extendWord16# w03#)
                            (writeWord16Array# mba#  2# (extendWord16# w02#)
                             (writeWord16Array# mba#  1# (extendWord16# w01#)
                              (writeWord16Array# mba#  0# (extendWord16# w00#) s1#)))))))))))))
        in case unsafeFreezeByteArray# mba# s2# of
          (# s3#, ba# #) -> (# s3#, SBS ba# #)
{-# INLINE unpackBytes28 #-}


packBytes28 :: ShortByteString -> PackedBytes28
packBytes28 (SBS ba#) =
  PackedBytes28#
    (narrowWord16# (indexWord16Array# ba# 0#))
    (narrowWord16# (indexWord16Array# ba# 1#))
    (narrowWord16# (indexWord16Array# ba# 2#))
    (narrowWord16# (indexWord16Array# ba# 3#))
    (narrowWord16# (indexWord16Array# ba# 4#))
    (narrowWord16# (indexWord16Array# ba# 5#))
    (narrowWord16# (indexWord16Array# ba# 6#))
    (narrowWord16# (indexWord16Array# ba# 7#))
    (narrowWord16# (indexWord16Array# ba# 8#))
    (narrowWord16# (indexWord16Array# ba# 9#))
    (narrowWord16# (indexWord16Array# ba# 10#))
    (narrowWord16# (indexWord16Array# ba# 11#))
    (narrowWord16# (indexWord16Array# ba# 12#))
    (narrowWord16# (indexWord16Array# ba# 13#))
{-# INLINE packBytes28 #-}


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
    writeByteArray mba 0 w0
    writeByteArray mba 1 w1
    writeByteArray mba 2 w2
    writeByteArray mba 3 w3
    ByteArray ba# <- unsafeFreezeByteArray mba
    pure $ SBS ba#
{-# INLINE unpackBytes32 #-}

packBytes32 :: ShortByteString -> PackedBytes32
packBytes32 (SBS ba#) =
  let ba = ByteArray ba#
  in PackedBytes32
       (indexByteArray ba 0)
       (indexByteArray ba 1)
       (indexByteArray ba 2)
       (indexByteArray ba 3)
{-# INLINE packBytes32 #-}


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
     forall n m. (KnownNat n, KnownNat m)
  => Proxy n
  -> (ShortByteString -> PackedBytes m)
  -> ShortByteString
  -> Maybe (PackedBytes n)
packBytesN px p sbs =
  case sameNat px (Proxy :: Proxy m) of
    Just Refl -> Just $ p sbs
    Nothing   -> Nothing

packBytes :: forall n . KnownNat n => ShortByteString -> PackedBytes n
packBytes sbs =
  let px = Proxy :: Proxy n
   in fromMaybe (error "Unpackable bytes") $
      msum [ packBytesN px (UnpackedBytes @0) sbs
           , packBytesN px (UnpackedBytes @1) sbs
           , packBytesN px (UnpackedBytes @2) sbs
           , packBytesN px (UnpackedBytes @3) sbs
           , packBytesN px (UnpackedBytes @4) sbs
           , packBytesN px (UnpackedBytes @5) sbs
           , packBytesN px (UnpackedBytes @6) sbs
           , packBytesN px (UnpackedBytes @7) sbs
           , packBytesN px (UnpackedBytes @8) sbs
           , packBytesN px (UnpackedBytes @9) sbs
           , packBytesN px (UnpackedBytes @10) sbs
           , packBytesN px (UnpackedBytes @11) sbs
           , packBytesN px (UnpackedBytes @12) sbs
           , packBytesN px (UnpackedBytes @13) sbs
           , packBytesN px (UnpackedBytes @14) sbs
           , packBytesN px (UnpackedBytes @15) sbs
           , packBytesN px (UnpackedBytes @16) sbs
           , packBytesN px (UnpackedBytes @17) sbs
           , packBytesN px (UnpackedBytes @18) sbs
           , packBytesN px (UnpackedBytes @19) sbs
           , packBytesN px (UnpackedBytes @20) sbs
           , packBytesN px (UnpackedBytes @21) sbs
           , packBytesN px (UnpackedBytes @22) sbs
           , packBytesN px (UnpackedBytes @23) sbs
           , packBytesN px (UnpackedBytes @24) sbs
           , packBytesN px (UnpackedBytes @25) sbs
           , packBytesN px (UnpackedBytes @26) sbs
           , packBytesN px (UnpackedBytes @27) sbs
           , packBytesN px packBytes28 sbs
           , packBytesN px (UnpackedBytes @29) sbs
           , packBytesN px (UnpackedBytes @30) sbs
           , packBytesN px (UnpackedBytes @31) sbs
           , packBytesN px packBytes32 sbs
           ]
{-# INLINE[1] packBytes #-}

unpackBytesN ::
     forall n m. (KnownNat n, KnownNat m)
  => Proxy n
  -> (PackedBytes m -> ShortByteString)
  -> PackedBytes n
  -> Maybe ShortByteString
unpackBytesN px p sbs =
  case sameNat px (Proxy :: Proxy m) of
    Just Refl -> Just $ p sbs
    Nothing   -> Nothing


unpackBytes :: forall n . KnownNat n => PackedBytes n -> ShortByteString
unpackBytes pb =
  let px = Proxy :: Proxy n
   in fromMaybe (error "Unpackable bytes") $
      msum [ unpackBytesN px (getUnpackedBytes @0) pb
           , unpackBytesN px (getUnpackedBytes @1) pb
           , unpackBytesN px (getUnpackedBytes @2) pb
           , unpackBytesN px (getUnpackedBytes @3) pb
           , unpackBytesN px (getUnpackedBytes @4) pb
           , unpackBytesN px (getUnpackedBytes @5) pb
           , unpackBytesN px (getUnpackedBytes @6) pb
           , unpackBytesN px (getUnpackedBytes @7) pb
           , unpackBytesN px (getUnpackedBytes @8) pb
           , unpackBytesN px (getUnpackedBytes @9) pb
           , unpackBytesN px (getUnpackedBytes @10) pb
           , unpackBytesN px (getUnpackedBytes @11) pb
           , unpackBytesN px (getUnpackedBytes @12) pb
           , unpackBytesN px (getUnpackedBytes @13) pb
           , unpackBytesN px (getUnpackedBytes @14) pb
           , unpackBytesN px (getUnpackedBytes @15) pb
           , unpackBytesN px (getUnpackedBytes @16) pb
           , unpackBytesN px (getUnpackedBytes @17) pb
           , unpackBytesN px (getUnpackedBytes @18) pb
           , unpackBytesN px (getUnpackedBytes @19) pb
           , unpackBytesN px (getUnpackedBytes @20) pb
           , unpackBytesN px (getUnpackedBytes @21) pb
           , unpackBytesN px (getUnpackedBytes @22) pb
           , unpackBytesN px (getUnpackedBytes @23) pb
           , unpackBytesN px (getUnpackedBytes @24) pb
           , unpackBytesN px (getUnpackedBytes @25) pb
           , unpackBytesN px (getUnpackedBytes @26) pb
           , unpackBytesN px (getUnpackedBytes @27) pb
           , unpackBytesN px unpackBytes28 pb
           , unpackBytesN px (getUnpackedBytes @29) pb
           , unpackBytesN px (getUnpackedBytes @30) pb
           , unpackBytesN px (getUnpackedBytes @31) pb
           , unpackBytesN px unpackBytes32 pb
           ]
{-# INLINE[1] unpackBytes #-}

{-# RULES
"packBytes28" packBytes = packBytes28
"packBytes32" packBytes = packBytes32
"unpackBytes28" unpackBytes = unpackBytes28
"unpackBytes32" unpackBytes = unpackBytes32
  #-}


applyOrdPackedBytes ::
     forall n b. KnownNat n
  => (forall a. Ord a => a -> a -> b)
  -> PackedBytes n
  -> PackedBytes n
  -> b
applyOrdPackedBytes f x1 x2 =
  let px = Proxy :: Proxy n
   in case sameNat px (Proxy :: Proxy 28) of
        Just Refl -> f x1 x2
        Nothing -> case sameNat px (Proxy :: Proxy 32) of
          Just Refl -> f x1 x2
          Nothing   -> f (unpackBytes x1) (unpackBytes x2)
{-# INLINE applyOrdPackedBytes #-}
