{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DerivingVia                #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE MagicHash                  #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE UnboxedTuples              #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
module Cardano.Crypto.PinnedSizedBytes
  (
    PinnedSizedBytes,
    -- * Initialization
    psbZero,
    -- * Conversions
    psbFromBytes,
    psbToBytes,
    psbFromByteString,
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

import Data.Kind (Type)
import Control.DeepSeq (NFData)
import Control.Monad.ST (runST)
import Control.Monad.Primitive  (primitive_, touch)
import Data.Primitive.ByteArray
          ( ByteArray (..)
          , MutableByteArray (..)
          , copyByteArrayToAddr
          , newPinnedByteArray
          , unsafeFreezeByteArray
          , foldrByteArray
          , byteArrayContents
          , writeByteArray
          , mutableByteArrayContents
          )
import Data.Proxy (Proxy (..))
import Data.String (IsString (..))
import Data.Word (Word8)
import Foreign.C.Types (CSize)
import Foreign.Ptr (FunPtr, castPtr)
import Foreign.Storable (Storable (..))
import GHC.TypeLits (KnownNat, Nat, natVal)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import Language.Haskell.TH.Syntax (Q, TExp(..))
import Numeric (showHex)
import System.IO.Unsafe (unsafeDupablePerformIO)

import GHC.Exts (Int (..))
import GHC.Prim (copyAddrToByteArray#)
import GHC.Ptr (Ptr (..))

import qualified Data.Primitive as Prim
import qualified Data.ByteString as BS

import Cardano.Foreign
import Cardano.Crypto.Libsodium.C (c_sodium_compare)
import Cardano.Crypto.Util (decodeHexString)

{- HLINT ignore "Reduce duplication" -}

-- $setup
-- >>> :set -XDataKinds -XTypeApplications -XOverloadedStrings
-- >>> import Cardano.Crypto.PinnedSizedBytes

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
  deriving NFData

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
        size = fromInteger (natVal (Proxy :: Proxy n))


-- | This instance is meant to be used with @TemplateHaskell@
--
-- >>> import Cardano.Crypto.PinnedSizedBytes
-- >>> :set -XTemplateHaskell
-- >>> :set -XOverloadedStrings
-- >>> :set -XDataKinds
-- >>> print ($$("0xdeadbeef") :: PinnedSizedBytes 4)
-- "deadbeef"
-- >>> print ($$("deadbeef") :: PinnedSizedBytes 4)
-- "deadbeef"
-- >>> let bsb = $$("0xdeadbeef") :: PinnedSizedBytes 5
-- <interactive>:9:14: error:
--     • <PinnedSizedBytes>: Expected in decoded form to be: 5 bytes, but got: 4
--     • In the Template Haskell splice $$("0xdeadbeef")
--       In the expression: $$("0xdeadbeef") :: PinnedSizedBytes 5
--       In an equation for ‘bsb’:
--           bsb = $$("0xdeadbeef") :: PinnedSizedBytes 5
-- >>> let bsb = $$("nogood") :: PinnedSizedBytes 5
-- <interactive>:11:14: error:
--     • <PinnedSizedBytes>: Malformed hex: invalid character at offset: 0
--     • In the Template Haskell splice $$("nogood")
--       In the expression: $$("nogood") :: PinnedSizedBytes 5
--       In an equation for ‘bsb’: bsb = $$("nogood") :: PinnedSizedBytes 5
instance KnownNat n => IsString (Q (TExp (PinnedSizedBytes n))) where
    fromString hexStr = do
      let n = fromInteger $ natVal (Proxy :: Proxy n)
      case decodeHexString hexStr n of
        Left err -> fail $ "<PinnedSizedBytes>: " ++ err
        Right _  -> [|| either error psbFromByteString (decodeHexString hexStr n) ||]


-- | See 'psbFromBytes'.
psbToBytes :: PinnedSizedBytes n -> [Word8]
psbToBytes (PSB ba) = foldrByteArray (:) [] ba

psbToByteString :: PinnedSizedBytes n -> BS.ByteString
psbToByteString = BS.pack . psbToBytes

-- | See @'IsString' ('PinnedSizedBytes' n)@ instance.
--
-- >>> psbToBytes . (id @(PinnedSizedBytes 4)) . psbFromBytes $ [1,2,3,4]
-- [1,2,3,4]
--
-- >>> psbToBytes . (id @(PinnedSizedBytes 4)) . psbFromBytes $ [1,2]
-- [0,0,1,2]
--
-- >>> psbToBytes . (id @(PinnedSizedBytes 4)) . psbFromBytes $ [1,2,3,4,5,6]
-- [3,4,5,6]
--
{-# DEPRECATED psbFromBytes "This is not referentially transparent" #-}
psbFromBytes :: forall n. KnownNat n => [Word8] -> PinnedSizedBytes n
psbFromBytes ws0 = PSB (pinnedByteArrayFromListN size ws)
  where
    size :: Int
    size = fromInteger (natVal (Proxy :: Proxy n))

    ws :: [Word8]
    ws = reverse
        $ take size
        $ (++ repeat 0)
        $ reverse ws0

-- | Convert a ByteString into PinnedSizedBytes. Input should contain the exact
-- number of bytes as expected by type level @n@ size, otherwise error.
psbFromByteString :: KnownNat n => BS.ByteString -> PinnedSizedBytes n
psbFromByteString bs =
  case psbFromByteStringCheck bs of
    Nothing -> error $ "psbFromByteString: Size mismatch, got: " ++ show (BS.length bs)
    Just psb -> psb

psbFromByteStringCheck :: forall n. KnownNat n => BS.ByteString -> Maybe (PinnedSizedBytes n)
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

{-# DEPRECATED psbZero "This is not referentially transparent" #-}
psbZero :: KnownNat n =>  PinnedSizedBytes n
psbZero = psbFromBytes []

instance KnownNat n => Storable (PinnedSizedBytes n) where
    sizeOf _          = fromInteger (natVal (Proxy :: Proxy n))
    alignment _       = alignment (undefined :: FunPtr (Int -> Int))

    peek (Ptr addr#) = do
        let size :: Int
            size = fromInteger (natVal (Proxy :: Proxy n))
        marr@(MutableByteArray marr#) <- newPinnedByteArray size
        primitive_ $ copyAddrToByteArray# addr# marr# 0# (case size of I# s -> s)
        arr <- unsafeFreezeByteArray marr
        return (PSB arr)

    poke p (PSB arr) = do
        let size :: Int
            size = fromInteger (natVal (Proxy :: Proxy n))
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

-------------------------------------------------------------------------------
-- derivative from primitive
-------------------------------------------------------------------------------

-- | Create a 'ByteArray' from a list of a known length. If the length
--   of the list does not match the given length, or if the length is zero,
--   then this throws an exception.
pinnedByteArrayFromListN :: forall a. Prim.Prim a => Int -> [a] -> ByteArray
pinnedByteArrayFromListN 0 _ =
    die "pinnedByteArrayFromListN" "list length zero"
pinnedByteArrayFromListN n ys = runST $ do
    marr <- newPinnedByteArray (n * Prim.sizeOf (head ys))
    let go !ix [] = if ix == n
          then return ()
          else die "pinnedByteArrayFromListN" "list length less than specified size"
        go !ix (x : xs) = if ix < n
          then do
            writeByteArray marr ix x
            go (ix + 1) xs
          else die "pinnedByteArrayFromListN" "list length greater than specified size"
    go 0 ys
    unsafeFreezeByteArray marr

die :: String -> String -> a
die fun problem = error $ "PinnedSizedBytes." ++ fun ++ ": " ++ problem

-- Wrapper that combines applying a function, then touching
runAndTouch ::
  forall (a :: Type) .
  ByteArray ->
  (Ptr Word8 -> IO a) ->
  IO a
runAndTouch ba f = do
  r <- f (byteArrayContents ba)
  r <$ touch ba
