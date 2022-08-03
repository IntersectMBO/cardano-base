{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskellQuotes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE BangPatterns #-}
-- Until we can upgrade primitive, we need this for an orphan Lift
-- This is necessary to avoid various awful grime from identical literals ending
-- up having identical addresses, which breaks referential transparency very
-- hard.
{-# OPTIONS_GHC -Wno-orphans #-}

module Cardano.Crypto.PinnedSizedBytes.TH (
  psbHex
  ) where

import Control.Monad.Primitive (PrimMonad (PrimState), primitive_)
import Data.Primitive.Types (Prim (sizeOf#))
import System.IO.Unsafe (unsafePerformIO, unsafeDupablePerformIO)
import GHC.Exts (
  toList, 
  Addr#,
  inline,
  Ptr (Ptr), 
  Int (I#), 
  copyAddrToByteArray#,
  (*#),
  )
import Text.Read (readMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Kind as Haskell
import Cardano.Crypto.PinnedSizedBytes.Internal (
  PinnedSizedBytes (PSB)
  )
import Data.Primitive.ByteArray (
  emptyByteArray, 
  byteArrayFromListN, 
  ByteArray,
  sizeofByteArray,
  MutableByteArray (MutableByteArray),
  newPinnedByteArray,
  unsafeFreezeByteArray,
  )
import Language.Haskell.TH.Quote (
  QuasiQuoter (
    QuasiQuoter, 
    quoteExp,
    quotePat,
    quoteType,
    quoteDec
    )
  )
import Language.Haskell.TH.Syntax (Lift (lift, liftTyped), unsafeTExpCoerce)
import Language.Haskell.TH (
  Q, 
  Exp (AppTypeE, AppE, ConE, VarE), 
  Type (LitT),
  TyLit (NumTyLit),
  appE, litE, stringPrimL,
  )
import Control.Monad.Trans.State.Strict (runStateT, StateT, get, modify)
import Data.Word (Word8)
import Data.Functor (($>))

-- | Constructs (and verifies) a compile-time-known hex string as a
-- 'PinnedSizedBytes', as well as computing its length at the type level.
--
-- The syntax accepted by this quasiquoter only works in an expression context.
-- A valid input consists of the literal sequence @0x@ followed by either:
--
-- * A single underscore (@_@); or
-- * A positive, even number of hexits (digits @0@ through @9@, or letters @a@
-- through @f@, lower-case only).
--
-- The first option produces the empty 'PinnedSizedBytes'; the second produces a
-- 'PinnedSizedBytes' of length equal to half the number of hexits, where the
-- hexit pairs define a byte at that position.
--
-- We allow any amount of leading or trailing whitespace, but no internal
-- whitespace is allowed.
--
-- = Examples
--
-- * @['psbHex'| 0x_ |]@ produces a 'PinnedByteString' of length 0.
-- * @['psbHex' | 0xafbc |]@ produces a 'PinnedByteString of length 2; the 
-- first byte is @0xaf@, and the second is @0xbc@.
--
-- = Note
--
-- To use this quasiquoter, @DataKinds@ and @TypeApplications@ need to be on.
psbHex :: QuasiQuoter
psbHex = QuasiQuoter {
  quoteExp = mkHexLiteral,
  quotePat = qqUseError "pattern",
  quoteType = qqUseError "type",
  quoteDec = qqUseError "declaration"
  }

-- Helpers

mkHexLiteral :: String -> Q Exp
mkHexLiteral input = do
  let asStrippedText = Text.strip . Text.pack $ input
  case Text.stripPrefix "0x" asStrippedText of 
    Nothing -> fail "No leading \"0x\" provided."
    Just rest -> case Text.uncons rest of 
      Nothing -> fail "No hexits or underscore after \"0x\"."
      Just ('_', rest') -> 
        if Text.null rest'
        -- This is a non-problematic overlap: we can't modify the empty byte
        -- array anyway.
        then pure $ AppE (AppTypeE (ConE 'PSB) (natLiteral 0)) . VarE $ 'emptyByteArray
        else fail "Extra data after _."
      _ -> do
        (bytes, len) <- runStateT (traverse decodeAndCount . Text.chunksOf 2 $ rest) 0
        let bytes' = byteArrayFromListN (fromIntegral len) bytes
        AppE (AppTypeE (ConE 'PSB) (natLiteral len)) <$> lift bytes'

natLiteral :: Integer -> Type
natLiteral = LitT . NumTyLit

decodeAndCount :: Text -> StateT Integer Q Word8
decodeAndCount chunk
  | Text.length chunk /= 2 = do
      len <- get
      fail $ "Odd number of hexits (" <> show (2 * len + 1) <> ")."
  | otherwise = case readMaybe ("0x" <> Text.unpack chunk) of 
      Nothing -> fail $ "Invalid hexit pair (" <> Text.unpack chunk <> ")."
      Just w8 -> modify (+ 1) $> w8

qqUseError :: forall (a :: Haskell.Type) . 
  String -> 
  String -> 
  Q a
qqUseError context _ = 
  fail $ "Cannot use psbHex in a " <> context <> " context."

-- Borrowed from primitive's latest version temporarily
--
-- Unlike that version, we _force_ a pin.

instance Lift ByteArray where
  lift ba = appE (if small 
                  then [| fromLitAddrSmall# len |] 
                  else [| fromLitAddrLarge# len |]) 
                 (litE . stringPrimL . toList $ ba)
    where
      small :: Bool
      small = len <= 2048
      len :: Int
      len = sizeofByteArray ba
  liftTyped = unsafeTExpCoerce . lift

{-# NOINLINE fromLitAddrSmall# #-}
fromLitAddrSmall# :: Int -> Addr# -> ByteArray
fromLitAddrSmall# len ptr = inline (fromLitAddr# True len ptr)

{-# NOINLINE fromLitAddrLarge# #-}
fromLitAddrLarge# :: Int -> Addr# -> ByteArray
fromLitAddrLarge# len ptr = inline (fromLitAddr# False len ptr)

fromLitAddr# :: Bool -> Int -> Addr# -> ByteArray
fromLitAddr# small !len !ptr = upIO $ do
  mba <- newPinnedByteArray len
  copyPtrToMutableByteArray mba 0 (Ptr ptr :: Ptr Word8) len
  unsafeFreezeByteArray mba
  where
    -- We don't care too much about duplication if the byte arrays are
    -- small. If they're large, we do. Since we don't allocate while
    -- we copy (we do it with a primop!), I don't believe the thunk
    -- deduplication mechanism can help us if two threads just happen
    -- to try to build the ByteArray at the same time.
    upIO
      | small = unsafeDupablePerformIO
      | otherwise = unsafePerformIO 

{-# INLINE copyPtrToMutableByteArray #-}
copyPtrToMutableByteArray :: forall m a. (PrimMonad m, Prim a)
  => MutableByteArray (PrimState m) -- ^ destination array
  -> Int   -- ^ destination offset given in elements of type @a@
  -> Ptr a -- ^ source pointer
  -> Int   -- ^ number of elements
  -> m ()
copyPtrToMutableByteArray (MutableByteArray ba#) (I# doff#) (Ptr addr#) (I# n#) =
  primitive_ (copyAddrToByteArray# addr# ba# (doff# *# siz#) (n# *# siz#))
  where
  siz# = sizeOf# (undefined :: a) 
