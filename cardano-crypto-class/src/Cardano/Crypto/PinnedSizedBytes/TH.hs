{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskellQuotes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Crypto.PinnedSizedBytes.TH (
  psbHex
  ) where

import Text.Read (readMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Kind as Haskell
import Cardano.Crypto.PinnedSizedBytes.Internal (
  PinnedSizedBytes (PSB)
  )
import Data.Primitive.ByteArray (
  emptyByteArray, 
  writeByteArray,
  ByteArray,
  unsafeFreezeByteArray,
  newPinnedByteArray,
  )
import Control.Monad.ST (runST)
import Language.Haskell.TH.Quote (
  QuasiQuoter (
    QuasiQuoter, 
    quoteExp,
    quotePat,
    quoteType,
    quoteDec
    )
  )
import Language.Haskell.TH (
  Q, 
  Exp (AppTypeE, AppE, ConE, VarE), 
  Type (LitT),
  TyLit (NumTyLit),
  )
import Control.Monad.Trans.State.Strict (runStateT, StateT, get, modify)
import Data.Word (Word8)
import Data.Functor (($>))
import Data.Foldable (traverse_)

-- | Constructs (and verifies) a compile-time-known hex string as a
-- 'PinnedSizedBytes', as well as computing its length at the type level.
--
-- The syntax accepted by this quasiquoter only works in an expression context.
-- A valid input consists of the following:
--
-- * An optional @0x@;
-- * An even number of /hexits/, which are either digits (@0@ through @9@) or
-- letters (@a@ through @f@ or @A@ through @F@).
--
-- It is acceptable to mix upper-case and lower-case letters in the same input.
-- We allow any amount of leading or trailing whitespace, but no internal
-- whitespace.
--
-- This syntax produces a 'PinnedSizedBytes', of length equal to half the number
-- of hexits, where the hexit pairs define a byte at that position. 
--
-- = Examples
--
-- * @['psbHex'| 0x |]@ produces a 'PinnedByteString' of length 0. This can also
-- be written @['psbHex'|  |]@ or @['psbHex'|                |]@.
-- * @['psbHex' | 0xafbc |]@ produces a 'PinnedByteString of length 2; the 
-- first byte is @0xaf@, and the second is @0xbc@. This can also be written
-- @['psbHex'| afbc |]@, @['psbHex'| AfBc |]@ or @['psbHex'|     Afbc    |]@.
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
    Nothing -> go asStrippedText
    Just rest -> case Text.uncons rest of 
      Nothing -> pure $ AppE (AppTypeE (ConE 'PSB) (natLiteral 0)) . VarE $ 'emptyByteArray
      _ -> go rest
  where
    go :: Text -> Q Exp
    go hexits = do
      (bytes, len) <- runStateT (traverse decodeAndCount . Text.chunksOf 2 $ hexits) 0
      AppE (AppTypeE (ConE 'PSB) (natLiteral len)) <$> [| mkPSB bytes len |]

{-# NOINLINE mkPSB #-}
mkPSB :: [Word8] -> Int -> ByteArray
mkPSB bytes len = runST $ do
  mba <- newPinnedByteArray len
  traverse_ (uncurry (writeByteArray @Word8 mba)) . zip [0 .. ] $ bytes
  unsafeFreezeByteArray mba

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
