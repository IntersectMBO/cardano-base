{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskellQuotes #-}

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
import Data.Primitive.ByteArray (emptyByteArray, byteArrayFromList)
import Language.Haskell.TH.Quote (
  QuasiQuoter (
    QuasiQuoter, 
    quoteExp,
    quotePat,
    quoteType,
    quoteDec
    )
  )
import Language.Haskell.TH.Syntax (lift)
import Language.Haskell.TH (
  Q, 
  Exp (AppTypeE, AppE, ConE, VarE), 
  Type (LitT),
  TyLit (NumTyLit),
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
        then pure $ 
          AppTypeE (AppE (ConE 'PSB) (VarE 'emptyByteArray)) . 
          LitT . 
          NumTyLit $ 0
        else fail "Extra data after _."
      _ -> do
        (bytes, len) <- runStateT (traverse decodeAndCount . Text.chunksOf 2 $ rest) 0
        baExp <- AppE (VarE 'byteArrayFromList) <$> lift bytes
        pure $ 
          AppTypeE (AppE (ConE 'PSB) baExp) . 
          LitT . 
          NumTyLit $ len

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
