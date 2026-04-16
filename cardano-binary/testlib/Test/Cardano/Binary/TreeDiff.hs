{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Binary.TreeDiff (
  -- * Diffing and pretty printing
  ToExpr (..),
  showExpr,
  ansiExpr,
  ansiExprString,
  diffExpr,
  diffExprString,
  diffExprCompact,
  diffExprCompactString,

  -- * Test expectations
  expectExprEqual,
  expectExprEqualWithMessage,
  requireExprEqualWithMessage,

  -- * Utility functions
  trimExprViaShow,
  tableDoc,
  hexByteStringExpr,
  showHexBytesGrouped,

  -- * Newtypes for debugging
  CBORBytes (..),
  HexBytes (..),

  -- * Re-exports from tree-diff
  Expr (App, Rec, Lst),
  defaultExprViaShow,
  ediff,
  ppEditExpr,

  -- * Re-exports from prettyprinter
  Pretty (..),
  Doc,
  AnsiStyle,
  ansiWlPretty,

  -- * Re-exports from ImpSpec
  ansiDocToString,
  assertColorFailure,
  callStackToLocation,
  srcLocToLocation,
) where

import qualified Cardano.Binary as Plain
import Codec.CBOR.Read (DeserialiseFailure (..), deserialiseFromBytes)
import qualified Codec.CBOR.Term as CBOR
import Data.Bifunctor (bimap)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import Data.TreeDiff
import GHC.Stack (HasCallStack)
import Prettyprinter (Doc)
import qualified Prettyprinter as Pretty
import Prettyprinter.Render.Terminal (AnsiStyle)
import Test.Hspec (Expectation)
import Test.ImpSpec (ansiDocToString)
import Test.ImpSpec.Expectations (assertColorFailure, callStackToLocation, srcLocToLocation)

-- =====================================================
-- Utility functions for TreeDiff and ToExpr

trimExprViaShow :: Show a => Int -> a -> Expr
trimExprViaShow _n x = defaultExprViaShow x

tableDoc :: Maybe (Doc AnsiStyle) -> [(String, Doc AnsiStyle)] -> Doc AnsiStyle
tableDoc mTitle rows =
  let w = foldr (max . length . fst) 0 rows
      t = case mTitle of
        Just title -> Pretty.hsep ["-----", title, "-----"] <> Pretty.line
        Nothing -> mempty
   in t <> Pretty.vsep [Pretty.fill (w + 1) (Pretty.pretty l) <> r | (l, r) <- rows]

-- =====================================================
-- Orphan ToExpr instances for cardano-binary types

instance ToExpr Plain.DecoderError where
  toExpr (Plain.DecoderErrorCanonicityViolation x) = App "DecoderErrorCanonicityViolation" [toExpr x]
  toExpr (Plain.DecoderErrorCustom x y) = App "DecoderErrorCustom" [toExpr x, toExpr y]
  toExpr (Plain.DecoderErrorDeserialiseFailure x y) = App "DecoderErrorDeserialiseFailure" [toExpr x, toExpr y]
  toExpr (Plain.DecoderErrorEmptyList x) = App "DecoderErrorEmptyList" [toExpr x]
  toExpr (Plain.DecoderErrorLeftover x y) = App "DecoderErrorLeftover" [toExpr x, toExpr y]
  toExpr (Plain.DecoderErrorSizeMismatch x y z) = App "DecoderErrorSizeMismatch" [toExpr x, toExpr y, toExpr z]
  toExpr (Plain.DecoderErrorUnknownTag x y) = App "DecoderErrorUnknownTag" [toExpr x, toExpr y]
  toExpr Plain.DecoderErrorVoid = App "DecoderErrorVoid" []

instance ToExpr DeserialiseFailure where
  toExpr (DeserialiseFailure x y) = App "DeserialiseFailure" [toExpr x, toExpr y]

-- =====================================================
-- Diffing and pretty showing

showExpr :: ToExpr a => a -> String
showExpr = show . prettyExpr . toExpr

ansiExpr :: ToExpr a => a -> Doc AnsiStyle
ansiExpr = ansiWlExpr . toExpr

ansiExprString :: ToExpr a => a -> String
ansiExprString = ansiDocToString . ansiExpr

diffExpr :: ToExpr a => a -> a -> Doc AnsiStyle
diffExpr x y = ansiWlEditExpr (ediff x y)

diffExprString :: ToExpr a => a -> a -> String
diffExprString x y = ansiDocToString $ diffExpr x y

diffExprCompact :: ToExpr a => a -> a -> Doc AnsiStyle
diffExprCompact x y = ansiWlEditExprCompact (ediff x y)

diffExprCompactString :: ToExpr a => a -> a -> String
diffExprCompactString x y = ansiDocToString $ diffExprCompact x y

-- =====================================================
-- Hex and CBOR byte debugging newtypes

-- | Wraps regular ByteString, but shows and diffs it as hex
newtype HexBytes = HexBytes {unHexBytes :: BS.ByteString}
  deriving (Eq)

instance Show HexBytes where
  show = showExpr

instance ToExpr HexBytes where
  toExpr = App "HexBytes" . hexByteStringExpr . unHexBytes

newtype CBORBytes = CBORBytes {unCBORBytes :: BS.ByteString}
  deriving (Eq)

instance Show CBORBytes where
  show = showExpr

instance ToExpr CBORBytes where
  toExpr (CBORBytes bytes) =
    case deserialiseFromBytes CBOR.decodeTerm (BSL.fromStrict bytes) of
      Left err ->
        App
          "CBORBytesError"
          [ toExpr @String "Error decoding CBOR, showing as Hex:"
          , toExpr (HexBytes bytes)
          , toExpr $ show err
          ]
      Right (leftOver, term)
        | BSL.null leftOver -> App "CBORBytes" [toExpr term]
        | otherwise ->
            case Plain.decodeFullDecoder "Term" CBOR.decodeTerm leftOver of
              Right leftOverTerm ->
                App
                  "CBORBytesError"
                  [ toExpr @String "Error decoding CBOR fully:"
                  , toExpr term
                  , toExpr @String "Leftover:"
                  , toExpr (leftOverTerm :: CBOR.Term)
                  ]
              Left err ->
                App
                  "CBORBytesError"
                  [ toExpr @String "Error decoding CBOR fully:"
                  , toExpr term
                  , toExpr @String "Leftover as Hex, due to inabilty to decode as Term:"
                  , toExpr $ HexBytes $ BSL.toStrict leftOver
                  , toExpr $ showDecoderError err
                  ]

instance ToExpr CBOR.Term where
  toExpr =
    \case
      CBOR.TInt i -> App "TInt" [toExpr i]
      CBOR.TInteger i -> App "TInteger" [toExpr i]
      CBOR.TBytes bs -> App "TBytes" $ hexByteStringExpr bs
      CBOR.TBytesI bs -> App "TBytesI" $ hexByteStringExpr $ BSL.toStrict bs
      CBOR.TString s -> App "TString" [toExpr s]
      CBOR.TStringI s -> App "TStringI" [toExpr s]
      CBOR.TList xs -> App "TList" [Lst (map toExpr xs)]
      CBOR.TListI xs -> App "TListI" [Lst (map toExpr xs)]
      CBOR.TMap xs -> App "TMap" [Lst (map (toExpr . bimap toExpr toExpr) xs)]
      CBOR.TMapI xs -> App "TMapI" [Lst (map (toExpr . bimap toExpr toExpr) xs)]
      CBOR.TTagged 24 (CBOR.TBytes x) -> App "CBOR-in-CBOR" [toExpr (CBORBytes x)]
      CBOR.TTagged t x -> App "TTagged" [toExpr t, toExpr x]
      CBOR.TBool x -> App "TBool" [toExpr x]
      CBOR.TNull -> App "TNull" []
      CBOR.TSimple x -> App "TSimple" [toExpr x]
      CBOR.THalf x -> App "THalf" [toExpr x]
      CBOR.TFloat x -> App "TFloat" [toExpr x]
      CBOR.TDouble x -> App "TDouble" [toExpr x]

hexByteStringExpr :: BS.ByteString -> [Expr]
hexByteStringExpr bs =
  [ toExpr (BS.length bs)
  , Lst (map toExpr $ showHexBytesGrouped 128 bs)
  ]

-- | Show a ByteString as hex groups of N characters each. This is a slightly more
-- useful form for debugging, rather than bunch of escaped characters.
showHexBytesGrouped :: Int -> BS.ByteString -> [String]
showHexBytesGrouped n bs
  | BS.null bs = []
  | otherwise =
      [ BS8.unpack (BS.take n $ BS.drop i bs16)
      | i <- [0, n .. BS.length bs16 - 1]
      ]
  where
    bs16 = Base16.encode bs

-- =====================================================
-- Test expectations

-- | Check that two values are equal and if they are not raise an exception with the
-- `ToExpr` diff
expectExprEqual :: (Eq a, ToExpr a) => a -> a -> Expectation
expectExprEqual = expectExprEqualWithMessage "Expected two values to be equal:"

expectExprEqualWithMessage :: (ToExpr a, Eq a, HasCallStack) => String -> a -> a -> Expectation
expectExprEqualWithMessage = requireExprEqualWithMessage (assertColorFailure . ansiDocToString) . Pretty.pretty

requireExprEqualWithMessage ::
  (ToExpr a, Eq a, Monoid b) => (Doc AnsiStyle -> b) -> Doc AnsiStyle -> a -> a -> b
requireExprEqualWithMessage fail_ message expected actual =
  if actual == expected then mempty else fail_ doc
  where
    doc = Pretty.width message (\w -> if w == 0 then diff else Pretty.line <> Pretty.indent 2 diff)
    diff = diffExpr actual expected

-- =====================================================
-- Internal helpers

showDecoderError :: Plain.DecoderError -> String
showDecoderError = show
