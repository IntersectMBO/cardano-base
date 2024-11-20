{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Cardano.Binary.TreeDiff where

import qualified Cardano.Binary as Plain
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import Data.Bifunctor (bimap)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import Data.TreeDiff
import Formatting (build, formatToString)
import qualified Formatting.Buildable as B (Buildable (..))

showDecoderError :: B.Buildable e => e -> String
showDecoderError = formatToString build

showExpr :: ToExpr a => a -> String
showExpr = show . ansiWlExpr . toExpr

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
    case CBOR.deserialiseFromBytes CBOR.decodeTerm (BSL.fromStrict bytes) of
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
  , Lst (map toExpr $ showHexBytesGrouped bs)
  ]

-- | Show a ByteString as hex groups of 8bytes each. This is a slightly more
-- useful form for debugging, rather than bunch of escaped characters.
showHexBytesGrouped :: BS.ByteString -> [String]
showHexBytesGrouped bs
  | BS.null bs = []
  | otherwise =
      ("0x" <> BS8.unpack (BS.take 128 bs16))
        : [ "  " <> BS8.unpack (BS.take 128 $ BS.drop i bs16)
          | i <- [128, 256 .. BS.length bs16 - 1]
          ]
  where
    bs16 = Base16.encode bs
