{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}

module Test.Crypto.Vector.SerializationUtils (
  unHex,
  unsafeUnHex,
  SignatureResult,
  HexStringInCBOR (..),
  sKeyParser,
  vKeyParser,
  sigParser,
  dropBytes,
  hexByteStringLength,
)
where

import Cardano.Binary (FromCBOR, serialize', unsafeDeserialize')
import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (SigDSIGN, SignKeyDSIGN, VerKeyDSIGN),
 )
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as BS8
import Data.String (IsString (fromString))
import Prelude hiding (drop)

-- Wrapper for serialized CBOR ByteString parsed from hex string
newtype HexStringInCBOR = HexCBOR ByteString

instance IsString HexStringInCBOR where
  fromString s =
    let bs = unsafeUnHex $ BS8.pack s
        cborBs = serialize' bs
     in HexCBOR cborBs

instance Show HexStringInCBOR where
  show (HexCBOR bs) = BS8.unpack $ BS16.encode bs

-- Drop from actual bytestring without cbor then recalculate
dropBytes :: Int -> HexStringInCBOR -> HexStringInCBOR
dropBytes n (HexCBOR bs) = HexCBOR $ serialize' $ BS.drop n (unsafeDeserialize' bs)

hexByteStringLength :: HexStringInCBOR -> Integer
hexByteStringLength (HexCBOR bs) = toInteger $ BS.length $ unsafeDeserialize' bs

unHex :: ByteString -> Either String ByteString
unHex = BS16.decode

unsafeUnHex :: ByteString -> ByteString
unsafeUnHex hexBs = case unHex hexBs of
  Left err -> error $ "Couldn't unHex the Hex string. Incorrect format: " ++ err
  Right bytes' -> bytes'

type SignatureResult = (Either String ())

sKeyParser :: forall d. FromCBOR (SignKeyDSIGN d) => HexStringInCBOR -> SignKeyDSIGN d
sKeyParser (HexCBOR bs) = unsafeDeserialize' bs

vKeyParser :: forall d. FromCBOR (VerKeyDSIGN d) => HexStringInCBOR -> VerKeyDSIGN d
vKeyParser (HexCBOR bs) = unsafeDeserialize' bs

sigParser :: forall d. FromCBOR (SigDSIGN d) => HexStringInCBOR -> SigDSIGN d
sigParser (HexCBOR bs) = unsafeDeserialize' bs
