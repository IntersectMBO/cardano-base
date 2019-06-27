{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- | Ed448 digital signatures.
module Cardano.Crypto.DSIGN.Ed448
  ( Ed448DSIGN
  , SigDSIGN (..)
  )
where

import Cardano.Binary
  ( Decoder
  , Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , serializeEncoding'
  )
import Cardano.Crypto.DSIGN.Class
import Crypto.Error (CryptoFailable (..))
import Crypto.PubKey.Ed448
import Data.ByteArray (ByteArrayAccess, convert)
import Data.ByteString (ByteString)
import Data.Function (on)
import GHC.Generics (Generic)

data Ed448DSIGN

instance DSIGNAlgorithm Ed448DSIGN where

    newtype VerKeyDSIGN Ed448DSIGN = VerKeyEd448DSIGN PublicKey
        deriving (Show, Eq, Generic, ByteArrayAccess)

    newtype SignKeyDSIGN Ed448DSIGN = SignKeyEd448DSIGN SecretKey
        deriving (Show, Eq, Generic, ByteArrayAccess)

    newtype SigDSIGN Ed448DSIGN = SigEd448DSIGN Signature
        deriving (Show, Eq, Generic, ByteArrayAccess)

    encodeVerKeyDSIGN = toCBOR
    encodeSignKeyDSIGN = toCBOR
    encodeSigDSIGN = toCBOR

    decodeVerKeyDSIGN = fromCBOR
    decodeSignKeyDSIGN = fromCBOR
    decodeSigDSIGN = fromCBOR

    genKeyDSIGN = SignKeyEd448DSIGN <$> generateSecretKey

    deriveVerKeyDSIGN (SignKeyEd448DSIGN sk) = VerKeyEd448DSIGN $ toPublic sk

    signDSIGN toEnc a (SignKeyEd448DSIGN sk) = do
        let vk = toPublic sk
            bs = serializeEncoding' $ toEnc a
        return $ SigEd448DSIGN $ sign sk vk bs

    verifyDSIGN toEnc (VerKeyEd448DSIGN vk) a (SigEd448DSIGN sig) =
        if verify vk (serializeEncoding' $ toEnc a) sig
          then Right ()
          else Left "Verification failed"

instance Ord (VerKeyDSIGN Ed448DSIGN) where
  compare = compare `on` show

instance Ord (SignKeyDSIGN Ed448DSIGN) where
  compare = compare `on` show

instance Ord (SigDSIGN Ed448DSIGN) where
  compare = compare `on` show

instance ToCBOR (VerKeyDSIGN Ed448DSIGN) where
  toCBOR = encodeBA

instance FromCBOR (VerKeyDSIGN Ed448DSIGN) where
  fromCBOR = VerKeyEd448DSIGN <$> decodeBA publicKey

instance ToCBOR (SignKeyDSIGN Ed448DSIGN) where
  toCBOR = encodeBA

instance FromCBOR (SignKeyDSIGN Ed448DSIGN) where
  fromCBOR = SignKeyEd448DSIGN <$> decodeBA secretKey

instance ToCBOR (SigDSIGN Ed448DSIGN) where
  toCBOR = encodeBA

instance FromCBOR (SigDSIGN Ed448DSIGN) where
  fromCBOR = SigEd448DSIGN <$> decodeBA signature

encodeBA :: ByteArrayAccess ba => ba -> Encoding
encodeBA ba = let bs = convert ba :: ByteString in toCBOR bs

decodeBA :: forall a s. (ByteString -> CryptoFailable a) -> Decoder s a
decodeBA f = do
  bs <- fromCBOR :: Decoder s ByteString
  case f bs of
    CryptoPassed a -> return a
    CryptoFailed e -> fail $ "decodeBA: " ++ show e
