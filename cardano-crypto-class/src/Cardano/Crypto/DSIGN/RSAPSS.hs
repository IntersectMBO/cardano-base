{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- | RSAPSS digital signatures.
module Cardano.Crypto.DSIGN.RSAPSS
  ( RSAPSSDSIGN
  )
where

import Cardano.Binary (FromCBOR (..), ToCBOR (..), serialize)
import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Hash
import Cardano.Prelude (NoUnexpectedThunks, UseIsNormalForm(..))
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PSS
import Data.ByteString.Lazy (toStrict)
import GHC.Generics (Generic)

data RSAPSSDSIGN

e :: Integer
e = 0x10001

byteSize :: Int
byteSize = 100

instance DSIGNAlgorithm RSAPSSDSIGN where

    type Signable RSAPSSDSIGN = ToCBOR

    newtype VerKeyDSIGN RSAPSSDSIGN = VerKeyRSAPSSDSIGN PublicKey
        deriving (Show, Eq, Generic)
        deriving NoUnexpectedThunks via UseIsNormalForm PublicKey

    newtype SignKeyDSIGN RSAPSSDSIGN = SignKeyRSAPSSDSIGN PrivateKey
        deriving (Show, Eq, Generic)
        deriving NoUnexpectedThunks via UseIsNormalForm PrivateKey

    newtype SigDSIGN RSAPSSDSIGN = SigRSAPSSDSIGN ByteString
        deriving (Show, Eq, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

    encodeVerKeyDSIGN = toCBOR
    encodeSignKeyDSIGN = toCBOR
    encodeSigDSIGN = toCBOR

    decodeVerKeyDSIGN = fromCBOR
    decodeSignKeyDSIGN = fromCBOR
    decodeSigDSIGN = fromCBOR

    genKeyDSIGN = do
        (_, sk) <- generate byteSize e
        return $ SignKeyRSAPSSDSIGN sk

    deriveVerKeyDSIGN (SignKeyRSAPSSDSIGN sk) = VerKeyRSAPSSDSIGN $ private_pub sk

    signDSIGN () a (SignKeyRSAPSSDSIGN sk) = do
        esig <- signSafer defaultPSSParamsSHA1 sk (toStrict $ serialize a)
        case esig of
            Left err  -> error $ "signDSIGN: " ++ show err
            Right sig -> return $ SigRSAPSSDSIGN sig

    verifyDSIGN () (VerKeyRSAPSSDSIGN vk) a (SigRSAPSSDSIGN sig) =
        if verify defaultPSSParamsSHA1 vk (toStrict $ serialize a) sig
          then Right ()
          else Left "Verification failed"

instance ToCBOR (VerKeyDSIGN RSAPSSDSIGN) where
  toCBOR (VerKeyRSAPSSDSIGN vk) = toCBOR $ vkToTuple vk

instance FromCBOR (VerKeyDSIGN RSAPSSDSIGN) where
  fromCBOR = VerKeyRSAPSSDSIGN . vkFromTuple <$> fromCBOR

instance ToCBOR (SignKeyDSIGN RSAPSSDSIGN) where
  toCBOR (SignKeyRSAPSSDSIGN sk) = toCBOR $ skToTuple sk

instance FromCBOR (SignKeyDSIGN RSAPSSDSIGN) where
  fromCBOR = SignKeyRSAPSSDSIGN . skFromTuple <$> fromCBOR

vkToTuple :: PublicKey -> (Int, Integer, Integer)
vkToTuple vk = (public_size vk, public_n vk, public_e vk)

vkFromTuple :: (Int, Integer, Integer) -> PublicKey
vkFromTuple (size, n, e') = PublicKey size n e'

skToTuple
  :: PrivateKey
  -> ( (Int, Integer, Integer)
     , Integer
     , Integer
     , Integer
     , Integer
     , Integer
     , Integer
     )
skToTuple sk =
  ( vkToTuple (private_pub sk)
  , private_d sk
  , private_p sk
  , private_q sk
  , private_dP sk
  , private_dQ sk
  , private_qinv sk
  )

skFromTuple
  :: ( (Int, Integer, Integer)
     , Integer
     , Integer
     , Integer
     , Integer
     , Integer
     , Integer
     )
  -> PrivateKey
skFromTuple (vk, d, p, q, dp, dq, qinv) = PrivateKey (vkFromTuple vk) d p q dp dq qinv
