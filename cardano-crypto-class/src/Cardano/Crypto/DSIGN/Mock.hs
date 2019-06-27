{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementation of digital signatures.
module Cardano.Crypto.DSIGN.Mock
  ( MockDSIGN
  , SignKeyDSIGN (..)
  , VerKeyDSIGN (..)
  , SigDSIGN (..)
  , verKeyIdFromSigned
  , mockSign
  )
where

import Cardano.Binary
  ( Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , decodeListLen
  , encodeListLen
  )
import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Hash
import Cardano.Crypto.Util (nonNegIntR)
import GHC.Generics (Generic)
import GHC.Stack

data MockDSIGN

instance DSIGNAlgorithm MockDSIGN where

    newtype VerKeyDSIGN MockDSIGN = VerKeyMockDSIGN Int
        deriving (Show, Eq, Ord, Generic, Num, ToCBOR, FromCBOR)

    newtype SignKeyDSIGN MockDSIGN = SignKeyMockDSIGN Int
        deriving (Show, Eq, Ord, Generic, Num, ToCBOR, FromCBOR)

    data SigDSIGN MockDSIGN = SigMockDSIGN ByteString Int
        deriving (Show, Eq, Ord, Generic)

    encodeVerKeyDSIGN  = toCBOR
    encodeSignKeyDSIGN = toCBOR
    encodeSigDSIGN     = toCBOR

    decodeVerKeyDSIGN  = fromCBOR
    decodeSignKeyDSIGN = fromCBOR
    decodeSigDSIGN     = fromCBOR

    genKeyDSIGN = SignKeyMockDSIGN <$> nonNegIntR

    deriveVerKeyDSIGN (SignKeyMockDSIGN n) = VerKeyMockDSIGN n

    signDSIGN toEnc a sk = return $ mockSign toEnc a sk

    verifyDSIGN toEnc (VerKeyMockDSIGN n) a s =
      if s == mockSign toEnc a (SignKeyMockDSIGN n)
        then Right ()
        else Left $ show $ MockVerificationFailure {
                 vErrVerKey    = VerKeyMockDSIGN n
               , vErrSignature = s
               , vErrCallStack = prettyCallStack callStack
               }

-- | Debugging: provide information about the verification failure
--
-- We don't include the actual value here as that would require propagating a
-- 'Show' constraint.
data VerificationFailure
  = MockVerificationFailure
      { vErrVerKey :: VerKeyDSIGN MockDSIGN
      , vErrSignature :: SigDSIGN MockDSIGN
      , vErrCallStack :: String
      }
  deriving Show

mockSign :: (a -> Encoding) -> a -> SignKeyDSIGN MockDSIGN -> SigDSIGN MockDSIGN
mockSign toEnc a (SignKeyMockDSIGN n) = SigMockDSIGN (getHash $ hashWithSerialiser @ShortHash toEnc a) n

instance ToCBOR (SigDSIGN MockDSIGN) where
  toCBOR (SigMockDSIGN b i) = encodeListLen 2 <> toCBOR b <> toCBOR i

instance FromCBOR (SigDSIGN MockDSIGN) where
  fromCBOR = SigMockDSIGN <$ decodeListLen <*> fromCBOR <*> fromCBOR

-- | Get the id of the signer from a signature. Used for testing.
verKeyIdFromSigned :: SignedDSIGN MockDSIGN a -> Int
verKeyIdFromSigned (SignedDSIGN (SigMockDSIGN _ i)) = i
