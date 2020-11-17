{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE LambdaCase #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.ForgetMock
  ( ForgetMockKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)

import Cardano.Prelude (lift, MonadIO, liftIO, ReaderT (..), ask)

import Cardano.Crypto.KES.Class
import Debug.Trace (traceEvent)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe

-- | A wrapper for a KES implementation that adds logging functionality, for
-- the purpose of verifying that invocations of 'genKeyKES' and
-- 'forgetSignKeyKES' pair up properly in a given host application.
--
-- The wrapped KES behaves exactly like its unwrapped payload, except that
-- invocations of 'genKeyKES', 'updateKES' and 'forgetSignKeyKES' are logged
-- to the eventlog (via 'traceEvent'), prefixed with @"PRE: "@, @"UPD: "@,
-- or @"DEL: "@, respectively.
data ForgetMockKES k

type Logger = String -> IO ()

instance
  ( KESAlgorithm k
  , MonadIO (GenerateKES k)
  )
  => KESAlgorithm (ForgetMockKES k) where
    type SeedSizeKES (ForgetMockKES k) = SeedSizeKES k
    type Signable (ForgetMockKES k) = Signable k

    newtype VerKeyKES (ForgetMockKES k) = VerKeyForgetMockKES (VerKeyKES k)
      deriving (Generic)
    newtype SignKeyKES (ForgetMockKES k) = SignKeyForgetMockKES (SignKeyKES k)
      deriving (Generic)
    newtype SigKES (ForgetMockKES k) = SigForgetMockKES (SigKES k)
      deriving (Generic)

    type ContextKES (ForgetMockKES k) = ContextKES k

    type GenerateKES (ForgetMockKES k) = ReaderT Logger (GenerateKES k)

    genKeyKES seed = do
      sk <- lift $ genKeyKES seed
      (writeLog :: Logger) <- ask
      let a = unsafePerformIO $ writeLog ("GEN: " ++ show sk)
      a `seq` return (SignKeyForgetMockKES sk)

    forgetSignKeyKES (SignKeyForgetMockKES sk) = do
      writeLog <- ask
      liftIO $ writeLog ("DEL: " ++ show sk)
      return ()

    algorithmNameKES _ = algorithmNameKES (Proxy @k)

    deriveVerKeyKES (SignKeyForgetMockKES k) = VerKeyForgetMockKES $ deriveVerKeyKES k

    signKES ctx p msg (SignKeyForgetMockKES sk) =
        SigForgetMockKES $ signKES ctx p msg sk

    verifyKES ctx (VerKeyForgetMockKES vk) p msg (SigForgetMockKES sig) =
        verifyKES ctx vk p msg sig

    updateKES ctx (SignKeyForgetMockKES sk) p = do
      writeLog <- ask
      lift (updateKES ctx sk p) >>= \case
        Just sk' -> do
          let a = unsafePerformIO $ writeLog ("UPD: " ++ show sk')
          a `seq` (return $ Just $ SignKeyForgetMockKES sk')
        Nothing -> do
          let a = unsafePerformIO $ writeLog ("UPD: ---")
          a `seq` return Nothing

    totalPeriodsKES _ = totalPeriodsKES (Proxy @k)

    sizeVerKeyKES _ = sizeVerKeyKES (Proxy @k)
    sizeSignKeyKES _ = sizeSignKeyKES (Proxy @k)
    sizeSigKES _ = sizeSigKES (Proxy @k)

    rawSerialiseVerKeyKES (VerKeyForgetMockKES k) = rawSerialiseVerKeyKES k
    rawSerialiseSignKeyKES (SignKeyForgetMockKES k) = rawSerialiseSignKeyKES k
    rawSerialiseSigKES (SigForgetMockKES k) = rawSerialiseSigKES k

    rawDeserialiseVerKeyKES = fmap VerKeyForgetMockKES . rawDeserialiseVerKeyKES
    rawDeserialiseSignKeyKES = fmap SignKeyForgetMockKES . rawDeserialiseSignKeyKES
    rawDeserialiseSigKES = fmap SigForgetMockKES . rawDeserialiseSigKES



deriving instance Show (VerKeyKES k) => Show (VerKeyKES (ForgetMockKES k))
deriving instance Eq (VerKeyKES k) => Eq (VerKeyKES (ForgetMockKES k))
deriving instance Ord (VerKeyKES k) => Ord (VerKeyKES (ForgetMockKES k))
deriving instance NoThunks (VerKeyKES k) => NoThunks (VerKeyKES (ForgetMockKES k))

deriving instance Show (SignKeyKES k) => Show (SignKeyKES (ForgetMockKES k))
deriving instance Eq (SignKeyKES k) => Eq (SignKeyKES (ForgetMockKES k))
deriving instance Ord (SignKeyKES k) => Ord (SignKeyKES (ForgetMockKES k))
deriving instance NoThunks (SignKeyKES k) => NoThunks (SignKeyKES (ForgetMockKES k))

deriving instance Show (SigKES k) => Show (SigKES (ForgetMockKES k))
deriving instance Eq (SigKES k) => Eq (SigKES (ForgetMockKES k))
deriving instance Ord (SigKES k) => Ord (SigKES (ForgetMockKES k))
deriving instance NoThunks (SigKES k) => NoThunks (SigKES (ForgetMockKES k))
