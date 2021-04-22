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
{-# LANGUAGE MultiParamTypeClasses #-}

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
import NoThunks.Class (NoThunks)
import System.Random (randomRIO)

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
  )
  => KESAlgorithm (ForgetMockKES k) where
    type SeedSizeKES (ForgetMockKES k) = SeedSizeKES k
    type Signable (ForgetMockKES k) = Signable k

    newtype VerKeyKES (ForgetMockKES k) = VerKeyForgetMockKES (VerKeyKES k)
      deriving (Generic)
    data SignKeyKES (ForgetMockKES k) = SignKeyForgetMockKES !Word !(SignKeyKES k)
      deriving (Generic)
    newtype SigKES (ForgetMockKES k) = SigForgetMockKES (SigKES k)
      deriving (Generic)

    type ContextKES (ForgetMockKES k) = ContextKES k

    algorithmNameKES _ = algorithmNameKES (Proxy @k)

    verifyKES ctx (VerKeyForgetMockKES vk) p msg (SigForgetMockKES sig) =
        verifyKES ctx vk p msg sig

    totalPeriodsKES _ = totalPeriodsKES (Proxy @k)

    sizeVerKeyKES _ = sizeVerKeyKES (Proxy @k)
    sizeSignKeyKES _ = sizeSignKeyKES (Proxy @k)
    sizeSigKES _ = sizeSigKES (Proxy @k)

    rawSerialiseVerKeyKES (VerKeyForgetMockKES k) = rawSerialiseVerKeyKES k
    rawSerialiseSigKES (SigForgetMockKES k) = rawSerialiseSigKES k

    rawDeserialiseVerKeyKES = fmap VerKeyForgetMockKES . rawDeserialiseVerKeyKES
    rawDeserialiseSigKES = fmap SigForgetMockKES . rawDeserialiseSigKES


instance
  ( KESSignAlgorithm m k
  , MonadIO m
  )
  => KESSignAlgorithm (ReaderT Logger m) (ForgetMockKES k) where
    genKeyKES seed = do
      sk <- lift (genKeyKES seed)
      nonce <- liftIO $ randomRIO (10000000, 99999999)
      writeLog <- ask
      liftIO $ writeLog ("GEN: " ++ show nonce)
      return (SignKeyForgetMockKES nonce sk)

    forgetSignKeyKES (SignKeyForgetMockKES nonce _) = do
      writeLog <- ask
      liftIO $ writeLog ("DEL: " ++ show nonce)
      return ()

    deriveVerKeyKES (SignKeyForgetMockKES _ k) =
      VerKeyForgetMockKES <$> lift (deriveVerKeyKES k)

    signKES ctx p msg (SignKeyForgetMockKES _ sk) =
        SigForgetMockKES <$> lift (signKES ctx p msg sk)

    updateKES ctx (SignKeyForgetMockKES nonce sk) p = do
      writeLog <- ask
      nonce' <- liftIO $ randomRIO (10000000, 99999999)
      lift (updateKES ctx sk p) >>= \case
        Just sk' -> do
          liftIO $ writeLog ("UPD: " ++ show nonce ++ "->" ++ show nonce')
          return $ Just $ SignKeyForgetMockKES nonce' sk'
        Nothing -> do
          liftIO $ writeLog ("UPD: ---")
          return Nothing

    rawSerialiseSignKeyKES (SignKeyForgetMockKES _ k) = lift $ rawSerialiseSignKeyKES k

    rawDeserialiseSignKeyKES bs = do
      msk <- lift $ rawDeserialiseSignKeyKES bs
      nonce :: Word <- liftIO $ randomRIO (10000000, 99999999)
      return $ fmap (SignKeyForgetMockKES nonce) msk


deriving instance Show (VerKeyKES k) => Show (VerKeyKES (ForgetMockKES k))
deriving instance Eq (VerKeyKES k) => Eq (VerKeyKES (ForgetMockKES k))
deriving instance Ord (VerKeyKES k) => Ord (VerKeyKES (ForgetMockKES k))
deriving instance NoThunks (VerKeyKES k) => NoThunks (VerKeyKES (ForgetMockKES k))

deriving instance Eq (SignKeyKES k) => Eq (SignKeyKES (ForgetMockKES k))
instance NoThunks (SignKeyKES k) => NoThunks (SignKeyKES (ForgetMockKES k)) where

deriving instance Show (SigKES k) => Show (SigKES (ForgetMockKES k))
deriving instance Eq (SigKES k) => Eq (SigKES (ForgetMockKES k))
deriving instance Ord (SigKES k) => Ord (SigKES (ForgetMockKES k))
deriving instance NoThunks (SigKES k) => NoThunks (SigKES (ForgetMockKES k))
