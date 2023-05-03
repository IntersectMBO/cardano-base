{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.ForgetMock
  ( ForgetMockKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  , ForgetMockEvent (..)
  , isGEN
  , isUPD
  , isDEL
  )
where

import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)

import Cardano.Crypto.KES.Class
import NoThunks.Class (NoThunks (..), allNoThunks)
import System.Random (randomRIO)
import Control.Tracer
import Test.Crypto.AllocLog
import Control.Monad.Reader (ask)
import Control.Monad ((<$!>))

-- | A wrapper for a KES implementation that adds logging functionality, for
-- the purpose of verifying that invocations of 'genKeyKES' and
-- 'forgetSignKeyKES' pair up properly in a given host application.
--
-- The wrapped KES behaves exactly like its unwrapped payload, except that
-- invocations of 'genKeyKES', 'updateKES' and 'forgetSignKeyKES' are logged
-- as 'GenericEvent' 'ForgetMockEvent' values. (We use 'GenericEvent' in order
-- to use the generic 'MonadMLock' instance of 'LogT'; otherwise we would
-- have to provide a boilerplate instance here).
data ForgetMockKES k

data ForgetMockEvent
  = GEN Word
  | UPD Word Word
  | NOUPD
  | DEL Word
  deriving (Ord, Eq, Show)

isGEN :: ForgetMockEvent -> Bool
isGEN GEN {} = True
isGEN _ = False

isUPD :: ForgetMockEvent -> Bool
isUPD UPD {} = True
isUPD _ = False

isDEL :: ForgetMockEvent -> Bool
isDEL DEL {} = True
isDEL _ = False

instance KESAlgorithm k => KESAlgorithm (ForgetMockKES k) where
    type SeedSizeKES (ForgetMockKES k) = SeedSizeKES k
    type Signable (ForgetMockKES k) = Signable k

    newtype VerKeyKES (ForgetMockKES k) = VerKeyForgetMockKES (VerKeyKES k)
      deriving (Generic)
    newtype SigKES (ForgetMockKES k) = SigForgetMockKES (SigKES k)
      deriving (Generic)

    type ContextKES (ForgetMockKES k) = ContextKES k

    algorithmNameKES _ = algorithmNameKES (Proxy @k)

    verifyKES ctx (VerKeyForgetMockKES vk) p msg (SigForgetMockKES sig) =
        verifyKES ctx vk p msg sig

    totalPeriodsKES _ = totalPeriodsKES (Proxy @k)

    type SizeVerKeyKES (ForgetMockKES k) = SizeVerKeyKES k
    type SizeSignKeyKES (ForgetMockKES k) = SizeSignKeyKES k
    type SizeSigKES (ForgetMockKES k) = SizeSigKES k

    rawSerialiseVerKeyKES (VerKeyForgetMockKES k) = rawSerialiseVerKeyKES k
    rawSerialiseSigKES (SigForgetMockKES k) = rawSerialiseSigKES k

    rawDeserialiseVerKeyKES = fmap VerKeyForgetMockKES . rawDeserialiseVerKeyKES
    rawDeserialiseSigKES = fmap SigForgetMockKES . rawDeserialiseSigKES


instance KESSignAlgorithm k => KESSignAlgorithm (ForgetMockKES k) where
    data SignKeyKES (ForgetMockKES k) = SignKeyForgetMockKES !Word !(SignKeyKES k)

    genKeyKESWith allocator seed = do
      sk <- genKeyKESWith allocator seed
      nonce <- randomRIO (10000000, 99999999)
      tracer <- ask
      traceWith tracer (GenericEvent $ GEN nonce)
      return $! SignKeyForgetMockKES nonce sk

    forgetSignKeyKES (SignKeyForgetMockKES nonce sk) = do
      tracer <- ask
      traceWith tracer (GenericEvent $ DEL nonce)
      forgetSignKeyKES sk

    deriveVerKeyKES (SignKeyForgetMockKES _ k) =
      VerKeyForgetMockKES <$!> deriveVerKeyKES k

    signKES ctx p msg (SignKeyForgetMockKES _ sk) =
        SigForgetMockKES <$!> signKES ctx p msg sk

    updateKESWith allocator ctx (SignKeyForgetMockKES nonce sk) p = do
      tracer <- ask
      nonce' <- randomRIO (10000000, 99999999)
      updateKESWith allocator ctx sk p >>= \case
        Just sk' -> do
          traceWith tracer (GenericEvent $ UPD nonce nonce')
          return $! Just $! SignKeyForgetMockKES nonce' sk'
        Nothing -> do
          traceWith tracer (GenericEvent NOUPD)
          return Nothing

instance UnsoundKESSignAlgorithm k => UnsoundKESSignAlgorithm (ForgetMockKES k) where

    rawSerialiseSignKeyKES (SignKeyForgetMockKES _ k) = rawSerialiseSignKeyKES k

    rawDeserialiseSignKeyKESWith allocator bs = do
      msk <- rawDeserialiseSignKeyKESWith allocator bs
      nonce :: Word <- randomRIO (10000000, 99999999)
      return $ fmap (SignKeyForgetMockKES nonce) msk


deriving instance Show (VerKeyKES k) => Show (VerKeyKES (ForgetMockKES k))
deriving instance Eq (VerKeyKES k) => Eq (VerKeyKES (ForgetMockKES k))
deriving instance Ord (VerKeyKES k) => Ord (VerKeyKES (ForgetMockKES k))
deriving instance NoThunks (VerKeyKES k) => NoThunks (VerKeyKES (ForgetMockKES k))

deriving instance Eq (SignKeyKES k) => Eq (SignKeyKES (ForgetMockKES k))

instance NoThunks (SignKeyKES k) => NoThunks (SignKeyKES (ForgetMockKES k)) where
  showTypeOf _ = "SignKeyKES (ForgetMockKES k)"
  wNoThunks ctx (SignKeyForgetMockKES t k) =
    allNoThunks
      [ noThunks ctx t
      , noThunks ctx k
      ]

deriving instance Show (SigKES k) => Show (SigKES (ForgetMockKES k))
deriving instance Eq (SigKES k) => Eq (SigKES (ForgetMockKES k))
deriving instance Ord (SigKES k) => Ord (SigKES (ForgetMockKES k))
deriving instance NoThunks (SigKES k) => NoThunks (SigKES (ForgetMockKES k))
