{-# OPTIONS_GHC -fno-warn-orphans  -Wno-unused-binds  -Wno-unused-imports #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications   #-}  --  :set -XTypeApplications  to set inside GHCi
{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE TypeFamilies       #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia        #-}
{-# LANGUAGE ScopedTypeVariables #-}


module Work(go,foo) where

import System.IO.Unsafe(unsafePerformIO)
import qualified Data.ByteString as BS
import Data.ByteArray(ScrubbedBytes)

import GHC.TypeNats (Nat, KnownNat, natVal)
import Data.Proxy (Proxy(..))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)





import KES(PublicKey
   (PublicKey),SecretKey(SecretKey),Signature(Signature),Seed(),
    createSeed,generate,verify,sign,update,t)
import Cardano.Crypto.KES.Class
import Cardano.Prelude(NoUnexpectedThunks(),UseIsNormalForm(..))

deriving instance Eq Signature
deriving instance Eq PublicKey
deriving instance Eq SecretKey

deriving instance Generic Signature
deriving instance Generic PublicKey
deriving instance Generic SecretKey

deriving instance NoUnexpectedThunks Signature
deriving instance NoUnexpectedThunks PublicKey
deriving instance NoUnexpectedThunks SecretKey
deriving via UseIsNormalForm ScrubbedBytes instance NoUnexpectedThunks ScrubbedBytes

foo ::  KESAlgorithm v => proxy v -> String
foo x =  algorithmNameKES x

{-# NOINLINE generate2 #-}
generate2 :: Seed -> (PublicKey, SecretKey)
generate2 seed = unsafePerformIO (generate seed)

{-# NOINLINE verify2 #-}
verify2 :: PublicKey -> BS.ByteString -> Signature -> Bool
verify2 publickey bytes sig =  unsafePerformIO (verify publickey bytes sig)

{-# NOINLINE sign2 #-}
sign2 :: SecretKey -> BS.ByteString -> Signature
sign2 secretkey bytes = unsafePerformIO(sign secretkey bytes)

go :: IO Bool
go = do
  seed <- createSeed
  putStrLn "> "
  bytes <- BS.getLine
  let (public,secret) = generate2 seed
      sig = sign2 secret bytes
  update secret
  let word = t secret
  return(verify2 public bytes sig)


-- ====================================================================================

-- This type is used as the name of KESAlgorithm instance. The index `t` stands for the the number of evolutions
-- This Natural numer type index, exposes in the name of the instance how large it is.

data RustKES (t :: Nat)


instance KnownNat t => KESAlgorithm (RustKES t) where

    newtype VerKeyKES (RustKES t) = Verify PublicKey
        deriving stock   (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    data SignKeyKES (RustKES t) = Sign SecretKey
        deriving stock    (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    data SigKES (RustKES t) = Sig Signature
        deriving stock    (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    totalPeriodsKES _ = fromIntegral (natVal (Proxy @ t))               -- requires ScopedTypeVariables
    algorithmNameKES proxy = "Rust_" ++ show (totalPeriodsKES proxy)

                                     -- These realy should not be in KES.Internal, so we can see them here
    sizeVerKeyKES  _ = 32            -- See KES.Internal   pattern PUBLIC_KEY_SIZE = 32
    sizeSignKeyKES _ = 1220          -- See KES.Internal   pattern SECRET_KEY_SIZE = 1220
    sizeSigKES     _ = 484           -- See KES.Internal   pattern SIGNATURE_SIZE = 484
    seedSizeKES    _ = 32            -- See KES.Internal   pattern SEED_SIZE = 32

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () _index _a (Sign key) =
        -- assert (index == t') $
        Sig (sign2 key {- _a -} undefined) -- a:: Signable t => t,  Not ByteString

    deriveVerKeyKES = undefined
    verifyKES  = undefined
    updateKES = undefined
    genKeyKES = undefined

    rawSerialiseVerKeyKES = undefined
    rawSerialiseSignKeyKES = undefined
    rawSerialiseSigKES = undefined
    rawDeserialiseVerKeyKES = undefined
    rawDeserialiseSignKeyKES = undefined
    rawDeserialiseSigKES = undefined
