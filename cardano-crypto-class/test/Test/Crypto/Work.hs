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


module Test.Crypto.Work(go) where

import System.IO.Unsafe(unsafePerformIO)
import qualified Data.ByteString as BS
import Data.ByteArray(ScrubbedBytes,convert,allocRet)


import GHC.TypeNats (Nat, KnownNat, natVal)
import Data.Proxy (Proxy(..))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)

import KES(PublicKey(PublicKey),
    SecretKey(SecretKey),Signature(Signature),Seed(Seed),
    createSeed,generate,verify,sign,update,t)
import Cardano.Crypto.KES.Class
import Cardano.Prelude(NoUnexpectedThunks(),UseIsNormalForm(..))
import Cardano.Binary(ToCBOR(),serialize')
import Cardano.Crypto.Seed(getSeedBytes)

-- =====================================================================
-- We are going to need some instances of the Rust flavor data

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

-- =====================================================================
-- A few versions that make pure functions from the Rust wrappers


{-# NOINLINE generate2 #-}
generate2 :: Seed -> (PublicKey, SecretKey)
generate2 seed = unsafePerformIO (generate seed)

-- Cardano's notion of a Seed (see  Cardano.Crypto.Seed) does not align with Rust's notion of a Seed
-- To convert we must make a ScrubbedBytes from a BS.ByteString

scrub:: BS.ByteString -> ScrubbedBytes
scrub bs = convert bs
seedToSeed xs = Seed(scrub (getSeedBytes xs))


{-# NOINLINE verify2 #-}
verify2 :: ToCBOR obj => PublicKey -> obj -> Signature -> Bool
verify2 publickey object sig =  unsafePerformIO (verify publickey (serialize' object) sig)

{-# NOINLINE sign2 #-}
sign2 :: ToCBOR a => SecretKey -> a -> Signature
sign2 secretkey bytes = unsafePerformIO(sign secretkey (serialize' bytes))


{-# NOINLINE update2 #-}
update2 :: SecretKey -> SecretKey
update2 secretkey = unsafePerformIO $ (
    (do update secretkey
        return secretkey  -- THIS IS WRONG, WE NEED TO MAKE A COPY OF THE UPDATED PTR
    ))

-- ====================================================================================

-- This type is used as the name of KESAlgorithm instance. The index `t` stands for the the number of evolutions
-- This Natural number type index, exposes in the name of the instance how large it is.

data RustKES (t :: Nat)


instance KnownNat t => KESAlgorithm (RustKES t) where

    newtype VerKeyKES (RustKES t) = Verify PublicKey
        deriving stock   (Generic,Show,Eq)
        deriving anyclass (NoUnexpectedThunks)

    data SignKeyKES (RustKES t) = Sign SecretKey PublicKey
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

    type Signable (RustKES t) = ToCBOR

    -- | Produce valid signature only with correct key, i.e., same iteration and allowed KES period.
    signKES () _period object (Sign secret _public) =
        -- let _period' = period_from(secret) in assert (period == period') $
        Sig (sign2 secret object)

    deriveVerKeyKES (Sign _secret public) = Verify public

    verifyKES () (Verify public) _period object (Sig signature) =
        if verify2 public object signature then Right() else Left "KES verification failed"

    updateKES () (Sign secret public) period =
       -- let period' = period_from(secret) in assert period = period' $
       if period +1 < (totalPeriodsKES (Proxy @ (RustKES t)))
          then Just (Sign (update2 secret) public)
          else Nothing

    genKeyKES seed = Sign secret public
       where (public,secret) = generate2(seedToSeed seed)  -- Converson from Cardano Seed to Rust Seed

    rawSerialiseVerKeyKES (Verify (PublicKey public)) = public
    rawSerialiseSignKeyKES (Sign (SecretKey secret) (PublicKey public)) = BS.append (convert secret) public
    rawSerialiseSigKES (Sig (Signature s)) = s

    rawDeserialiseVerKeyKES bs = Just(Verify (PublicKey bs))
    rawDeserialiseSignKeyKES bs = Just(Sign (SecretKey (convert secret)) (PublicKey public))
       where (secret,public) = BS.splitAt 1220 bs
    rawDeserialiseSigKES bs = Just(Sig (Signature bs))


-- =====================================================================

go :: IO Bool
go = do
  seed <- createSeed
  putStrLn "> "
  bytes <- BS.getLine
  let (a,b) = BS.splitAt 4 bytes
  putStrLn("'"++show a++"'   '"++show b++"'")
  let (public,secret) = generate2 seed
      sig = sign2 secret bytes
  update secret
  let word = t secret
  return(verify2 public bytes sig)
