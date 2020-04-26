{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

-- | Seeds for key generation.
--
module Cardano.Crypto.Seed
  ( Seed
    -- * Constructing seeds
  , mkSeedFromBytes
  , readSeedFromSystemEntropy
    -- * Using seeds
  , getBytesFromSeed
  , runMonadRandomWithSeed
  , SeedBytesExhausted(..)
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.ByteArray as BA (convert)
import           Numeric.Natural (Natural)

import           Control.Exception (Exception(..), throw)

import           Data.Functor.Identity
import           Control.Monad.Trans.Maybe
import           Control.Monad.Trans.State

import           Crypto.Random (MonadRandom(..))
import           Crypto.Random.Entropy (getEntropy)

import           Cardano.Prelude (NoUnexpectedThunks)


-- | A seed contains a finite number of bytes, and is used for seeding
-- cryptographic algorithms including key generation.
--
-- This is not itself a PRNG, but can be used to seed a PRNG.
--
newtype Seed = Seed ByteString
  deriving (Show, Eq, Semigroup, Monoid, NoUnexpectedThunks)


-- | Construct a 'Seed' deterministically from a number of bytes.
--
mkSeedFromBytes :: ByteString -> Seed
mkSeedFromBytes = Seed


-- | Get a number of bytes from the seed. This will fail if not enough bytes
-- are available. This can be chained multiple times provided the seed is big
-- enough to cover each use.
--
getBytesFromSeed :: Int -> Seed -> Maybe (ByteString, Seed)
getBytesFromSeed n (Seed s)
  | BS.length b == n = Just (b, Seed s')
  | otherwise        = Nothing
  where
    (b, s') = BS.splitAt n s


-- | Obtain a 'Seed' by reading @n@ bytes of entropy from the operating system.
--
readSeedFromSystemEntropy :: Natural -> IO Seed
readSeedFromSystemEntropy n = mkSeedFromBytes <$> getEntropy (fromIntegral n)

--
-- Support for MonadRandom
--

-- | Run an action in 'MonadRandom' deterministically using a seed as a
-- finite source of randomness. Note that this is not a PRNG, so like with
-- 'getBytesFromSeed' it will fail if more bytes are requested than are
-- available.
--
-- So this is only really suitable for key generation where there is a known
-- upper bound on the amount of entropy that will be requested.
--
runMonadRandomWithSeed :: Seed -> (forall m. MonadRandom m => m a) -> a
runMonadRandomWithSeed s@(Seed bs) a =
    case runIdentity (runMaybeT (evalStateT (unMonadRandomFromSeed a) s)) of
      Just x  -> x
      Nothing -> throw (SeedBytesExhausted (BS.length bs))

newtype SeedBytesExhausted = SeedBytesExhausted { seedBytesSupplied :: Int }
  deriving Show

instance Exception SeedBytesExhausted

newtype MonadRandomFromSeed a =
        MonadRandomFromSeed {
          unMonadRandomFromSeed :: StateT Seed (MaybeT Identity) a
        }
  deriving newtype (Functor, Applicative, Monad)

getRandomBytesFromSeed :: Int -> MonadRandomFromSeed ByteString
getRandomBytesFromSeed n =
    MonadRandomFromSeed $
      StateT $ \s ->
        MaybeT $
          Identity $
            getBytesFromSeed n s


instance MonadRandom MonadRandomFromSeed where
  getRandomBytes n = BA.convert <$> getRandomBytesFromSeed n

