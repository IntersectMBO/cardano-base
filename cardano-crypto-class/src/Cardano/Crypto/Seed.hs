{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

-- | Seeds for key generation.
--
module Cardano.Crypto.Seed
  ( Seed
    -- * Constructing seeds
  , mkSeedFromBytes
  , getSeedBytes
  , readSeedFromSystemEntropy
  , splitSeed
  , expandSeed
    -- * Using seeds
  , getBytesFromSeed
  , getBytesFromSeedT
  , getBytesFromSeedEither
  , getSeedSize
  , runMonadRandomWithSeed
  , SeedBytesExhausted(..)
  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.ByteArray as BA (convert)

import           Control.DeepSeq (NFData)
import           Control.Exception (Exception(..), throw)

import           Data.Functor.Identity
import           Data.Bifunctor (first)
import           Control.Monad.Trans.Except
import           Control.Monad.Trans.State
import           NoThunks.Class (NoThunks)

import           Crypto.Random (MonadRandom(..))
import           Crypto.Random.Entropy (getEntropy)
import           Cardano.Crypto.Hash.Class (HashAlgorithm(digest))


-- | A seed contains a finite number of bytes, and is used for seeding
-- cryptographic algorithms including key generation.
--
-- This is not itself a PRNG, but can be used to seed a PRNG.
--
newtype Seed = Seed ByteString
  deriving (Show, Eq, Semigroup, Monoid, NoThunks, NFData)

-- | Construct a 'Seed' deterministically from a number of bytes.
--
mkSeedFromBytes :: ByteString -> Seed
mkSeedFromBytes = Seed


-- | Extract the full bytes from a seed. Note that this function does not
-- guarantee that the result is sufficiently long for the desired seed size!
getSeedBytes :: Seed -> ByteString
getSeedBytes (Seed s) = s

getSeedSize :: Seed -> Word
getSeedSize (Seed bs) =
  fromIntegral . max 0 $ BS.length bs

-- | Get a number of bytes from the seed. This will fail if not enough bytes
-- are available. This can be chained multiple times provided the seed is big
-- enough to cover each use.
--
getBytesFromSeed :: Word -> Seed -> Maybe (ByteString, Seed)
getBytesFromSeed n s =
  case getBytesFromSeedEither n s of
    Right x -> Just x
    Left _ -> Nothing

getBytesFromSeedEither :: Word -> Seed -> Either SeedBytesExhausted (ByteString, Seed)
getBytesFromSeedEither n (Seed s)
  | n == fromIntegral (BS.length b)
  = Right (b, Seed s')
  | otherwise
  = Left $ SeedBytesExhausted (fromIntegral $ BS.length b) (fromIntegral n)
  where
    (b, s') = BS.splitAt (fromIntegral n) s

-- | A flavor of 'getBytesFromSeed' that throws 'SeedBytesExhausted' instead of
-- returning 'Nothing'.
getBytesFromSeedT :: Word -> Seed -> (ByteString, Seed)
getBytesFromSeedT n s =
  either throw id $ getBytesFromSeedEither n s

-- | Split a seed into two smaller seeds, the first of which is the given
-- number of bytes large, and the second is the remaining. This will fail if
-- not enough bytes are available. This can be chained multiple times provided
-- the seed is big enough to cover each use.
--
splitSeed :: Word -> Seed -> Maybe (Seed, Seed)
splitSeed n s =
  first Seed <$> getBytesFromSeed n s

-- | Expand a seed into a pair of seeds using a cryptographic hash function (in
-- the role of a crypto PRNG). The whole input seed is consumed. The output
-- seeds are the size of the hash output.
--
expandSeed :: HashAlgorithm h => proxy h -> Seed -> (Seed, Seed)
expandSeed p (Seed s) =
    ( Seed (digest p (BS.cons 1 s))
    , Seed (digest p (BS.cons 2 s))
    )


-- | Obtain a 'Seed' by reading @n@ bytes of entropy from the operating system.
--
readSeedFromSystemEntropy :: Word -> IO Seed
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
runMonadRandomWithSeed s a =
    case runIdentity (runExceptT (evalStateT (unMonadRandomFromSeed a) s)) of
      Right x  -> x
      Left e -> throw e

data SeedBytesExhausted =
  SeedBytesExhausted
    { seedBytesSupplied :: Int
    , seedBytesDemanded :: Int
    }
  deriving Show

instance Exception SeedBytesExhausted

newtype MonadRandomFromSeed a =
        MonadRandomFromSeed {
          unMonadRandomFromSeed :: StateT Seed (ExceptT SeedBytesExhausted Identity) a
        }
  deriving newtype (Functor, Applicative, Monad)

getRandomBytesFromSeed :: Int -> MonadRandomFromSeed ByteString
getRandomBytesFromSeed n =
    MonadRandomFromSeed $
      StateT $ \s ->
        ExceptT $
          Identity $
            getBytesFromSeedEither (fromIntegral n) s

instance MonadRandom MonadRandomFromSeed where
  getRandomBytes n = BA.convert <$> getRandomBytesFromSeed n
