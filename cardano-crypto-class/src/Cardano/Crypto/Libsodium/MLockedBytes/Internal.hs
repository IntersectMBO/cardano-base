{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Cardano.Crypto.Libsodium.MLockedBytes.Internal (
    MLockedFiniteBytes (..),
    mlfbFromByteString,
    mlfbToByteString,
) where

import Control.DeepSeq (NFData (..))
import Data.Proxy (Proxy (..))
import Foreign.C.Types (CSize (..))
import Foreign.ForeignPtr (castForeignPtr)
import Foreign.Ptr (castPtr)
import GHC.IO.Handle.Text (memcpy)
import GHC.TypeLits (KnownNat, natVal)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Cardano.Crypto.Libsodium.Memory.Internal
import Cardano.Crypto.Libsodium.C
import Cardano.Prelude (NoUnexpectedThunks, OnlyCheckIsWHNF (..))

import qualified Cardano.Crypto.FiniteBytes as FB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI

newtype MLockedFiniteBytes n = MLFB (MLockedForeignPtr (FB.FiniteBytes n))
  deriving NoUnexpectedThunks via OnlyCheckIsWHNF "MLockedFiniteBytes" (MLockedFiniteBytes n)

instance KnownNat n => Eq (MLockedFiniteBytes n) where
    x == y = compare x y == EQ

instance KnownNat n => Ord (MLockedFiniteBytes n) where
    compare (MLFB x) (MLFB y) = unsafeDupablePerformIO $
        withMLockedForeignPtr x $ \x' ->
        withMLockedForeignPtr y $ \y' -> do
            res <- c_sodium_compare x' y' (CSize (fromIntegral size))
            return (compare res 0)
      where
        size = natVal (Proxy @n)

instance KnownNat n => Show (MLockedFiniteBytes n) where
    showsPrec d _ = showParen (d > 10)
        $ showString "_ :: MLockedFiniteBytes"
        . showsPrec 11 (natVal (Proxy @n))
        
    
instance NFData (MLockedFiniteBytes n) where
    rnf (MLFB p) = seq p ()

mlfbFromByteString :: forall n. KnownNat n => BS.ByteString -> MLockedFiniteBytes n
mlfbFromByteString bs = unsafeDupablePerformIO $ BS.useAsCStringLen bs $ \(ptrBS, len) -> do
    fptr <- allocMLockedForeignPtr
    withMLockedForeignPtr fptr $ \ptr -> do
        _ <- memcpy (castPtr ptr) ptrBS (fromIntegral (min len size))
        return ()
    return (MLFB fptr)
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

-- | /Note:/ the resulting 'BS.ByteString' will still refer to secure memory,
-- but the types don't prevent it from be exposed.
--
mlfbToByteString :: forall n. KnownNat n => MLockedFiniteBytes n -> BS.ByteString
mlfbToByteString (MLFB (SFP fptr)) = BSI.PS (castForeignPtr fptr) 0 size where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

