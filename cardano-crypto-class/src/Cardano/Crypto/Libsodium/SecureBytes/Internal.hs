{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Cardano.Crypto.Libsodium.SecureBytes.Internal (
    SecureFiniteBytes (..),
    sfbFromByteString,
    sfbToByteString,
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

newtype SecureFiniteBytes n = SFB (SecureForeignPtr (FB.FiniteBytes n))
  deriving NoUnexpectedThunks via OnlyCheckIsWHNF "SecureFiniteBytes" (SecureFiniteBytes n)

instance KnownNat n => Eq (SecureFiniteBytes n) where
    x == y = compare x y == EQ

instance KnownNat n => Ord (SecureFiniteBytes n) where
    compare (SFB x) (SFB y) = unsafeDupablePerformIO $
        withSecureForeignPtr x $ \x' ->
        withSecureForeignPtr y $ \y' -> do
            res <- c_sodium_compare x' y' (CSize (fromIntegral size))
            return (compare res 0)
      where
        size = natVal (Proxy @n)

instance KnownNat n => Show (SecureFiniteBytes n) where
    showsPrec d _ = showParen (d > 10)
        $ showString "_ :: SecureFiniteBytes"
        . showsPrec 11 (natVal (Proxy @n))
        
    
instance NFData (SecureFiniteBytes n) where
    rnf (SFB p) = seq p ()

sfbFromByteString :: forall n. KnownNat n => BS.ByteString -> SecureFiniteBytes n
sfbFromByteString bs = unsafeDupablePerformIO $ BS.useAsCStringLen bs $ \(ptrBS, len) -> do
    fptr <- allocSecureForeignPtr
    withSecureForeignPtr fptr $ \ptr -> do
        _ <- memcpy (castPtr ptr) ptrBS (fromIntegral (min len size))
        return ()
    return (SFB fptr)
  where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

-- | /Note:/ the resulting 'BS.ByteString' will still refer to secure memory,
-- but the types don't prevent it from be exposed.
--
sfbToByteString :: forall n. KnownNat n => SecureFiniteBytes n -> BS.ByteString
sfbToByteString (SFB (SFP fptr)) = BSI.PS (castForeignPtr fptr) 0 size where
    size  :: Int
    size = fromInteger (natVal (Proxy @n))

