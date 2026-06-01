{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  fixedSize,
  guardFixedSized,
) where

import Cardano.Binary (Decoder, Encoding, decodeBytes, encodeBytes)
import Control.Monad (when)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable, typeRep)
import GHC.TypeLits (KnownNat, Nat, natVal)

class (Typeable a, KnownNat (FixedSize a)) => FixedSizeCodec a where
  type FixedSize a :: Nat
  rawEncodeFixedSized :: a -> BS.ByteString
  rawDecodeFixedSized :: MonadFail m => BS.ByteString -> m a

fixedSize :: forall a proxy. FixedSizeCodec a => proxy a -> Word
fixedSize _ = fromInteger @Word . natVal $ Proxy @(FixedSize a)

guardFixedSized ::
  forall a m.
  (FixedSizeCodec a, MonadFail m) =>
  Proxy a -> BS.ByteString -> m ()
guardFixedSized proxy bs =
  when (actualSize /= expectedSize) $
    fail
      ( tyName
          ++ ": wrong length, expected "
          ++ show expectedSize
          ++ " bytes but got "
          ++ show actualSize
      )
  where
    tyName = show (typeRep proxy)
    expectedSize = fromIntegral $ fixedSize proxy
    actualSize = BS.length bs
{-# INLINE guardFixedSized #-}

decodeFixedSized :: FixedSizeCodec a => Decoder s a
decodeFixedSized = decodeBytes >>= rawDecodeFixedSized

encodeFixedSized :: FixedSizeCodec a => a -> Encoding
encodeFixedSized = encodeBytes . rawEncodeFixedSized
