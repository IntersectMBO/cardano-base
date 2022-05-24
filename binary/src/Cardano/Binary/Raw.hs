{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Cardano.Binary.Raw
  ( Raw(..)
  )
where

import Prelude

import Control.DeepSeq (NFData)
import Data.ByteString ( ByteString )

import Cardano.Binary.FromCBOR (FromCBOR)
import Cardano.Binary.ToCBOR (ToCBOR)


-- | A wrapper over 'ByteString' for signalling that a bytestring should be
--   processed as a sequence of bytes, not as a separate entity. It's used in
--   crypto and binary code.
newtype Raw = Raw ByteString
  deriving (Eq, Ord, Show, NFData, FromCBOR, ToCBOR)
