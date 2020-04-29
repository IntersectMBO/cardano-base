{-# LANGUAGE FlexibleInstances #-}

{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
module Cardano.Crypto.Util
  ( Empty
  , mockNonNegIntR
  )
where

import Crypto.Random (MonadRandom (..))
import Data.ByteString (ByteString, unpack)
import Data.List (foldl')

class Empty a

instance Empty a

mockNonNegIntR :: MonadRandom m => m Int
mockNonNegIntR = abs . toInt <$> getRandomBytes 8
  where
    toInt :: ByteString -> Int
    toInt =
      foldl' (\acc w8 -> acc * 256 + fromIntegral w8) 0 . unpack
