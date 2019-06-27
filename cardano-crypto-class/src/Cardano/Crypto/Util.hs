{-# LANGUAGE FlexibleInstances #-}

{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
module Cardano.Crypto.Util
  ( Empty
  , nonNegIntR
  )
where

import Crypto.Random (MonadRandom (..))
import Data.ByteString (ByteString, unpack)

class Empty a

instance Empty a

nonNegIntR :: MonadRandom m => m Int
nonNegIntR = toInt <$> getRandomBytes 4
  where
    toInt :: ByteString -> Int
    toInt bs =
      let a , b, c, d :: Int
          [a, b, c, d] = map fromIntegral $ unpack bs
      in a + 256 * b + 65536 * c + 16777216 * d
