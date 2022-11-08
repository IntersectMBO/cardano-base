{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Memory.PoolSpec (spec) where

import Common
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Monad.Primitive
import GHC.TypeNats
import Foreign.ForeignPtr
import Foreign.Storable
import System.Mem (performGC)
import Control.Monad
import Foreign.Ptr
import Data.Bits
import Data.Primitive.Ptr (setPtr)
import Data.Primitive.PVar
import Cardano.Memory.Pool
import Data.Word


spec :: Spec
spec = do
  describe "Pool" $ do
    prop "findNextZeroIndex" $ propFindNextZeroIndex
    prop "First prop" $ propPool (Block :: Block 32)

propFindNextZeroIndex :: Word -> Expectation
propFindNextZeroIndex w =
  case findNextZeroIndex w of
    Nothing -> w `shouldBe` maxBound
    Just ix -> do
      testBit w ix `shouldBe` False
      case findNextZeroIndex (setBit w ix) of
        Nothing -> setBit w ix `shouldBe` maxBound
        Just ix' -> do
          ix' `shouldNotBe` ix
          testBit w ix' `shouldBe` False

propPool ::
     forall n. KnownNat n
  => Block n
  -> Positive Int
  -> Word16
  -> Word8
  -> Word8
  -> Expectation
propPool block (Positive n) numBlocks16 preFillByte fillByte = do
  let -- A fairly large positive number
      numBlocks = 1 + (fromIntegral numBlocks16 `div` 20)
      mallocPreFilled bc = do
        mfp <- mallocForeignPtrBytes bc
        withForeignPtr mfp $ \ptr -> setPtr (castPtr ptr) bc preFillByte
        pure mfp
      checkBlockBytes byte ptr =
        let checkFillByte i =
               when (i >= 0) $ do
                 peekByteOff ptr i `shouldReturn` byte
                 checkFillByte (i - 1)
        in checkFillByte (blockByteCount block - 1)
  countRef <- newPVar (0 :: Int)
  pool <-
    initPool n mallocPreFilled $ \ptr -> do
      setPtr (castPtr ptr) (blockByteCount block) fillByte
      () <$ atomicAddIntPVar countRef 1
  fmps :: [ForeignPtr (Block n)] <-
    replicateConcurrently numBlocks (grabNextBlock pool)
  touch fmps
  -- Here we return just the pointers and let the GC collect the ForeignPtrs
  ptrsFPtrs <- forM fmps $ \fma ->
    withForeignPtr fma $ \ptr -> do
      let bytePtr = castPtr ptr
      checkBlockBytes preFillByte bytePtr
      setPtr bytePtr (blockByteCount block) fillByte
      pure bytePtr
  performGC
  threadDelay 50000
  atomicReadIntPVar countRef `shouldReturn` numBlocks
  forM_ ptrsFPtrs (checkBlockBytes fillByte)
  -- Ensure that memory to that pointers are referncing is still alive
  touch pool
