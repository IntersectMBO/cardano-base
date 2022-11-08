{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Memory.PoolTests (poolTests) where

import Cardano.Memory.Pool
import Common
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Monad
import Control.Monad.Primitive
import Data.Bits
import Data.Primitive.PVar
import Data.Primitive.Ptr (setPtr)
import Data.Word
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import GHC.TypeNats
import System.Mem (performGC)
import Test.QuickCheck.Monadic

propIO :: Testable a => IO a -> Property
propIO propM = monadicIO $ run $ propM

poolTests :: TestTree
poolTests = do
  testGroup
    "Pool"
    [ testProperty "findNextZeroIndex" $ propFindNextZeroIndex,
      poolProps (Block :: Block 32),
      poolProps (Block :: Block 64)
    ]

poolProps :: KnownNat n => Block n -> TestTree
poolProps block =
  testGroup
    ("Block " ++ show (blockByteCount block))
    [ testProperty "propPoolGarbageCollected (32byte)" $ propPoolGarbageCollected block
    ]

propFindNextZeroIndex :: Word -> Property
propFindNextZeroIndex w = propIO $
  case findNextZeroIndex w of
    Nothing -> w @?= maxBound
    Just ix -> do
      testBit w ix @?= False
      case findNextZeroIndex (setBit w ix) of
        Nothing -> setBit w ix @?= maxBound
        Just ix' -> do
          assertBool
            ("Expected found index to be different, but got same: " ++ show ix)
            (ix' /= ix)
          assertBool
            ("Expected the bit under index: " ++ show ix' ++ " to not be set") $
            not (testBit w ix')

propPoolGarbageCollected ::
  forall n.
  KnownNat n =>
  Block n ->
  Positive Int ->
  Word16 ->
  Word8 ->
  Word8 ->
  Property
propPoolGarbageCollected block (Positive n) numBlocks16 preFillByte fillByte = propIO $ do
  let -- A fairly large positive number
      numBlocks = 1 + (fromIntegral numBlocks16 `div` 20)
      mallocPreFilled bc = do
        mfp <- mallocForeignPtrBytes bc
        withForeignPtr mfp $ \ptr -> setPtr (castPtr ptr) bc preFillByte
        pure mfp
      checkBlockBytes byte ptr =
        let checkFillByte i =
              when (i >= 0) $ do
                byte' <- peekByteOff ptr i
                byte' @?= byte
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
  numBlocks' <- atomicReadIntPVar countRef
  numBlocks' @?= numBlocks
  forM_ ptrsFPtrs (checkBlockBytes fillByte)
  -- Ensure that memory to that pointers are referncing is still alive
  touch pool
