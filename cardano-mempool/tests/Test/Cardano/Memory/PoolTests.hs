{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Cardano.Memory.PoolTests (poolTests) where


import Cardano.Memory.Pool
import Common
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Concurrent.Chan
import Control.Monad
import Control.Monad.Primitive
import Data.Bits
import Data.Function
import Data.Primitive.PVar
import Data.Primitive.Ptr (setPtr)
import Data.Word
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import GHC.TypeNats
import System.Mem (performGC)
import System.Random.Stateful
import Test.QuickCheck.Monadic

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
    [ testProperty "PoolGarbageCollected" $ propPoolGarbageCollected block
    , testProperty "PoolAllocateAndFinalize" $ propPoolAllocateAndFinalize block
    ]

propFindNextZeroIndex :: Int -> Property
propFindNextZeroIndex w = monadicIO . run $
  case findNextZeroIndex w of
    Nothing -> w @?= complement 0
    Just ix -> do
      testBit w ix @?= False
      case findNextZeroIndex (setBit w ix) of
        Nothing -> setBit w ix @?= complement 0
        Just ix' -> do
          assertBool
            ("Expected found index to be different, but got same: " ++ show ix)
            (ix' /= ix)
          assertBool
            ("Expected the bit under index: " ++ show ix' ++ " to not be set")
            $ not (testBit w ix')

-- We allow one extra page be allocated due to concurrency false positives in block
-- reservations
checkNumPages :: Pool n -> Int -> Int -> Assertion
checkNumPages pool n numBlocks = do
  let estimatedUpperBoundOfPages = 1 + max 1 (numBlocks `div` n `div` 64)
  numPages <- countPages pool
  assertBool
    (concat
       [ "Number of pages should not exceed the expected amount: "
       , show estimatedUpperBoundOfPages
       , " but allocated: "
       , show numPages
       ])
    (numPages <= estimatedUpperBoundOfPages)


checkBlockBytes ::
  (KnownNat n, Storable a, Eq a, Show a) => Block n -> a -> Ptr b -> Assertion
checkBlockBytes block byte ptr =
  let checkFillByte i =
        when (i >= 0) $ do
          byte' <- peekByteOff ptr i
          byte' @?= byte
          checkFillByte (i - 1)
   in checkFillByte (blockByteCount block - 1)

mallocPreFilled :: Word8 -> Int -> IO (ForeignPtr b)
mallocPreFilled preFillByte bc = do
  mfp <- mallocForeignPtrBytes bc
  withForeignPtr mfp $ \ptr -> setPtr (castPtr ptr) bc preFillByte
  pure mfp

propPoolGarbageCollected ::
  forall n.
  KnownNat n =>
  Block n ->
  Positive Int ->
  Word16 ->
  Word8 ->
  Word8 ->
  Property
propPoolGarbageCollected block (Positive n) numBlocks16 preFillByte fillByte =
  monadicIO . run $ do
    let numBlocks = 1 + (fromIntegral numBlocks16 `div` 20) -- make it not too big
    countRef <- newPVar (0 :: Int)
    pool <-
      initPool n (mallocPreFilled preFillByte) $ \ptr -> do
        setPtr (castPtr ptr) (blockByteCount block) fillByte
        void $ atomicAddIntPVar countRef 1
    fmps :: [ForeignPtr (Block n)] <-
      replicateConcurrently numBlocks (grabNextBlock pool)
    touch fmps
    -- Here we return just the pointers and let the GC collect the ForeignPtrs
    ptrs <-
      forM fmps $ \fma ->
        withForeignPtr fma $ \ptr -> do
          let bytePtr = castPtr ptr
          checkBlockBytes block preFillByte bytePtr
          setPtr bytePtr (blockByteCount block) fillByte
          pure bytePtr
    performGC
    -- allow some time for all blocks to finalize
    threadDelay 50000
    numBlocks' <- atomicReadIntPVar countRef
    numBlocks' @?= numBlocks
    forM_ ptrs (checkBlockBytes block fillByte)
    checkNumPages pool n numBlocks
    -- Ensure that memory to that the pointers are referencing to is still alive
    touch pool

propPoolAllocateAndFinalize ::
  forall n.
  KnownNat n =>
  Block n ->
  Positive Int ->
  Word16 ->
  Word8 ->
  Word8 ->
  Property
propPoolAllocateAndFinalize block (Positive n) numBlocks16 emptyByte fullByte =
  monadicIO . run $ do
    let numBlocks = 1 + (fromIntegral numBlocks16 `div` 20)
    countRef <- newPVar (0 :: Int)
    chan <- newChan
    pool <-
      initPool n (mallocPreFilled emptyByte) $ \(ptr :: Ptr (Block n)) -> do
        setPtr (castPtr ptr) (blockByteCount block) emptyByte
        void $ atomicAddIntPVar countRef 1
    -- allocate and finalize blocks concurrently
    concurrently_
      (do replicateConcurrently_ numBlocks $ do
            fp <- grabNextBlock pool
            withForeignPtr fp (checkBlockBytes block emptyByte)
            writeChan chan (Just fp)
          -- place Nothing to indicate we are done allocating blocks
          writeChan chan Nothing)
      (fix $ \loop -> do
         mfp <- readChan chan
         forM_ mfp $ \fp -> do
           withForeignPtr fp $ \ptr ->
             -- fill the newly allocated block
             setPtr (castPtr ptr) (blockByteCount block) fullByte
           -- manually finalize every other block and let the GC to pick the rest
           shouldFinalize <- uniformM globalStdGen
           when shouldFinalize $ finalizeForeignPtr fp
           loop)
    performGC
    -- allow some time for all blocks to finalize
    threadDelay 50000
    -- verify all finalizers have been executed
    numBlocks' <- atomicReadIntPVar countRef
    numBlocks' @?= numBlocks
    -- verify number of pages
    checkNumPages pool n numBlocks
