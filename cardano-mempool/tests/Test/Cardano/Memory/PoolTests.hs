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
import Data.Proxy
import Data.Reflection
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
    [ testProperty "findNextZeroIndex" $ propFindNextZeroIndex
    , poolProps (Block :: Block 32)
    , poolProps (Block :: Block 64)
    , poolPropsArbSizeBlock
    ]

poolProps :: KnownNat n => Block n -> TestTree
poolProps block =
  testGroup
    ("Block " ++ show (blockByteCount block))
    [ testProperty "PoolGarbageCollected" $ propPoolGarbageCollected block
    , testProperty "PoolAllocateAndFinalize" $ propPoolAllocateAndFinalize block
    ]

poolPropsArbSizeBlock :: TestTree
poolPropsArbSizeBlock =
  testGroup
    "Arbitrary sized block"
    [ testProperty "PoolGarbageCollected" $ \(Positive n) ->
        reifyNat n (propPoolGarbageCollected . proxyToBlock)
    , testProperty "PoolAllocateAndFinalize" $ \(Positive n) ->
        reifyNat n (propPoolAllocateAndFinalize . proxyToBlock)
    ]
  where
    proxyToBlock :: Proxy n -> Block n
    proxyToBlock Proxy = Block

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
            ("Expected the bit under index: " ++ show ix' ++ " to not be set") $
            not (testBit w ix')

-- We allow one extra page be allocated due to concurrency false positives in block
-- reservations
checkNumPages :: Pool n RealWorld -> Int -> Int -> Assertion
checkNumPages pool n numBlocks = do
  let estimatedUpperBoundOfPages = 1 + max 1 (numBlocks `div` n `div` 64)
  numPages <- stToPrim $ countPages pool
  assertBool
    (concat
       [ "Number of pages should not exceed the expected amount: "
       , show estimatedUpperBoundOfPages
       , " but allocated: "
       , show numPages
       ])
    (numPages <= estimatedUpperBoundOfPages)

checkBlockBytes ::
     (KnownNat n, Storable a, Eq a, Show a)
  => Block n
  -> a
  -> Ptr b
  -> Assertion
checkBlockBytes block byte ptr =
  let checkFillByte i =
        when (i >= 0) $ do
          byte' <- peekByteOff ptr i
          byte' @?= byte
          checkFillByte (i - 1)
   in checkFillByte (blockByteCount block - 1)

mallocPreFilled :: Word8 -> Int -> ST s (ForeignPtr b)
mallocPreFilled preFillByte bc = unsafeIOToPrim $ do
  mfp <- mallocForeignPtrBytes bc
  withForeignPtr mfp $ \ptr -> setPtr (castPtr ptr) bc preFillByte
  pure mfp


-- | @ensureAllGCedWith iterations delay expectedCount registerCounter@ waits
-- for all items to be GCed by triggering garbage collection @iterations@
-- times, once every @delay@ milliseconds. After @iterations@ attempts, if the
-- counter hook was not called exactly @expectedCount@ times, a test failure is
-- raised via 'assertFailure'. Garbage collection is tracked via finalizers
-- (see below).
ensureAllGCedWith ::
     Int
  -- ^ Number of GC attempts to make before failing
  -> Int
  -- ^ Delay between attempts, in milliseconds
  -> Int
  -- ^ Expected number of counter hook firings (in practice: individual
  -- garbage collections on 'ForeignPtr's, as per their finalizers).
  -> (IO () -> IO a)
  -- ^ Function for registering the counter hook. The argument to this
  -- function should be attached to each 'ForeignPtr' we're interested in
  -- as a finalizer.
  -> IO a
ensureAllGCedWith iterations delay expectedCount registerCounter = do
  countRef <- newPVar (0 :: Int)
  res <- registerCounter (void $ atomicAddIntPVar countRef 1)
  let go i = do
        performGC
        threadDelay (delay * 1000)
        n <- atomicReadIntPVar countRef
        unless (n == expectedCount) $ do
          if i <= 1
            then assertFailure $
                 "Expected all " ++
                 show expectedCount ++
                 " pointers to be GCed in " ++
                 show (delay * iterations) ++
                 "ms, but " ++ show n ++ " where GCed instead"
            else go (i - 1)
  res <$ go iterations


-- | 'ensureAllGCedWith' with default values: 100 iterations, 10ms delay.
ensureAllGCed :: Int -> (IO () -> IO a) -> IO a
ensureAllGCed = ensureAllGCedWith 100 10


propPoolGarbageCollected ::
     forall n. KnownNat n
  => Block n
  -> Positive Int
  -> Word16
  -> Word8
  -> Word8
  -> Property
propPoolGarbageCollected block (Positive n) numBlocks16 preFillByte fillByte =
  monadicIO . run $ do
    let numBlocks = 1 + (fromIntegral numBlocks16 `div` 20) -- make it not too big
    (pool, ptrs) <-
      ensureAllGCed numBlocks $ \countOneBlockGCed -> do
        pool <-
          stToPrim $ initPool n (mallocPreFilled preFillByte) $ \ptr -> do
            setPtr (castPtr ptr) (blockByteCount block) fillByte
            countOneBlockGCed
        fmps :: [ForeignPtr (Block n)] <-
          replicateConcurrently numBlocks (stToPrim $ grabNextBlock pool)
        touch fmps
        -- Here we return just the pointers and let the GC collect the ForeignPtrs
        ptrs <-
          forM fmps $ \fma ->
            withForeignPtr fma $ \ptr -> do
              let bytePtr = castPtr ptr
              checkBlockBytes block preFillByte bytePtr
              setPtr bytePtr (blockByteCount block) fillByte
              pure bytePtr
        pure (pool, ptrs)
    forM_ ptrs (checkBlockBytes block fillByte)
    checkNumPages pool n numBlocks
    -- Ensure that memory to that the pointers are referencing to is still alive
    touch pool

propPoolAllocateAndFinalize ::
     forall n. KnownNat n
  => Block n
  -> Positive Int
  -> Word16
  -> Word8
  -> Word8
  -> Property
propPoolAllocateAndFinalize block (Positive n) numBlocks16 emptyByte fullByte =
  monadicIO . run $ do
    let numBlocks = 1 + (fromIntegral numBlocks16 `div` 20)
    pool <-
      ensureAllGCed numBlocks $ \countOneBlockGCed -> do
        chan <- newChan
        pool <-
          stToPrim $ initPool n (mallocPreFilled emptyByte) $ \(ptr :: Ptr (Block n)) -> do
            setPtr (castPtr ptr) (blockByteCount block) emptyByte
            countOneBlockGCed
        -- allocate and finalize blocks concurrently
        pool <$
          concurrently_
            (do replicateConcurrently_ numBlocks $ do
                  fp <- stToPrim $ grabNextBlock pool
                  withForeignPtr fp (checkBlockBytes block emptyByte)
                  writeChan chan (Just fp)
                -- place Nothing to indicate that we are done allocating blocks
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
    -- verify number of pages
    checkNumPages pool n numBlocks
