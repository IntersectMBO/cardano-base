{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UnboxedTuples #-}

module Cardano.Memory.Pool where

import Control.Monad
import Control.Monad.Primitive
import Foreign.Ptr
import Foreign.ForeignPtr
import GHC.ForeignPtr
import Control.Applicative
import Data.Bits
import Data.Maybe
import GHC.TypeLits
import Data.Primitive.PrimArray
import Data.Primitive.PVar
import Data.Primitive.PVar.Unsafe (atomicModifyIntArray#)
import Data.IORef
import GHC.Int
import GHC.IO
import GHC.Exts (fetchAndIntArray#)

data Block (n :: Nat) = Block

blockByteCount :: KnownNat n => Block n -> Int
blockByteCount = fromInteger . natVal

data Page n =
  Page
    { pageMemory :: !(ForeignPtr (Block n))
    , pageBitArray :: !(MutablePrimArray RealWorld Int) -- Need to use Int, since there are
                                                        -- no built-in atomic ops for Word
    , pageFull :: !(PVar Int RealWorld)
    , pageNextPage :: !(IORef (Maybe (Page n)))
    }

data Pool n =
  Pool
    { poolFirstPage :: !(Page n)
    , poolPageInitializer :: !(IO (Page n))
    , poolBlockFinalizer :: !(Ptr (Block n) -> IO ())
    }

ixBitSize :: Int
ixBitSize = finiteBitSize (0 :: Word)

initPool ::
     forall n. KnownNat n
  => Int
  -- ^ Number of groups per page. Must be a posititve number, otherwise error. One group
  -- contains as many blocks as the operating system has bits. A 64bit architecture will
  -- have 64 blocks per group. For example, if program is compiled on a 64 bit OS and you
  -- know ahead of time the maximum number of blocks that will be allocated through out
  -- the program, then the optimal value for this argument will @maxBlockNum/64@
  -> (forall a. Int -> IO (ForeignPtr a))
  -- ^ Mempool page allocator. Some allocated pages might be immediately discarded,
  -- therefore number of pages utilized will not necessesarely match the number of times
  -- this action will be called.
  -> (Ptr (Block n) -> IO ())
  -- ^ Finalizer to use for each block. It is an IO action because it will be executed by
  -- the Garbage Collector in a separate thread once the `Block` is no longer referenced.
  -> IO (Pool n)
initPool groupsPerPage memAlloc blockFinalizer = do
  unless (groupsPerPage > 0) $
    error $
    "Groups per page should be a positive number, but got: " ++
    show groupsPerPage
  let pageInit = do
        pageMemory <-
          memAlloc $ groupsPerPage * ixBitSize * blockByteCount (Block :: Block n)
        pageBitArray <- newPrimArray groupsPerPage
        pageFull <- newPVar 0
        pageNextPage <- newIORef Nothing
        pure Page {..}
  firstPage <- pageInit
  pure
    Pool
      { poolFirstPage = firstPage
      , poolPageInitializer = pageInit
      , poolBlockFinalizer = blockFinalizer
      }

grabNextPoolForeignPtr :: KnownNat n => Pool n -> IO (ForeignPtr (Block n))
grabNextPoolForeignPtr = grabNextPoolBlockWith grabNextPageForeignPtr
{-# INLINE grabNextPoolForeignPtr #-}


grabNextPoolBlockWith ::
     (Page n -> (Ptr (Block n) -> IO ()) -> IO (Maybe (ForeignPtr (Block n))))
  -> Pool n
  -> IO (ForeignPtr (Block n))
grabNextPoolBlockWith grabNext pool = go (poolFirstPage pool)
  where
    go page@Page {..} = do
      isPageFull <- atomicReadIntPVar pageFull
      if intToBool isPageFull
        then readIORef pageNextPage >>= \case
               Nothing -> do
                 newPage <- poolPageInitializer pool
                 -- There is a slight chance of a race condition in that the next page could
                 -- have been allocated and assigned to 'pageNextPage' by another thread
                 -- since we last checked for it. This is not a problem since we can safely
                 -- discard the page created in this thread and switch to the one that was
                 -- assigned to 'pageNextPage'.
                 mNextPage <-
                   atomicModifyIORef' pageNextPage $ \mNextPage ->
                     (mNextPage <|> Just newPage, mNextPage)
                 -- Here we potentially discard the newly allocated page in favor of the one
                 -- created by another thread.
                 go (fromMaybe newPage mNextPage)
               Just nextPage -> go nextPage
        else grabNext page (poolBlockFinalizer pool) >>= \case
               Nothing -> go page
               Just ma -> pure ma
{-# INLINE grabNextPoolBlockWith #-}

intToBool :: Int -> Bool
intToBool 0 = False
intToBool _ = True

grabNextPageForeignPtr ::
     forall n.
     KnownNat n
  -- | Page to grab the block from
  => Page n
  -- | Finalizer to run, once the `FMAddr` to the block is no longer used
  -> (Ptr (Block n) -> IO ())
  -> IO (Maybe (ForeignPtr (Block n)))
grabNextPageForeignPtr page finalizer =
  grabNextPageWithAllocator page $ \blockPtr resetIndex -> do
    fp <- newForeignPtr_ blockPtr
    addForeignPtrConcFinalizer fp $ finalizer blockPtr >> resetIndex
    pure fp
{-# INLINE grabNextPageForeignPtr #-}

grabNextPageWithAllocator ::
     forall n.  KnownNat n
  => Page n
  -> (Ptr (Block n) -> IO () -> IO (ForeignPtr (Block n)))
  -> IO (Maybe (ForeignPtr (Block n)))
grabNextPageWithAllocator Page {..} allocator = do
  setNextZero pageBitArray >>= \case
    -- There is a slight chance that some Blocks will be cleared before the pageFull is
    -- set to True. This is not a problem because that memory will be recovered as soon as
    -- any other Block in the Page is finalized
    --
    -- TODO: Potentially verify that first Int in pageBitArray has all bits set, in
    -- order to prevent the degenerate case of all Blocks beeing finalized right before
    -- the page is marked as full.
    Nothing -> Nothing <$ atomicWriteIntPVar pageFull 1
    Just ix ->
      fmap Just $
        withForeignPtr pageMemory $ \pagePtr ->
          let !blockPtr =
                plusPtr pagePtr $ ix * blockByteCount (Block :: Block n)
           in allocator blockPtr $ do
                let !(!q, !r) = ix `quotRem` ixBitSize
                    !pageBitMask = clearBit (complement 0) r
                touch pageMemory
                atomicAndIntMutablePrimArray pageBitArray q pageBitMask
                atomicWriteIntPVar pageFull 0
{-# INLINE grabNextPageWithAllocator #-}


atomicAndIntMutablePrimArray :: MutablePrimArray RealWorld Int -> Int -> Int -> IO ()
atomicAndIntMutablePrimArray (MutablePrimArray mba#) (I# i#) (I# m#) =
  IO $ \s# ->
    case fetchAndIntArray# mba# i# m# s# of
      (# s'#, _ #) -> (# s'#, () #)

atomicModifyMutablePrimArray :: MutablePrimArray RealWorld Int -> Int -> (Int -> (Int, a)) -> IO a
atomicModifyMutablePrimArray (MutablePrimArray mba#) (I# i#) f =
  IO $ atomicModifyIntArray# mba# i# (\x# -> case f (I# x#) of (I# y#, a) -> (# y#, a #))

findNextZeroIndex :: forall b. FiniteBits b => b -> Maybe Int
findNextZeroIndex b =
  let !i0 = countTrailingZeros b
      i1 = countTrailingZeros (complement b)
      maxBits = finiteBitSize (undefined :: b)
   in if i0 == 0
        then if i1 == maxBits
               then Nothing
               else Just i1
        else Just (i0 - 1)
{-# INLINE findNextZeroIndex #-}

setNextZero :: MutablePrimArray RealWorld Int -> IO (Maybe Int)
setNextZero ma = ifindAtomicMutablePrimArray ma f
  where
    f i !w =
      case findNextZeroIndex w of
        Nothing -> (w, Nothing)
        Just !bitIx -> (setBit w bitIx, Just (ixBitSize * i + bitIx))
{-# INLINE setNextZero #-}


ifindAtomicMutablePrimArray ::
  MutablePrimArray RealWorld Int ->
  (Int -> Int -> (Int, Maybe a)) ->
  IO (Maybe a)
ifindAtomicMutablePrimArray ma f = do
  n <- getSizeofMutablePrimArray ma
  let go i
        | i >= n = pure Nothing
        | otherwise =
          atomicModifyMutablePrimArray ma i (f i) >>= \case
            Nothing -> go (i + 1)
            Just a -> pure $! Just a
  go 0
{-# INLINE ifindAtomicMutablePrimArray #-}
