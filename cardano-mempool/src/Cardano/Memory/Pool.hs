{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UnboxedTuples #-}

-- | The goal of this Memory Pool is to provide the ability to allocate big chunks of
-- memory that can fit many `Block`s. Some memory allocators out there have a fairly large
-- minimal size requirement, which would be wasteful if many chunks of small size (eg. 32
-- bytes) are needed at once. Memory pool will allocate one page at a time as more blocks
-- is needed.
--
-- Currently there is no functionality for releasing unused pages. So, once a page is
-- allocated, it will be re-used when more `Block`s is needed, but it will not be GCed
-- until the whole `Pool` is GCed.
module Cardano.Memory.Pool
  ( -- * Pool
    Pool
  , initPool
  -- * Block
  , Block(..)
  , blockByteCount
  , grabNextBlock
  -- * Helpers
  --
  -- Exported for testing
  , countPages
  , findNextZeroIndex
  ) where

import Control.Monad
import Control.Monad.Primitive
import Foreign.Ptr
import Foreign.ForeignPtr
import GHC.ForeignPtr
import Control.Applicative
import Data.Bits
import GHC.TypeLits
import Data.Primitive.PrimArray
import Data.Primitive.PVar
import Data.Primitive.PVar.Unsafe (atomicModifyIntArray#)
import Data.IORef
import GHC.Int
import GHC.IO
import GHC.Exts (fetchAndIntArray#)

-- | This is just a proxy type that carries information at the type level about the size
-- of the block in bytes supported by a particular instance of a `Pool`. Use
-- `blockByteCount` to get the byte size at the value level.
data Block (n :: Nat) = Block

-- | Number of bytes in a `Block`
blockByteCount :: KnownNat n => Block n -> Int
blockByteCount = fromInteger . natVal

-- | Internal helper type that manages each individual page. This is essentailly a mutable
-- linked list, which contains a memory buffer, a bit array that tracks which blocks in
-- the buffere are free and which ones are taken.
data Page n =
  Page
    { pageMemory :: !(ForeignPtr (Block n))
    -- ^ Contiguous memory buffer that holds all the blocks in the page.
    , pageBitArray :: !(MutablePrimArray RealWorld Int)
    -- ^ We use an Int array, because there are no built-in atomic primops for Word.
    , pageFull :: !(PVar Int RealWorld)
    -- ^ This is a boolean flag which indicates when a page is full. It here as
    -- optimization only, because it allows us to skip iteration of the above bit
    -- array. It is an `Int` instead of a `Bool`, because GHC provides atomic primops for
    -- ByteArray, whcih is what `PVar` is based on.
    , pageNextPage :: !(IORef (Maybe (Page n)))
    -- ^ Link to the next page. Last page when this IORef contains `Nothing`
    }

-- | Thread-safe lock-free memory pool for managing large memory pages that contain of
-- many small `Block`s.
data Pool n =
  Pool
    { poolFirstPage :: !(Page n)
    -- ^ Initial page, which itself contains references to subsequent pages
    , poolPageInitializer :: !(IO (Page n))
    -- ^ Page initializing action
    , poolBlockFinalizer :: !(Ptr (Block n) -> IO ())
    -- ^ Finilizer that will be attached to each individual `ForeignPtr` of a reserved
    -- `Block`.
    }

-- | Useful function for testing. Check how many pages have been allocated thus far.
countPages :: Pool n -> IO Int
countPages pool = go 1 (poolFirstPage pool)
  where
    go n Page {pageNextPage} = do
      readIORef pageNextPage >>= \case
        Nothing -> pure n
        Just nextPage -> go (n + 1) nextPage


ixBitSize :: Int
ixBitSize = finiteBitSize (0 :: Word)

-- | Initilizes the `Pool` that can be used for further allocation of @`ForeignPtr`
-- `Block` n@ with `grabNextBlock`.
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
        setPrimArray pageBitArray 0 groupsPerPage 0
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

-- | Reserve a `ForeignPtr` of the `blockByteCount` size in the `Pool`. There is a default
-- finalizer attached to the `ForeignPtr` that will run `Block` pointer finalizer and
-- release that memory for re-use by other blocks allocated in the future. It is safe to
-- add more Haskell finalizers with `addForeignPtrConcFinalizer` if necessary.
grabNextBlock :: KnownNat n => Pool n -> IO (ForeignPtr (Block n))
grabNextBlock = grabNextPoolBlockWith grabNextPageForeignPtr
{-# INLINE grabNextBlock #-}

-- | This is a helper function that will allocate a `Page` if the current `Page` in the
-- `Pool` is full. Whenever there are still block slots are available then supplied
-- @grabNext@ function will be used to reserve the slot in that `Page`.
grabNextPoolBlockWith ::
     (Page n -> (Ptr (Block n) -> IO ()) -> IO (Maybe (ForeignPtr (Block n))))
  -> Pool n
  -> IO (ForeignPtr (Block n))
grabNextPoolBlockWith grabNext pool = go (poolFirstPage pool)
  where
    go page = do
      isPageFull <- atomicReadIntPVar (pageFull page)
      if intToBool isPageFull
        then readIORef (pageNextPage page) >>= \case
               Nothing -> do
                 newPage <- poolPageInitializer pool
                 -- There is a slight chance of a race condition in that the next page could
                 -- have been allocated and assigned to 'pageNextPage' by another thread
                 -- since we last checked for it. This is not a problem since we can safely
                 -- discard the page created in this thread and switch to the one that was
                 -- assigned to 'pageNextPage'.
                 mNextPage <-
                   atomicModifyIORef' (pageNextPage page) $ \mNextPage ->
                     (mNextPage <|> Just newPage, mNextPage)
                 case mNextPage of
                   Nothing -> go newPage
                   Just existingPage -> do
                     -- Here we cleanup the newly allocated page in favor of the one that
                     -- was potentially created by another thread. It is important to
                     -- eagerly free up scarce resources
                     finalizeForeignPtr (pageMemory newPage)
                     go existingPage
               Just nextPage -> go nextPage
        else grabNext page (poolBlockFinalizer pool) >>= \case
               Nothing -> go page
               Just ma -> pure ma
{-# INLINE grabNextPoolBlockWith #-}

intToBool :: Int -> Bool
intToBool 0 = False
intToBool _ = True

-- | This is a helper function that will attempt to find the next available slot for the
-- `Block` and create a `ForeignPtr` with the size of `Block` in the `Page`. In case when
-- `Page` is full it will return `Nothing`.
grabNextPageForeignPtr ::
     forall n.
     KnownNat n
  -- | Page to grab the block from
  => Page n
  -- | Finalizer to run, once the `ForeignPtr` holding on to `Ptr` `Block` is no longer used
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

-- | Atomically AND an element of the array
atomicAndIntMutablePrimArray :: MutablePrimArray RealWorld Int -> Int -> Int -> IO ()
atomicAndIntMutablePrimArray (MutablePrimArray mba#) (I# i#) (I# m#) =
  IO $ \s# ->
    case fetchAndIntArray# mba# i# m# s# of
      (# s'#, _ #) -> (# s'#, () #)
{-# INLINE atomicAndIntMutablePrimArray #-}

-- | Atomically modify an element of the array
atomicModifyMutablePrimArray :: MutablePrimArray RealWorld Int -> Int -> (Int -> (Int, a)) -> IO a
atomicModifyMutablePrimArray (MutablePrimArray mba#) (I# i#) f =
  IO $ atomicModifyIntArray# mba# i# (\x# -> case f (I# x#) of (I# y#, a) -> (# y#, a #))
{-# INLINE atomicModifyMutablePrimArray #-}

-- | Helper function that finds an index of the left-most bit that is not set.
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

-- | Finds an index of the next bit that is not set in the bit array and flips it
-- atomically. In case when all bits are set, then `Nothing` is returned. It is possible
-- that while search is ongoing bits that where checked get cleared. This is totally fine
-- for our implementation of mempool.
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
