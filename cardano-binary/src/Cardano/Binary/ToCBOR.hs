{-# LANGUAGE CPP #-}
{-# LANGUAGE ConstrainedClassMethods #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NumDecimals #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Binary.ToCBOR (
  ToCBOR (..),
  withWordSize,
  module E,
  encodeMaybe,
  toCBORMaybe,
  encodeNullMaybe,
  encodeSeq,
  encodeNominalDiffTime,
  encodeNominalDiffTimeMicro,

  -- * Size of expressions
  Range (..),
  szEval,
  Size,
  Case (..),
  caseValue,
  LengthOf (..),
  SizeOverride (..),
  isTodo,
  szCases,
  szLazy,
  szGreedy,
  szForce,
  szWithCtx,
  szSimplify,
  apMono,
  szBounds,
)
where

import Prelude hiding ((.))

import qualified Codec.CBOR.ByteArray as BA (ByteArray (..), sizeofByteArray)
import Codec.CBOR.ByteArray.Sliced as BAS
import Codec.CBOR.Encoding as E
import Codec.CBOR.Term
import Control.Category (Category ((.)))
import Data.Array.Byte (ByteArray)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BS.Lazy
import qualified Data.ByteString.Short as SBS
import Data.ByteString.Short.Internal (ShortByteString (SBS))
import Data.Fixed (Fixed (..), Micro)
import qualified Data.Primitive.ByteArray as Prim
import qualified Data.Sequence as Seq
#if MIN_VERSION_recursion_schemes(5,2,0)
import Data.Fix ( Fix(..) )
#else
import Data.Functor.Foldable (Fix(..))
#endif
import Data.Foldable (foldMap', toList)
import Data.Functor.Foldable (cata, project)
import Data.Int (Int32, Int64)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.Map as M
import Data.Ratio (Ratio, denominator, numerator)
import qualified Data.Set as S
import Data.Tagged (Tagged (..))
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Lazy.Builder (Builder)
import Data.Time.Calendar.OrdinalDate (toOrdinalDate)
import Data.Time.Clock (
  NominalDiffTime,
  UTCTime (..),
  diffTimeToPicoseconds,
  nominalDiffTimeToSeconds,
 )
import Data.Typeable (Proxy (..), TypeRep, Typeable, typeRep)
import qualified Data.Vector as Vector
import qualified Data.Vector.Generic as Vector.Generic
import Data.Void (Void, absurd)
import Data.Word (Word16, Word32, Word64, Word8)
import Foreign.Storable (sizeOf)
import Formatting (bprint, build, shown, stext)
import qualified Formatting.Buildable as B (Buildable (..))
import Numeric.Natural (Natural)

class Typeable a => ToCBOR a where
  toCBOR :: a -> Encoding

  encodedSizeExpr :: (forall t. ToCBOR t => Proxy t -> Size) -> Proxy a -> Size
  encodedSizeExpr = todo

  encodedListSizeExpr :: (forall t. ToCBOR t => Proxy t -> Size) -> Proxy [a] -> Size
  encodedListSizeExpr = defaultEncodedListSizeExpr

-- | A type used to represent the length of a value in 'Size' computations.
newtype LengthOf xs = LengthOf xs

instance Typeable xs => ToCBOR (LengthOf xs) where
  toCBOR = error "The `LengthOf` type cannot be encoded!"

-- | Default size expression for a list type.
defaultEncodedListSizeExpr ::
  forall a.
  ToCBOR a =>
  (forall t. ToCBOR t => Proxy t -> Size) ->
  Proxy [a] ->
  Size
defaultEncodedListSizeExpr size _ =
  2 + size (Proxy @(LengthOf [a])) * size (Proxy @a)

--------------------------------------------------------------------------------
-- Size expressions
--------------------------------------------------------------------------------

(.:) :: (c -> d) -> (a -> b -> c) -> (a -> b -> d)
f .: g = \x y -> f (g x y)

-- | Expressions describing the statically-computed size bounds on
--   a type's possible values.
type Size = Fix SizeF

-- | The base functor for @Size@ expressions.
data SizeF t
  = -- | Sum of two sizes.
    AddF t t
  | -- | Product of two sizes.
    MulF t t
  | -- | Difference of two sizes.
    SubF t t
  | -- | Absolute value of a size.
    AbsF t
  | -- | Negation of a size.
    NegF t
  | -- | Signum of a size.
    SgnF t
  | -- | Case-selection for sizes. Used for sum types.
    CasesF [Case t]
  | -- | A constant value.
    ValueF Natural
  | -- | Application of a monotonic function to a size.
    ApF Text (Natural -> Natural) t
  | -- | A suspended size calculation ("thunk"). This is used to delay the
    --   computation of a size until some later point, which is useful for
    --   progressively building more detailed size estimates for a type
    --   from the outside in. For example, `szLazy` can be followed by
    --   applications of `szForce` to reveal more detailed expressions
    --   describing the size bounds on a type.
    forall a. ToCBOR a => TodoF (forall x. ToCBOR x => Proxy x -> Size) (Proxy a)

instance Functor SizeF where
  fmap f = \case
    AddF x y -> AddF (f x) (f y)
    MulF x y -> MulF (f x) (f y)
    SubF x y -> SubF (f x) (f y)
    AbsF x -> AbsF (f x)
    NegF x -> NegF (f x)
    SgnF x -> SgnF (f x)
    CasesF xs -> CasesF (map (fmap f) xs)
    ValueF x -> ValueF x
    ApF n g x -> ApF n g (f x)
    TodoF g x -> TodoF g x

instance Num (Fix SizeF) where
  (+) = Fix .: AddF
  (*) = Fix .: MulF
  (-) = Fix .: SubF
  negate = Fix . NegF
  abs = Fix . AbsF
  signum = Fix . SgnF
  fromInteger = Fix . ValueF . fromInteger

instance B.Buildable t => B.Buildable (SizeF t) where
  build x_ =
    let
      showp2 :: (B.Buildable a, B.Buildable b) => a -> Text -> b -> Builder
      showp2 = bprint ("(" . build . " " . stext . " " . build . ")")
     in
      case x_ of
        AddF x y -> showp2 x "+" y
        MulF x y -> showp2 x "*" y
        SubF x y -> showp2 x "-" y
        NegF x -> bprint ("-" . build) x
        AbsF x -> bprint ("|" . build . "|") x
        SgnF x -> bprint ("sgn(" . build . ")") x
        CasesF xs ->
          bprint ("{ " . build . "}") $ foldMap (bprint (build . " ")) xs
        ValueF x -> bprint shown (toInteger x)
        ApF n _ x -> bprint (stext . "(" . build . ")") n x
        TodoF _ x -> bprint ("(_ :: " . shown . ")") (typeRep x)

instance B.Buildable (Fix SizeF) where
  build x = bprint build (project @(Fix _) x)

-- | Create a case expression from individual cases.
szCases :: [Case Size] -> Size
szCases = Fix . CasesF

-- | An individual labeled case.
data Case t
  = Case Text t
  deriving (Functor)

-- | Discard the label on a case.
caseValue :: Case t -> t
caseValue (Case _ x) = x

instance B.Buildable t => B.Buildable (Case t) where
  build (Case n x) = bprint (stext . "=" . build) n x

-- | A range of values. Should satisfy the invariant @forall x. lo x <= hi x@.
data Range b = Range
  { lo :: b
  , hi :: b
  }

-- | The @Num@ instance for @Range@ uses interval arithmetic. Note that the
--   @signum@ method is not lawful: if the interval @x@ includes 0 in its
--   interior but is not symmetric about 0, then @abs x * signum x /= x@.
instance (Ord b, Num b) => Num (Range b) where
  x + y = Range {lo = lo x + lo y, hi = hi x + hi y}
  x * y =
    let products = [u * v | u <- [lo x, hi x], v <- [lo y, hi y]]
     in Range {lo = minimum products, hi = maximum products}
  x - y = Range {lo = lo x - hi y, hi = hi x - lo y}
  negate x = Range {lo = negate (hi x), hi = negate (lo x)}
  abs x =
    if
      | lo x <= 0 && hi x >= 0 -> Range {lo = 0, hi = max (hi x) (negate $ lo x)}
      | lo x <= 0 && hi x <= 0 -> Range {lo = negate (hi x), hi = negate (lo x)}
      | otherwise -> x
  signum x = Range {lo = signum (lo x), hi = signum (hi x)}
  fromInteger n = Range {lo = fromInteger n, hi = fromInteger n}

instance B.Buildable (Range Natural) where
  build r = bprint (shown . ".." . shown) (toInteger $ lo r) (toInteger $ hi r)

-- | Fully evaluate a size expression by applying the given function to any
--   suspended computations. @szEval g@ effectively turns each "thunk"
--   of the form @TodoF f x@ into @g x@, then evaluates the result.
szEval ::
  (forall t. ToCBOR t => (Proxy t -> Size) -> Proxy t -> Range Natural) ->
  Size ->
  Range Natural
szEval doit = cata $ \case
  AddF x y -> x + y
  MulF x y -> x * y
  SubF x y -> x - y
  NegF x -> negate x
  AbsF x -> abs x
  SgnF x -> signum x
  CasesF xs ->
    Range
      { lo = minimum (map (lo . caseValue) xs)
      , hi = maximum (map (hi . caseValue) xs)
      }
  ValueF x -> Range {lo = x, hi = x}
  ApF _ f x -> Range {lo = f (lo x), hi = f (hi x)}
  TodoF f x -> doit f x

-- | Evaluate the expression lazily, by immediately creating a thunk
--     that will evaluate its contents lazily.
--
-- > ghci> putStrLn $ pretty $ szLazy (Proxy @TxAux)
-- > (_ :: TxAux)
szLazy :: ToCBOR a => (Proxy a -> Size)
szLazy = todo (encodedSizeExpr szLazy)

-- | Evaluate an expression greedily. There may still be thunks in the
--     result, for types that did not provide a custom 'encodedSizeExpr' method
--     in their 'ToCBOR' instance.
--
-- > ghci> putStrLn $ pretty $ szGreedy (Proxy @TxAux)
-- > (0 + { TxAux=(2 + ((0 + (((1 + (2 + ((_ :: LengthOf [TxIn]) * (2 + { TxInUtxo=(2 + ((1 + 34) + { minBound=1 maxBound=5 })) })))) + (2 + ((_ :: LengthOf [TxOut]) * (0 + { TxOut=(2 + ((0 + ((2 + ((2 + withWordSize((((1 + 30) + (_ :: Attributes AddrAttributes)) + 1))) + (((1 + 30) + (_ :: Attributes AddrAttributes)) + 1))) + { minBound=1 maxBound=5 })) + { minBound=1 maxBound=9 })) })))) + (_ :: Attributes ()))) + (_ :: Vector TxInWitness))) })
szGreedy :: ToCBOR a => (Proxy a -> Size)
szGreedy = encodedSizeExpr szGreedy

-- | Is this expression a thunk?
isTodo :: Size -> Bool
isTodo (Fix (TodoF _ _)) = True
isTodo _ = False

-- | Create a "thunk" that will apply @f@ to @pxy@ when forced.
todo ::
  forall a.
  ToCBOR a =>
  (forall t. ToCBOR t => Proxy t -> Size) ->
  Proxy a ->
  Size
todo f pxy = Fix (TodoF f pxy)

-- | Apply a monotonically increasing function to the expression.
--   There are three cases when applying @f@ to a @Size@ expression:
--      * When applied to a value @x@, compute @f x@.
--      * When applied to cases, apply to each case individually.
--      * In all other cases, create a deferred application of @f@.
apMono :: Text -> (Natural -> Natural) -> Size -> Size
apMono n f = \case
  Fix (ValueF x) -> Fix (ValueF (f x))
  Fix (CasesF cs) -> Fix (CasesF (map (fmap (apMono n f)) cs))
  x -> Fix (ApF n f x)

-- | Greedily compute the size bounds for a type, using the given context to
--   override sizes for specific types.
szWithCtx :: ToCBOR a => M.Map TypeRep SizeOverride -> Proxy a -> Size
szWithCtx ctx pxy = case M.lookup (typeRep pxy) ctx of
  Nothing -> normal
  Just override -> case override of
    SizeConstant sz -> sz
    SizeExpression f -> f (szWithCtx ctx)
    SelectCases names -> cata (selectCase names) normal
  where
    -- The non-override case
    normal = encodedSizeExpr (szWithCtx ctx) pxy

    selectCase :: [Text] -> SizeF Size -> Size
    selectCase names orig = case orig of
      CasesF cs -> matchCase names cs (Fix orig)
      _ -> Fix orig

    matchCase :: [Text] -> [Case Size] -> Size -> Size
    matchCase names cs orig =
      case filter (\(Case name _) -> name `elem` names) cs of
        [] -> orig
        [Case _ x] -> x
        cs' -> Fix (CasesF cs')

-- | Override mechanisms to be used with 'szWithCtx'.
data SizeOverride
  = -- | Replace with a fixed @Size@.
    SizeConstant Size
  | -- | Recursively compute the size.
    SizeExpression ((forall a. ToCBOR a => Proxy a -> Size) -> Size)
  | -- | Select only a specific case from a @CasesF@.
    SelectCases [Text]

-- | Simplify the given @Size@, resulting in either the simplified @Size@ or,
--   if it was fully simplified, an explicit upper and lower bound.
szSimplify :: Size -> Either Size (Range Natural)
szSimplify = cata $ \case
  TodoF f pxy -> Left (todo f pxy)
  ValueF x -> Right (Range {lo = x, hi = x})
  CasesF xs -> case mapM caseValue xs of
    Right xs' ->
      Right (Range {lo = minimum (map lo xs'), hi = maximum (map hi xs')})
    Left _ -> Left (szCases $ map (fmap toSize) xs)
  AddF x y -> binOp (+) x y
  MulF x y -> binOp (*) x y
  SubF x y -> binOp (-) x y
  NegF x -> unOp negate x
  AbsF x -> unOp abs x
  SgnF x -> unOp signum x
  ApF _ f (Right x) -> Right (Range {lo = f (lo x), hi = f (hi x)})
  ApF n f (Left x) -> Left (apMono n f x)
  where
    binOp ::
      (forall a. Num a => a -> a -> a) ->
      Either Size (Range Natural) ->
      Either Size (Range Natural) ->
      Either Size (Range Natural)
    binOp op (Right x) (Right y) = Right (op x y)
    binOp op x y = Left (op (toSize x) (toSize y))

    unOp ::
      (forall a. Num a => a -> a) ->
      Either Size (Range Natural) ->
      Either Size (Range Natural)
    unOp f = \case
      Right x -> Right (f x)
      Left x -> Left (f x)

    toSize :: Either Size (Range Natural) -> Size
    toSize = \case
      Left x -> x
      Right r ->
        if lo r == hi r
          then fromIntegral (lo r)
          else
            szCases
              [Case "lo" (fromIntegral $ lo r), Case "hi" (fromIntegral $ hi r)]

-- | Force any thunks in the given @Size@ expression.
--
-- > ghci> putStrLn $ pretty $ szForce $ szLazy (Proxy @TxAux)
-- > (0 + { TxAux=(2 + ((0 + (_ :: Tx)) + (_ :: Vector TxInWitness))) })
szForce :: Size -> Size
szForce = cata $ \case
  AddF x y -> x + y
  MulF x y -> x * y
  SubF x y -> x - y
  NegF x -> negate x
  AbsF x -> abs x
  SgnF x -> signum x
  CasesF xs -> Fix $ CasesF xs
  ValueF x -> Fix (ValueF x)
  ApF n f x -> apMono n f x
  TodoF f x -> f x

szBounds :: ToCBOR a => a -> Either Size (Range Natural)
szBounds = szSimplify . szGreedy . pure

-- | Compute encoded size of an integer
withWordSize :: (Integral s, Integral a) => s -> a
withWordSize x =
  let s = fromIntegral x :: Integer
   in if
        | s <= 0x17 && s >= (-0x18) -> 1
        | s <= 0xff && s >= (-0x100) -> 2
        | s <= 0xffff && s >= (-0x10000) -> 3
        | s <= 0xffffffff && s >= (-0x100000000) -> 5
        | otherwise -> 9

instance ToCBOR Encoding where
  toCBOR = id

instance ToCBOR (Tokens -> Tokens) where
  toCBOR = Encoding

instance ToCBOR Term where
  toCBOR = encodeTerm

--------------------------------------------------------------------------------
-- Primitive types
--------------------------------------------------------------------------------

instance ToCBOR () where
  toCBOR = const E.encodeNull
  encodedSizeExpr _ _ = 1

instance ToCBOR Bool where
  toCBOR = E.encodeBool
  encodedSizeExpr _ _ = 1

--------------------------------------------------------------------------------
-- Numeric data
--------------------------------------------------------------------------------

instance ToCBOR Integer where
  toCBOR = E.encodeInteger

encodedSizeRange :: forall a. (Integral a, Bounded a) => Proxy a -> Size
encodedSizeRange _ =
  szCases
    [ mkCase "minBound" 0 -- min, in absolute value
    , mkCase "maxBound" maxBound
    ]
  where
    mkCase :: Text -> a -> Case Size
    mkCase n x = Case n (fromIntegral $ (withWordSize :: a -> Integer) x)

instance ToCBOR Word where
  toCBOR = E.encodeWord
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Word8 where
  toCBOR = E.encodeWord8
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Word16 where
  toCBOR = E.encodeWord16
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Word32 where
  toCBOR = E.encodeWord32
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Word64 where
  toCBOR = E.encodeWord64
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Int where
  toCBOR = E.encodeInt
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Int32 where
  toCBOR = E.encodeInt32
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Int64 where
  toCBOR = E.encodeInt64
  encodedSizeExpr _ = encodedSizeRange

instance ToCBOR Float where
  toCBOR = E.encodeFloat
  encodedSizeExpr _ _ = 1 + fromIntegral (sizeOf (0 :: Float))

instance ToCBOR Double where
  toCBOR = E.encodeDouble
  encodedSizeExpr _ _ = 1 + fromIntegral (sizeOf (0 :: Double))

instance ToCBOR a => ToCBOR (Ratio a) where
  toCBOR r = E.encodeListLen 2 <> toCBOR (numerator r) <> toCBOR (denominator r)
  encodedSizeExpr size _ = 1 + size (Proxy @a) + size (Proxy @a)

instance Typeable a => ToCBOR (Fixed a) where
  toCBOR (MkFixed i) = toCBOR i

encodeNominalDiffTime :: NominalDiffTime -> Encoding
encodeNominalDiffTime = toCBOR . nominalDiffTimeToSeconds

-- | Same as `encodeNominalDiffTime`, except with loss of precision, because it encoded as
-- `Data.Fixed.Micro`
encodeNominalDiffTimeMicro :: NominalDiffTime -> Encoding
encodeNominalDiffTimeMicro = toCBOR . realToFrac @_ @Micro

instance ToCBOR Natural where
  toCBOR = toCBOR . toInteger

instance ToCBOR Void where
  toCBOR = absurd

--------------------------------------------------------------------------------
-- Tagged
--------------------------------------------------------------------------------

instance (Typeable s, ToCBOR a) => ToCBOR (Tagged s a) where
  toCBOR (Tagged a) = toCBOR a
  encodedSizeExpr size _ = encodedSizeExpr size (Proxy @a)

--------------------------------------------------------------------------------
-- Containers
--------------------------------------------------------------------------------

instance (ToCBOR a, ToCBOR b) => ToCBOR (a, b) where
  toCBOR (a, b) = E.encodeListLen 2 <> toCBOR a <> toCBOR b

  encodedSizeExpr size _ = 1 + size (Proxy @a) + size (Proxy @b)

instance (ToCBOR a, ToCBOR b, ToCBOR c) => ToCBOR (a, b, c) where
  toCBOR (a, b, c) = E.encodeListLen 3 <> toCBOR a <> toCBOR b <> toCBOR c

  encodedSizeExpr size _ =
    1 + size (Proxy @a) + size (Proxy @b) + size (Proxy @c)

instance (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d) => ToCBOR (a, b, c, d) where
  toCBOR (a, b, c, d) =
    E.encodeListLen 4 <> toCBOR a <> toCBOR b <> toCBOR c <> toCBOR d

  encodedSizeExpr size _ =
    1 + size (Proxy @a) + size (Proxy @b) + size (Proxy @c) + size (Proxy @d)

instance
  (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d, ToCBOR e) =>
  ToCBOR (a, b, c, d, e)
  where
  toCBOR (a, b, c, d, e) =
    E.encodeListLen 5
      <> toCBOR a
      <> toCBOR b
      <> toCBOR c
      <> toCBOR d
      <> toCBOR e

  encodedSizeExpr size _ =
    1
      + size (Proxy @a)
      + size (Proxy @b)
      + size (Proxy @c)
      + size (Proxy @d)
      + size (Proxy @e)

instance
  (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d, ToCBOR e, ToCBOR f) =>
  ToCBOR (a, b, c, d, e, f)
  where
  toCBOR (a, b, c, d, e, f) =
    E.encodeListLen 6
      <> toCBOR a
      <> toCBOR b
      <> toCBOR c
      <> toCBOR d
      <> toCBOR e
      <> toCBOR f

  encodedSizeExpr size _ =
    1
      + size (Proxy @a)
      + size (Proxy @b)
      + size (Proxy @c)
      + size (Proxy @d)
      + size (Proxy @e)
      + size (Proxy @f)

instance
  (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d, ToCBOR e, ToCBOR f, ToCBOR g) =>
  ToCBOR (a, b, c, d, e, f, g)
  where
  toCBOR (a, b, c, d, e, f, g) =
    E.encodeListLen 7
      <> toCBOR a
      <> toCBOR b
      <> toCBOR c
      <> toCBOR d
      <> toCBOR e
      <> toCBOR f
      <> toCBOR g

  encodedSizeExpr size _ =
    1
      + size (Proxy @a)
      + size (Proxy @b)
      + size (Proxy @c)
      + size (Proxy @d)
      + size (Proxy @e)
      + size (Proxy @f)
      + size (Proxy @g)

instance
  (ToCBOR a, ToCBOR b, ToCBOR c, ToCBOR d, ToCBOR e, ToCBOR f, ToCBOR g, ToCBOR h) =>
  ToCBOR (a, b, c, d, e, f, g, h)
  where
  toCBOR (a, b, c, d, e, f, g, h) =
    E.encodeListLen 8
      <> toCBOR a
      <> toCBOR b
      <> toCBOR c
      <> toCBOR d
      <> toCBOR e
      <> toCBOR f
      <> toCBOR g
      <> toCBOR h

  encodedSizeExpr size _ =
    1
      + size (Proxy @a)
      + size (Proxy @b)
      + size (Proxy @c)
      + size (Proxy @d)
      + size (Proxy @e)
      + size (Proxy @f)
      + size (Proxy @g)
      + size (Proxy @h)

instance ToCBOR BS.ByteString where
  toCBOR = E.encodeBytes
  encodedSizeExpr size _ =
    let len = size (Proxy @(LengthOf BS.ByteString))
     in apMono "withWordSize@Int" (withWordSize @Int . fromIntegral) len + len

instance ToCBOR Text.Text where
  toCBOR = E.encodeString
  encodedSizeExpr size _ =
    let
      bsLength =
        size (Proxy @(LengthOf Text))
          * szCases [Case "minChar" 1, Case "maxChar" 4]
     in
      bsLength + apMono "withWordSize" withWordSize bsLength

instance ToCBOR BA.ByteArray where
  toCBOR cborgByteArray@(BA.BA ba) =
    E.encodeByteArray $ BAS.SBA ba 0 (BA.sizeofByteArray cborgByteArray)

  encodedSizeExpr size _ =
    let len = size (Proxy @(LengthOf BA.ByteArray))
     in apMono "withWordSize@Int" (withWordSize @Int . fromIntegral) len + len

deriving via BA.ByteArray instance ToCBOR ByteArray

-- TODO: Once support for GHC-9.6.7 is dropped, this can use newtype deriving:
-- deriving via ByteArray instance ToCBOR ShortByteString
instance ToCBOR SBS.ShortByteString where
  toCBOR sbs@(SBS ba) =
    E.encodeByteArray $ BAS.SBA (Prim.ByteArray ba) 0 (SBS.length sbs)

  encodedSizeExpr size _ =
    let len = size (Proxy @(LengthOf SBS.ShortByteString))
     in apMono "withWordSize@Int" (withWordSize @Int . fromIntegral) len + len

instance ToCBOR BS.Lazy.ByteString where
  toCBOR = toCBOR . BS.Lazy.toStrict
  encodedSizeExpr size _ =
    let len = size (Proxy @(LengthOf BS.Lazy.ByteString))
     in apMono "withWordSize@Int" (withWordSize @Int . fromIntegral) len + len

instance ToCBOR a => ToCBOR [a] where
  toCBOR xs = E.encodeListLenIndef <> foldr (\x r -> toCBOR x <> r) E.encodeBreak xs
  encodedSizeExpr size _ = encodedListSizeExpr size (Proxy @[a])

instance (ToCBOR a, ToCBOR b) => ToCBOR (Either a b) where
  toCBOR (Left x) = E.encodeListLen 2 <> E.encodeWord 0 <> toCBOR x
  toCBOR (Right x) = E.encodeListLen 2 <> E.encodeWord 1 <> toCBOR x

  encodedSizeExpr size _ =
    szCases
      [Case "Left" (2 + size (Proxy @a)), Case "Right" (2 + size (Proxy @b))]

instance ToCBOR a => ToCBOR (NonEmpty a) where
  toCBOR = toCBOR . toList
  encodedSizeExpr size _ = size (Proxy @[a]) -- MN TODO make 0 count impossible

instance ToCBOR a => ToCBOR (Maybe a) where
  toCBOR = encodeMaybe toCBOR

  encodedSizeExpr size _ =
    szCases [Case "Nothing" 1, Case "Just" (1 + size (Proxy @a))]

instance ToCBOR a => ToCBOR (Seq.Seq a) where
  toCBOR = encodeSeq toCBOR

encodeSeq :: (a -> Encoding) -> Seq.Seq a -> Encoding
encodeSeq encValue f = variableListLenEncoding (Seq.length f) (foldMap' encValue f)
{-# INLINE encodeSeq #-}

exactListLenEncoding :: Int -> Encoding -> Encoding
exactListLenEncoding len contents =
  encodeListLen (fromIntegral len :: Word) <> contents
{-# INLINE exactListLenEncoding #-}

-- | Conditionally use variable length encoding for list like structures with length
-- larger than 23, otherwise use exact list length encoding.
variableListLenEncoding ::
  -- | Number of elements in the encoded data structure.
  Int ->
  -- | Encoding for the actual data structure
  Encoding ->
  Encoding
variableListLenEncoding len contents =
  if len <= lengthThreshold
    then exactListLenEncoding len contents
    else encodeListLenIndef <> contents <> encodeBreak
  where
    lengthThreshold = 23
{-# INLINE variableListLenEncoding #-}

encodeMaybe :: (a -> Encoding) -> Maybe a -> Encoding
encodeMaybe encodeA = \case
  Nothing -> E.encodeListLen 0
  Just x -> E.encodeListLen 1 <> encodeA x

toCBORMaybe :: (a -> Encoding) -> Maybe a -> Encoding
toCBORMaybe = encodeMaybe
{-# DEPRECATED toCBORMaybe "In favor of `encodeMaybe`" #-}

-- | Alternative way to encode a Maybe type.
--
-- /Note/ - this is not the default method for encoding `Maybe`, use `encodeMaybe` instead
encodeNullMaybe :: (a -> Encoding) -> Maybe a -> Encoding
encodeNullMaybe encodeValue = \case
  Nothing -> encodeNull
  Just x -> encodeValue x

encodeContainerSkel ::
  (Word -> E.Encoding) ->
  (container -> Int) ->
  (accumFunc -> E.Encoding -> container -> E.Encoding) ->
  accumFunc ->
  container ->
  E.Encoding
encodeContainerSkel encodeLen size foldFunction f c =
  encodeLen (fromIntegral (size c)) <> foldFunction f mempty c
{-# INLINE encodeContainerSkel #-}

encodeMapSkel ::
  (ToCBOR k, ToCBOR v) =>
  (m -> Int) ->
  ((k -> v -> E.Encoding -> E.Encoding) -> E.Encoding -> m -> E.Encoding) ->
  m ->
  E.Encoding
encodeMapSkel size foldrWithKey =
  encodeContainerSkel
    E.encodeMapLen
    size
    foldrWithKey
    (\k v b -> toCBOR k <> toCBOR v <> b)
{-# INLINE encodeMapSkel #-}

instance (Ord k, ToCBOR k, ToCBOR v) => ToCBOR (M.Map k v) where
  toCBOR = encodeMapSkel M.size M.foldrWithKey

encodeSetSkel ::
  ToCBOR a =>
  (s -> Int) ->
  ((a -> E.Encoding -> E.Encoding) -> E.Encoding -> s -> E.Encoding) ->
  s ->
  E.Encoding
encodeSetSkel size foldFunction =
  mappend encodeSetTag
    . encodeContainerSkel
      E.encodeListLen
      size
      foldFunction
      (\a b -> toCBOR a <> b)
{-# INLINE encodeSetSkel #-}

-- We stitch a `258` in from of a (Hash)Set, so that tools which
-- programmatically check for canonicity can recognise it from a normal
-- array. Why 258? This will be formalised pretty soon, but IANA allocated
-- 256...18446744073709551615 to "First come, first served":
-- https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml Currently `258` is
-- the first unassigned tag and as it requires 2 bytes to be encoded, it sounds
-- like the best fit.
setTag :: Word
setTag = 258

encodeSetTag :: E.Encoding
encodeSetTag = E.encodeTag setTag

instance (Ord a, ToCBOR a) => ToCBOR (S.Set a) where
  toCBOR = encodeSetSkel S.size S.foldr

-- | Generic encoder for vectors. Its intended use is to allow easy
-- definition of 'Serialise' instances for custom vector
encodeVector :: (ToCBOR a, Vector.Generic.Vector v a) => v a -> E.Encoding
encodeVector =
  encodeContainerSkel
    E.encodeListLen
    Vector.Generic.length
    Vector.Generic.foldr
    (\a b -> toCBOR a <> b)
{-# INLINE encodeVector #-}

instance ToCBOR a => ToCBOR (Vector.Vector a) where
  toCBOR = encodeVector
  {-# INLINE toCBOR #-}
  encodedSizeExpr size _ =
    2 + size (Proxy @(LengthOf (Vector.Vector a))) * size (Proxy @a)

--------------------------------------------------------------------------------
-- Time
--------------------------------------------------------------------------------

instance ToCBOR UTCTime where
  toCBOR (UTCTime day timeOfDay) =
    mconcat
      [ encodeListLen 3
      , encodeInteger year
      , encodeInt dayOfYear
      , encodeInteger timeOfDayPico
      ]
    where
      (year, dayOfYear) = toOrdinalDate day
      timeOfDayPico = diffTimeToPicoseconds timeOfDay
