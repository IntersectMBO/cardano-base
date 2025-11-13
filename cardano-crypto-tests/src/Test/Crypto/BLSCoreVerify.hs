{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Test.Crypto.BLSCoreVerify (
  tests,
) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal (
  BLSTError (..),
  CoreVerifyOrder,
  Curve1,
  Curve2,
  PublicKey (..),
  Signature (..),
  blsKeyGen,
  blsSignatureVerify,
  blsSignatureVerifyCore,
  blsSign,
  blsSkToPk,
  publicKeyToCompressedBS,
 )

tests :: TestTree
tests =
  testGroup
    "BLS core verify equivalence"
    [ testCurve (Proxy @Curve1) "Curve1 (MinPk)"
    , testCurve (Proxy @Curve2) "Curve2 (MinSig)"
    ]

testCurve ::
  forall curve.
  (CoreCurve curve) =>
  Proxy curve ->
  String ->
  TestTree
testCurve _ label =
  testGroup
    label
    [ testCase "matching signatures agree" $
        mapM_ (runVector (compareGood (Proxy @curve))) vectors
    , testCase "wrong message agrees" $
        mapM_ (runVector (compareWrongMsg (Proxy @curve))) vectors
    , testCase "wrong public key agrees" $
        mapM_ (runVector (compareWrongKey (Proxy @curve))) vectors
    , testCase "wrong dst agrees" $
        mapM_ (runVector (compareWrongDst (Proxy @curve))) vectors
    , testCase "wrong aug agrees" $
        mapM_ (runVector (compareWrongAug (Proxy @curve))) vectors
    , testCase "Nothing vs empty context" $
        mapM_ (runVector (compareEmptyContext (Proxy @curve))) vectors
    , testCase "Explicit vs implicit default dst" $
        mapM_ (runVector (compareExplicitDst (Proxy @curve))) vectors
    ]
  where
    runVector action vec = action vec

vectors :: [TestVector]
vectors =
  [ TestVector seed1 (bs "message-one") Nothing Nothing
  , TestVector seed2 BS.empty (Just dstDefault) Nothing
  , TestVector seed3 longMsg (Just dstDefault) (Just (bs "role=vote"))
  ]
  where
    seed1 = bs "seed-000000000000000000000000000001"
    seed2 = bs "seed-000000000000000000000000000002"
    seed3 = bs "seed-000000000000000000000000000003"
    longMsg = BS.replicate 4096 0x42 -- 4KB message
    bs = BS8.pack

dstDefault :: ByteString
dstDefault = BS8.pack "BLS_DST_CARDANO_BASE_V1"

data TestVector = TestVector
  { tvSeed :: ByteString
  , tvMsg :: ByteString
  , tvDst :: Maybe ByteString
  , tvAug :: Maybe ByteString
  }

compareGood ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareGood _ vec = do
  (pk, sig) <- signVector (Proxy @curve) vec
  let pairing = blsSignatureVerify pk (tvMsg vec) sig (tvDst vec) (tvAug vec)
      core = blsSignatureVerifyCore pk (tvMsg vec) sig (tvDst vec) (tvAug vec)
  assertEqual "pairing/core disagree on valid signature" pairing core
  assertBool "valid signature unexpectedly rejected" pairing

compareWrongMsg ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareWrongMsg _ vec = do
  (pk, sig) <- signVector (Proxy @curve) vec
  let wrongMsg = tvMsg vec <> BS8.pack "-tampered"
  let pairing = blsSignatureVerify pk wrongMsg sig (tvDst vec) (tvAug vec)
      core = blsSignatureVerifyCore pk wrongMsg sig (tvDst vec) (tvAug vec)
  assertEqual "pairing/core mismatch on wrong message" pairing core
  assertBool "wrong message unexpectedly accepted" (not pairing)

compareWrongKey ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareWrongKey _ vec = do
  (_, sig) <- signVector (Proxy @curve) vec
  let otherSeed = BS8.pack "seed-ffffffffffffffffffffffffffffffff"
      otherSk = expectRight (blsKeyGen otherSeed Nothing)
      otherPk = blsSkToPk otherSk
  let pairing = blsSignatureVerify otherPk (tvMsg vec) sig (tvDst vec) (tvAug vec)
      core = blsSignatureVerifyCore otherPk (tvMsg vec) sig (tvDst vec) (tvAug vec)
  assertEqual "pairing/core mismatch on wrong key" pairing core
  assertBool "wrong key unexpectedly accepted" (not pairing)

compareWrongDst ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareWrongDst _ vec = do
  (pk, sig) <- signVector (Proxy @curve) vec
  let wrongDst = Just (BS8.pack "NON_DEFAULT_DST")
  let pairing = blsSignatureVerify pk (tvMsg vec) sig wrongDst (tvAug vec)
      core = blsSignatureVerifyCore pk (tvMsg vec) sig wrongDst (tvAug vec)
  assertEqual "pairing/core mismatch on wrong dst" pairing core
  assertBool "wrong dst unexpectedly accepted" (not pairing)

compareWrongAug ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareWrongAug _ vec = do
  (pk, sig) <- signVector (Proxy @curve) vec
  let wrongAug = Just (maybe (BS8.pack "role=wrong") (<> BS8.pack "_alt") (tvAug vec))
  let pairing = blsSignatureVerify pk (tvMsg vec) sig (tvDst vec) wrongAug
      core = blsSignatureVerifyCore pk (tvMsg vec) sig (tvDst vec) wrongAug
  assertEqual "pairing/core mismatch on wrong aug" pairing core
  assertBool "wrong aug unexpectedly accepted" (not pairing)

compareEmptyContext ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareEmptyContext _ vec = do
  (pk, sig) <- signVector (Proxy @curve) vec
  let ctxs =
        [ (Nothing, Nothing)
        , (Nothing, Just mempty)
        , (Just mempty, Nothing)
        , (Just mempty, Just mempty)
        ]
  mapM_
    ( \(dstCtx, augCtx) -> do
        let pairing = blsSignatureVerify pk (tvMsg vec) sig dstCtx augCtx
            core = blsSignatureVerifyCore pk (tvMsg vec) sig dstCtx augCtx
        assertEqual "pairing/core mismatch on empty context" pairing core
    )
    ctxs

compareExplicitDst ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO ()
compareExplicitDst _ vec = do
  let aug = tvAug vec
  (pkImplicit, sigImplicit) <- signVectorWith (Proxy @curve) vec Nothing aug
  (pkExplicit, sigExplicit) <- signVectorWith (Proxy @curve) vec (Just dstDefault) aug
  assertBool
    "pk differs between implicit/explicit DST"
    (publicKeyToCompressedBS pkImplicit == publicKeyToCompressedBS pkExplicit)
  let contexts =
        [ (pkImplicit, sigImplicit, Nothing, aug)
        , (pkExplicit, sigImplicit, Nothing, aug)
        , (pkImplicit, sigExplicit, Just dstDefault, aug)
        , (pkExplicit, sigExplicit, Just dstDefault, aug)
        ]
  mapM_
    ( \(pk, sig, dstCtx, augCtx) -> do
        let pairing = blsSignatureVerify pk (tvMsg vec) sig dstCtx augCtx
            core = blsSignatureVerifyCore pk (tvMsg vec) sig dstCtx augCtx
        assertEqual "pairing/core mismatch on explicit dst" pairing core
    )
    contexts

signVector ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  IO (PublicKey curve, Signature curve)
signVector proxy vec =
  signVectorWith proxy vec (tvDst vec) (tvAug vec)

signVectorWith ::
  forall curve.
  CoreCurve curve =>
  Proxy curve ->
  TestVector ->
  Maybe ByteString ->
  Maybe ByteString ->
  IO (PublicKey curve, Signature curve)
signVectorWith _ vec dst aug = do
  let sk = expectRight (blsKeyGen (tvSeed vec) Nothing)
      pk = blsSkToPk sk
      sig = blsSign (curveProxy @curve) sk (tvMsg vec) dst aug
  pure (pk, sig)

expectRight :: Either BLSTError a -> a
expectRight = either (error . ("BLS keygen failed: " <>) . show) id

class CoreVerifyOrder curve => CoreCurve curve where
  curveProxy :: Proxy curve

instance CoreCurve Curve1 where
  curveProxy = Proxy

instance CoreCurve Curve2 where
  curveProxy = Proxy
