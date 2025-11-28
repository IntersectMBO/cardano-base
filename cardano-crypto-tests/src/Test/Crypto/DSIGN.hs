{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{- FOURMOLU_DISABLE -}
module Test.Crypto.DSIGN
  ( tests
  )
where

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

import Test.QuickCheck (
  (=/=),
  (===),
  (==>),
  Arbitrary(..),
  Gen,
  Property,
  Testable,
  forAll,
  forAllShow,
  forAllShrinkShow,
  ioProperty,
  counterexample,
  conjoin,
  property,
  )
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckTests)
import Test.Tasty.HUnit (testCase, assertFailure, (@?=))

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Base16 as Base16
import Cardano.Crypto.Libsodium
import Cardano.Crypto.Seed (mkSeedFromBytes)

import Text.Show.Pretty (ppShow)

#ifdef SECP256K1_ENABLED
import Control.Monad (replicateM)
import qualified GHC.Exts as GHC
#endif

import qualified Test.QuickCheck.Gen as Gen
import Control.Monad (forM, forM_, when, guard)
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Data.Maybe (fromJust, mapMaybe)
import Data.List (stripPrefix, sortOn)
import Data.Char (isDigit)
import qualified Data.Map.Strict as Map
import Paths_cardano_crypto_tests (getDataFileName)
import Text.Read (readMaybe)

import Control.Exception (evaluate, bracket)

import Cardano.Crypto.DSIGN (
  MockDSIGN,
  Ed25519DSIGN,
  Ed448DSIGN,
  DSIGNAlgorithm (
    SeedSizeDSIGN,
    VerKeyDSIGN,
    SignKeyDSIGN,
    SigDSIGN,
    ContextDSIGN,
    Signable,
    rawSerialiseVerKeyDSIGN,
    rawDeserialiseVerKeyDSIGN,
    rawSerialiseSignKeyDSIGN,
    rawDeserialiseSignKeyDSIGN,
    rawSerialiseSigDSIGN,
    rawDeserialiseSigDSIGN
    ),
  sizeVerKeyDSIGN,
  sizeSignKeyDSIGN,
  sizeSigDSIGN,
  encodeVerKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSignKeyDSIGN,
  decodeSignKeyDSIGN,
  encodeSigDSIGN,
  decodeSigDSIGN,
  signDSIGN,
  verifyDSIGN,
  genKeyDSIGN,
  seedSizeDSIGN,

  DSIGNMAlgorithm (SignKeyDSIGNM, deriveVerKeyDSIGNM),
  UnsoundDSIGNMAlgorithm,
  rawSerialiseSignKeyDSIGNM,
  rawDeserialiseSignKeyDSIGNM,
  signDSIGNM,
  deriveVerKeyDSIGN,
  genKeyDSIGNM,

  getSeedDSIGNM,
  forgetSignKeyDSIGNM
  )
import Cardano.Crypto.DSIGN.BLS12381MinPk (BLS12381MinPkDSIGN, PopDSIGN)
import qualified Cardano.Crypto.DSIGN.BLS12381MinPk as BLSMinPk
import Cardano.Crypto.DSIGN.BLS12381MinSig (BLS12381MinSigDSIGN)
import qualified Cardano.Crypto.DSIGN.BLS12381MinSig as BLSMinSig
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS
import Cardano.Binary (FromCBOR, ToCBOR)
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)
import Cardano.Crypto.DirectSerialise
import Test.Crypto.Util (
  Lock,
  Message (..),
  arbitrarySeedOfSize,
  directDeserialiseFromBS,
  directSerialiseToBS,
  genBadInputFor,
  hexBS,
  prop_cbor,
  prop_cbor_direct_vs_class,
  prop_cbor_size,
  prop_cbor_with,
  prop_no_thunks,
  prop_no_thunks_IO,
  prop_raw_deserialise,
  prop_raw_serialise,
  prop_size_serialise,
  shrinkBadInputFor,
  showBadInputFor,
  withLock,
  )
import Cardano.Crypto.Libsodium.MLockedSeed

import Test.Crypto.Instances (withMLockedSeedFromPSB)
import Test.Crypto.EqST (EqST (..), (==!))

#ifdef SECP256K1_ENABLED
import Cardano.Crypto.DSIGN (
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
  MessageHash,
  toMessageHash,
  hashAndPack,
  )
import Cardano.Crypto.SECP256K1.Constants (SECP256K1_ECDSA_MESSAGE_BYTES)
import GHC.TypeLits (natVal)
import Cardano.Crypto.Hash (SHA3_256, HashAlgorithm (SizeHash), Blake2b_256, SHA256, Keccak256)
#endif

mockSigGen :: Gen (SigDSIGN MockDSIGN)
mockSigGen = defaultSigGen

ed25519SigGen :: Gen (SigDSIGN Ed25519DSIGN)
ed25519SigGen = defaultSigGen

ed448SigGen :: Gen (SigDSIGN Ed448DSIGN)
ed448SigGen = defaultSigGen

blsMinPkSigGen :: Gen (SigDSIGN BLS12381MinPkDSIGN)
blsMinPkSigGen = defaultSigGenWithCtx (Nothing, Nothing)

blsMinSigSigGen :: Gen (SigDSIGN BLS12381MinSigDSIGN)
blsMinSigSigGen = defaultSigGenWithCtx (Nothing, Nothing)

blsPopGen :: Gen PopDSIGN
blsPopGen = do
  sk <- defaultSignKeyGen @BLS12381MinPkDSIGN
  -- PoP derivation uses an empty augmentation; the vk bytes show up only in the
  -- message portion of the proof.
  let pin = BS.empty
      ctx = blsCtxDefault
  pure (BLSMinPk.derivePopDSIGN ctx sk pin)

#ifdef SECP256K1_ENABLED
ecdsaSigGen :: Gen (SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaSigGen = do
  msg <- genEcdsaMsg
  signDSIGN () msg <$> defaultSignKeyGen

schnorrSigGen :: Gen (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSigGen = defaultSigGen

genEcdsaMsg :: Gen MessageHash
genEcdsaMsg =
  Gen.suchThatMap (GHC.fromListN 32 <$> replicateM 32 arbitrary)
                  toMessageHash
#endif

defaultVerKeyGen :: forall (a :: Type) .
  (DSIGNAlgorithm a) => Gen (VerKeyDSIGN a)
defaultVerKeyGen = deriveVerKeyDSIGN <$> defaultSignKeyGen @a

defaultSignKeyGen :: forall (a :: Type).
  (DSIGNAlgorithm a) => Gen (SignKeyDSIGN a)
defaultSignKeyGen =
  genKeyDSIGN <$> arbitrarySeedOfSize (seedSizeDSIGN (Proxy :: Proxy a))

defaultSigGenWithCtx ::
  forall (a :: Type) .
  (DSIGNAlgorithm a, Signable a Message) =>
  ContextDSIGN a ->
  Gen (SigDSIGN a)
defaultSigGenWithCtx ctx = do
  msg :: Message <- arbitrary
  signDSIGN ctx msg <$> defaultSignKeyGen

defaultSigGen ::
  forall (a :: Type) .
  (DSIGNAlgorithm a, ContextDSIGN a ~ (), Signable a Message) =>
  Gen (SigDSIGN a)
defaultSigGen = defaultSigGenWithCtx @a ()

defaultBlsDst :: ByteString
defaultBlsDst = BS8.pack "BLS_DST_CARDANO_BASE_V1"

badBlsDst :: ByteString
badBlsDst = BS8.pack "BLS_DST_CARDANO_BASE_V1_X"

blsAugVote :: ByteString
blsAugVote = BS8.pack "role=vote"

blsAugCert :: ByteString
blsAugCert = BS8.pack "role=cert"

blsTestMessage :: Message
blsTestMessage = Message (BS8.pack "dst-aug-test-message")

blsCtxDefault :: (Maybe ByteString, Maybe ByteString)
blsCtxDefault = (Nothing, Nothing)

blsCtxVote :: (Maybe ByteString, Maybe ByteString)
blsCtxVote = (Just defaultBlsDst, Just blsAugVote)

blsCtxCert :: (Maybe ByteString, Maybe ByteString)
blsCtxCert = (Just defaultBlsDst, Just blsAugCert)

blsCtxWrongDst :: (Maybe ByteString, Maybe ByteString)
blsCtxWrongDst = (Just badBlsDst, Just BS.empty)

data DsignSerdeVector = DsignSerdeVector
  { dsvLabel :: String
  , dsvSeed :: ByteString
  , dsvSk :: ByteString
  , dsvVk :: ByteString
  , dsvSig :: ByteString
  , dsvPop :: ByteString
  }

-- | Deterministic sign/verify vectors with label, key, message and signature.
data DsignSignVector = DsignSignVector
  { dsvLabelSV :: String
  , dsvSkSV :: ByteString
  , dsvMsgSV :: ByteString
  , dsvSigSV :: ByteString
  }

data DsignKeygenVector = DsignKeygenVector
  { dkvLabel :: String
  , dkvSeed :: ByteString
  , dkvSk :: ByteString
  , dkvVk :: ByteString
  }

data DsignPopVector = DsignPopVector
  { dpvLabel :: String
  , dpvSk :: ByteString
  , dpvVk :: ByteString
  , dpvPop :: ByteString
  }

data DsignVkAggregationVector = DsignVkAggregationVector
  { dvavLabel :: String
  , dvavInputs :: [ByteString]
  , dvavAggVk :: ByteString
  }

data DsignSigAggregationSigner = DsignSigAggregationSigner
  { dsasSeed :: ByteString
  , dsasSk :: ByteString
  , dsasVk :: ByteString
  , dsasMsg :: ByteString
  , dsasSig :: ByteString
  }

data DsignSigAggregationVector = DsignSigAggregationVector
  { dsavLabel :: String
  , dsavSharedMsg :: Maybe ByteString
  , dsavSigners :: [DsignSigAggregationSigner]
  , dsavAggSig :: ByteString
  }

loadSerdeVectors :: String -> IO [DsignSerdeVector]
loadSerdeVectors relPath = do
  filename <- getDataFileName relPath
  bytes <- BS.readFile filename
  reverse <$> parseLines (BS8.lines bytes) Nothing []
  where
    decodeLine field value =
      case Base16.decode value of
        Right bs -> pure bs
        Left err ->
          fail $
            "Failed to decode "
              <> field
              <> " in "
              <> relPath
              <> ": "
              <> err

    parseLines [] current acc =
      finalize current acc
    parseLines (raw : rest) current acc =
      let line = BS8.unpack (BS8.filter (/= '\r') raw)
       in if null line
            then parseLines rest current acc
            else case stripPrefix "# case:" line of
              Just lbl ->
                finalize current acc >>= \acc' ->
                  parseLines rest (Just (trim lbl, [])) acc'
              Nothing ->
                case current of
                  Nothing ->
                    fail ("Field without case header in " <> relPath)
                  Just (lbl, fields) ->
                    case break (== '=') line of
                      (name, '=' : val) ->
                        parseLines
                          rest
                          (Just (lbl, (name, BS8.pack val) : fields))
                          acc
                      _ ->
                        fail ("Malformed line in " <> relPath <> ": " <> line)

    finalize Nothing acc = pure acc
    finalize (Just (lbl, fields)) acc = do
      seedBytes <- lookupField "seed" fields
      skBytes <- lookupField "sk" fields
      vkBytes <- lookupField "vk" fields
      sigBytes <- lookupField "sig" fields
      popBytes <- lookupField "pop" fields
      pure $
        DsignSerdeVector
          { dsvLabel = lbl
          , dsvSeed = seedBytes
          , dsvSk = skBytes
          , dsvVk = vkBytes
          , dsvSig = sigBytes
          , dsvPop = popBytes
          }
          : acc

    lookupField name fields =
      case lookup name fields of
        Just val -> decodeLine name val
        Nothing -> fail ("Missing " <> name <> " in case from " <> relPath)

    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

loadSignVectors :: String -> IO [DsignSignVector]
loadSignVectors relPath = do
  filename <- getDataFileName relPath
  bytes <- BS.readFile filename
  reverse <$> parseEntries (BS8.lines bytes) Nothing []
  where
    decodeField field value =
      case Base16.decode value of
        Right bs -> pure bs
        Left err ->
          fail $
            "Failed to decode "
              <> field
              <> " in "
              <> relPath
              <> ": "
              <> err

    parseEntries [] current acc = finalize current acc
    parseEntries (raw : rest) current acc =
      let line = BS8.unpack (BS8.filter (/= '\r') raw)
       in if null line
            then parseEntries rest current acc
            else case stripPrefix "# case:" line of
              Just lbl ->
                finalize current acc >>= \acc' ->
                  parseEntries rest (Just (trim lbl, [])) acc'
              Nothing ->
                case current of
                  Nothing -> fail ("Field without case header in " <> relPath)
                  Just (lbl, fields) ->
                    case break (== '=') line of
                      (name, '=' : val) ->
                        parseEntries
                          rest
                          (Just (lbl, (name, BS8.pack val) : fields))
                          acc
                      _ ->
                        fail ("Malformed line in " <> relPath <> ": " <> line)

    finalize Nothing acc = pure acc
    finalize (Just (lbl, fields)) acc = do
      skBytes <- decodeField "sk" =<< lookupField "sk" fields
      msgBytes <- decodeField "msg" =<< lookupField "msg" fields
      sigBytes <- decodeField "sig" =<< lookupField "sig" fields
      pure
        ( DsignSignVector
            { dsvLabelSV = lbl
            , dsvSkSV = skBytes
            , dsvMsgSV = msgBytes
            , dsvSigSV = sigBytes
            }
            : acc
        )

    lookupField name fields =
      maybe (fail ("Missing " <> name <> " in " <> relPath)) pure (lookup name fields)

    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

loadKeygenVectors :: String -> IO [DsignKeygenVector]
loadKeygenVectors relPath = do
  filename <- getDataFileName relPath
  bytes <- BS.readFile filename
  reverse <$> parseEntries (BS8.lines bytes) Nothing []
  where
    decodeField field value =
      case Base16.decode value of
        Right bs -> pure bs
        Left err ->
          fail $
            "Failed to decode "
              <> field
              <> " in "
              <> relPath
              <> ": "
              <> err

    parseEntries [] current acc = finalize current acc
    parseEntries (raw : rest) current acc =
      let line = BS8.unpack (BS8.filter (/= '\r') raw)
       in if null line
            then parseEntries rest current acc
            else case stripPrefix "# case:" line of
              Just lbl ->
                finalize current acc >>= \acc' ->
                  parseEntries rest (Just (trim lbl, [])) acc'
              Nothing ->
                case current of
                  Nothing -> fail ("Field without case header in " <> relPath)
                  Just (lbl, fields) ->
                    case break (== '=') line of
                      (name, '=' : val) ->
                        parseEntries
                          rest
                          (Just (lbl, (name, BS8.pack val) : fields))
                          acc
                      _ ->
                        fail ("Malformed line in " <> relPath <> ": " <> line)

    finalize Nothing acc = pure acc
    finalize (Just (lbl, fields)) acc = do
      seedBytes <- decodeField "seed" =<< lookupField "seed" fields
      skBytes <- decodeField "sk" =<< lookupField "sk" fields
      vkBytes <- decodeField "vk" =<< lookupField "vk" fields
      pure
        ( DsignKeygenVector
            { dkvLabel = lbl
            , dkvSeed = seedBytes
            , dkvSk = skBytes
            , dkvVk = vkBytes
            }
            : acc
        )

    lookupField name fields =
      maybe (fail ("Missing " <> name <> " in " <> relPath)) pure (lookup name fields)

    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

loadPopVectors :: String -> IO [DsignPopVector]
loadPopVectors relPath = do
  filename <- getDataFileName relPath
  bytes <- BS.readFile filename
  reverse <$> parseEntries (BS8.lines bytes) Nothing []
  where
    decodeField field value =
      case Base16.decode value of
        Right bs -> pure bs
        Left err ->
          fail $
            "Failed to decode "
              <> field
              <> " in "
              <> relPath
              <> ": "
              <> err

    parseEntries [] current acc = finalize current acc
    parseEntries (raw : rest) current acc =
      let line = BS8.unpack (BS8.filter (/= '\r') raw)
       in if null line
            then parseEntries rest current acc
            else case stripPrefix "# case:" line of
              Just lbl ->
                finalize current acc >>= \acc' ->
                  parseEntries rest (Just (trim lbl, [])) acc'
              Nothing ->
                case current of
                  Nothing -> fail ("Field without case header in " <> relPath)
                  Just (lbl, fields) ->
                    case break (== '=') line of
                      (name, '=' : val) ->
                        parseEntries
                          rest
                          (Just (lbl, (name, BS8.pack val) : fields))
                          acc
                      _ ->
                        fail ("Malformed line in " <> relPath <> ": " <> line)

    finalize Nothing acc = pure acc
    finalize (Just (lbl, fields)) acc = do
      skBytes <- decodeField "sk" =<< lookupField "sk" fields
      vkBytes <- decodeField "vk" =<< lookupField "vk" fields
      popBytes <- decodeField "pop" =<< lookupField "pop" fields
      pure
        ( DsignPopVector
            { dpvLabel = lbl
            , dpvSk = skBytes
            , dpvVk = vkBytes
            , dpvPop = popBytes
            }
            : acc
        )

    lookupField name fields =
      maybe (fail ("Missing " <> name <> " in " <> relPath)) pure (lookup name fields)

    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

loadVkAggregationVectors :: String -> IO [DsignVkAggregationVector]
loadVkAggregationVectors relPath = do
  filename <- getDataFileName relPath
  bytes <- BS.readFile filename
  reverse <$> parseEntries (BS8.lines bytes) Nothing []
  where
    decodeField field value =
      case Base16.decode value of
        Right bs -> pure bs
        Left err ->
          fail $
            "Failed to decode "
              <> field
              <> " in "
              <> relPath
              <> ": "
              <> err

    parseEntries [] current acc = finalize current acc
    parseEntries (raw : rest) current acc =
      let line = BS8.unpack (BS8.filter (/= '\r') raw)
       in if null line
            then parseEntries rest current acc
            else case stripPrefix "# case:" line of
              Just lbl ->
                finalize current acc >>= \acc' ->
                  parseEntries rest (Just (trim lbl, [])) acc'
              Nothing ->
                case current of
                  Nothing -> fail ("Field without case header in " <> relPath)
                  Just (lbl, fields) ->
                    case break (== '=') line of
                      (name, '=' : val) ->
                        parseEntries
                          rest
                          (Just (lbl, (name, BS8.pack val) : fields))
                          acc
                      _ ->
                        fail ("Malformed line in " <> relPath <> ": " <> line)

    finalize Nothing acc = pure acc
    finalize (Just (lbl, fields)) acc = do
      aggVkBytes <- decodeField "agg_vk" =<< lookupField "agg_vk" fields
      let vkFieldPairs =
            sortOn fst $
              mapMaybe
                ( \(name, value) -> do
                    suffix <- stripPrefix "vk_" name
                    idx <- readMaybe suffix
                    pure (idx, (name, value))
                )
                fields
      when (null vkFieldPairs) $
        fail ("No vk_i entries found for case " <> lbl <> " in " <> relPath)
      inputVks <-
        mapM
          ( \(idx, (name, value)) -> do
              let fieldName = name
                  -- idx used to ensure decode errors reference the numbered field.
                  _ = idx :: Int
              decodeField fieldName value
          )
          vkFieldPairs
      pure
        ( DsignVkAggregationVector
            { dvavLabel = lbl
            , dvavInputs = inputVks
            , dvavAggVk = aggVkBytes
            }
            : acc
        )

    lookupField name fields =
      maybe (fail ("Missing " <> name <> " in " <> relPath)) pure (lookup name fields)

    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

loadSigAggregationVectors :: String -> IO [DsignSigAggregationVector]
loadSigAggregationVectors relPath = do
  filename <- getDataFileName relPath
  bytes <- BS.readFile filename
  reverse <$> parseEntries (BS8.lines bytes) Nothing []
  where
    decodeField field value =
      case Base16.decode value of
        Right bs -> pure bs
        Left err ->
          fail $
            "Failed to decode "
              <> field
              <> " in "
              <> relPath
              <> ": "
              <> err

    parseEntries [] current acc = finalize current acc
    parseEntries (raw : rest) current acc =
      let line = BS8.unpack (BS8.filter (/= '\r') raw)
       in if null line
            then parseEntries rest current acc
            else case stripPrefix "# case:" line of
              Just lbl ->
                finalize current acc >>= \acc' ->
                  parseEntries rest (Just (trim lbl, [])) acc'
              Nothing ->
                case current of
                  Nothing -> fail ("Field without case header in " <> relPath)
                  Just (lbl, fields) ->
                    case break (== '=') line of
                      (name, '=' : val) ->
                        parseEntries
                          rest
                          (Just (lbl, (name, BS8.pack val) : fields))
                          acc
                      _ ->
                        fail ("Malformed line in " <> relPath <> ": " <> line)

    finalize Nothing acc = pure acc
    finalize (Just (lbl, fields)) acc = do
      aggSigBytes <- decodeField "agg_sig" =<< lookupField "agg_sig" fields
      sharedMsg <-
        case lookup "msg" fields of
          Nothing -> pure Nothing
          Just rawMsg -> Just <$> decodeField "msg" rawMsg
      let signerMap =
            Map.fromListWith (++)
              [ (idx :: Int, [(fieldName, value)])
              | (name, value) <- fields
              , Just (idx, fieldName) <- [parseSignerField name]
              ]
      when (Map.null signerMap) $
        fail ("No signer entries found for case " <> lbl <> " in " <> relPath)
      let sortedSigners = sortOn fst (Map.toList signerMap)
      signers <-
        mapM
          ( \(idx, signerFields) -> do
              seedBytes <-
                decodeField
                  ("signer_" <> show idx <> "_seed")
                  =<< lookupSignerField "seed" signerFields
              skBytes <-
                decodeField
                  ("signer_" <> show idx <> "_sk")
                  =<< lookupSignerField "sk" signerFields
              vkBytes <-
                decodeField
                  ("signer_" <> show idx <> "_vk")
                  =<< lookupSignerField "vk" signerFields
              msgBytes <-
                decodeField
                  ("signer_" <> show idx <> "_msg")
                  =<< lookupSignerField "msg" signerFields
              sigBytes <-
                decodeField
                  ("signer_" <> show idx <> "_sig")
                  =<< lookupSignerField "sig" signerFields
              pure
                DsignSigAggregationSigner
                  { dsasSeed = seedBytes
                  , dsasSk = skBytes
                  , dsasVk = vkBytes
                  , dsasMsg = msgBytes
                  , dsasSig = sigBytes
                  }
          )
          sortedSigners
      pure
        ( DsignSigAggregationVector
            { dsavLabel = lbl
            , dsavSharedMsg = sharedMsg
            , dsavSigners = signers
            , dsavAggSig = aggSigBytes
            }
            : acc
        )

    lookupField name fields =
      maybe (fail ("Missing " <> name <> " in " <> relPath)) pure (lookup name fields)

    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse

    parseSignerField name = do
      rest <- stripPrefix "signer_" name
      let (idxDigits, suffix) = span isDigit rest
      guard (not (null idxDigits))
      guard (all isDigit idxDigits)
      case suffix of
        '_' : fieldName
          | fieldName `elem` ["seed", "sk", "vk", "msg", "sig"] -> do
              idx <- readMaybe idxDigits
              pure (idx :: Int, fieldName)
        _ ->
          Nothing

    lookupSignerField field fields =
      maybe (fail ("Missing signer field " <> field <> " in " <> relPath)) pure (lookup field fields)

assertSkRoundTrip ::
  forall v.
  String ->
  (ByteString -> Maybe (SignKeyDSIGN v)) ->
  (SignKeyDSIGN v -> ByteString) ->
  ByteString ->
  IO ()
assertSkRoundTrip label deser ser bytes = do
  value <- expectJust ("Failed to decode " <> label) (deser bytes)
  ser value @?= bytes

assertVkRoundTrip ::
  forall v.
  String ->
  (ByteString -> Maybe (VerKeyDSIGN v)) ->
  (VerKeyDSIGN v -> ByteString) ->
  ByteString ->
  IO ()
assertVkRoundTrip label deser ser bytes = do
  value <- expectJust ("Failed to decode " <> label) (deser bytes)
  ser value @?= bytes

assertSigRoundTrip ::
  forall v.
  String ->
  (ByteString -> Maybe (SigDSIGN v)) ->
  (SigDSIGN v -> ByteString) ->
  ByteString ->
  IO ()
assertSigRoundTrip label deser ser bytes = do
  value <- expectJust ("Failed to decode " <> label) (deser bytes)
  ser value @?= bytes

assertPopRoundTrip ::
  String ->
  (ByteString -> Maybe pop) ->
  (pop -> ByteString) ->
  ByteString ->
  IO ()
assertPopRoundTrip label deser ser bytes = do
  value <- expectJust ("Failed to decode " <> label) (deser bytes)
  ser value @?= bytes

assertPopGolden ::
  forall v pop.
  ( DSIGNAlgorithm v
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  ) =>
  String ->
  (ByteString -> Maybe pop) ->
  (pop -> ByteString) ->
  (ContextDSIGN v -> SignKeyDSIGN v -> ByteString -> pop) ->
  DsignPopVector ->
  IO ()
assertPopGolden label deser ser derivePop vec = do
  sk <-
    expectJust
      (label <> " failed to decode secret key")
      (rawDeserialiseSignKeyDSIGN @v (dpvSk vec))
  vk <-
    expectJust
      (label <> " failed to decode verification key")
      (rawDeserialiseVerKeyDSIGN @v (dpvVk vec))
  let vkBytes = rawSerialiseVerKeyDSIGN vk
  vkBytes @?= dpvVk vec
  popBytes <- expectJust (label <> " failed to decode pop") (deser (dpvPop vec))
  ser popBytes @?= dpvPop vec
  let derived = derivePop blsCtxDefault sk BS.empty
  ser derived @?= dpvPop vec

expectJust :: String -> Maybe a -> IO a
expectJust msg = maybe (assertFailure msg >> fail msg) pure

-- Used for adjusting number of QuickCheck tests so crypto cases get enough coverage
testEnough :: QuickCheckTests -> QuickCheckTests
testEnough = max 10_000

testBlsDstAug :: TestTree
testBlsDstAug =
  adjustOption testEnough . testGroup
    "DST/AUG behaviour"
    $ [ blsDstAugGroup "BLS12381MinPkDSIGN" (Proxy @BLS12381MinPkDSIGN)
      , blsDstAugGroup "BLS12381MinSigDSIGN" (Proxy @BLS12381MinSigDSIGN)
      ]

testBlsPop :: TestTree
testBlsPop =
  adjustOption testEnough . testGroup
    "BLS Proof of Possession"
    $ [ blsPopSuite
          @BLS12381MinPkDSIGN
          "MinPk PoP"
          BLSMinPk.derivePopDSIGN
          BLSMinPk.verifyPopDSIGN
      , blsPopSuite
          @BLS12381MinSigDSIGN
          "MinSig PoP"
          BLSMinSig.derivePopDSIGN
          BLSMinSig.verifyPopDSIGN
      ]

testBlsPopCbor :: TestTree
testBlsPopCbor =
  adjustOption testEnough . testGroup
    "BLS PoP CBOR"
    $ [ testProperty "CBOR roundtrip" .
          forAllShow blsPopGen ppShow $
            prop_cbor @PopDSIGN
      , testProperty "ToCBOR size" .
          forAllShow blsPopGen ppShow $
            prop_cbor_size @PopDSIGN
      ]

testBlsPopRaw :: TestTree
testBlsPopRaw =
  adjustOption testEnough . testGroup
    "BLS PoP raw"
    $ [ testProperty "raw serialise/deserialise" .
          forAllShow blsPopGen ppShow $
            prop_raw_serialise
              BLSMinPk.rawSerialisePopBLS
              BLSMinPk.rawDeserialisePopBLS
      , testProperty "raw deserialization (wrong length)" .
          forAllShrinkShow
            (genBadInputFor BLSMinPk.popByteLength)
            (shrinkBadInputFor @PopDSIGN)
            showBadInputFor $
            prop_raw_deserialise BLSMinPk.rawDeserialisePopBLS
      ]

testBlsPopGolden :: TestTree
testBlsPopGolden =
  testGroup
    "DSIGN PoP golden vectors"
    [ testCase "MinPk vectors match" $ do
        vectors <-
          loadPopVectors
            "bls12-381-test-vectors/test_vectors/dsign_minpk_pop"
        forM_ vectors $ \vec -> do
          let prefix = "MinPk (" <> dpvLabel vec <> ") "
          assertPopGolden
            @BLS12381MinPkDSIGN
            prefix
            BLSMinPk.rawDeserialisePopBLS
            BLSMinPk.rawSerialisePopBLS
            BLSMinPk.derivePopDSIGN
            vec
    , testCase "MinSig vectors match" $ do
        vectors <-
          loadPopVectors
            "bls12-381-test-vectors/test_vectors/dsign_minsig_pop"
        forM_ vectors $ \vec -> do
          let prefix = "MinSig (" <> dpvLabel vec <> ") "
          assertPopGolden
            @BLS12381MinSigDSIGN
            prefix
            BLSMinSig.rawDeserialisePopBLS
            BLSMinSig.rawSerialisePopBLS
            BLSMinSig.derivePopDSIGN
            vec
    ]

testBlsSerde :: TestTree
testBlsSerde =
  adjustOption testEnough . testGroup
    "BLS DSIGN serde golden"
    $ [ testCase "MinPk vectors round-trip" $ do
          vectors <-
            loadSerdeVectors
              "bls12-381-test-vectors/test_vectors/dsign_minpk_serde"
          forM_ vectors $ \vec -> do
            let prefix = "MinPk (" <> dsvLabel vec <> ") "
            assertSkRoundTrip
              @BLS12381MinPkDSIGN
              (prefix <> "secret key")
              rawDeserialiseSignKeyDSIGN
              rawSerialiseSignKeyDSIGN
              (dsvSk vec)
            assertVkRoundTrip
              @BLS12381MinPkDSIGN
              (prefix <> "verification key")
              rawDeserialiseVerKeyDSIGN
              rawSerialiseVerKeyDSIGN
              (dsvVk vec)
            assertSigRoundTrip
              @BLS12381MinPkDSIGN
              (prefix <> "signature")
              rawDeserialiseSigDSIGN
              rawSerialiseSigDSIGN
              (dsvSig vec)
            assertPopRoundTrip
              (prefix <> "proof of possession")
              BLSMinPk.rawDeserialisePopBLS
              BLSMinPk.rawSerialisePopBLS
              (dsvPop vec)
      , testCase "MinSig vectors round-trip" $ do
          vectors <-
            loadSerdeVectors
              "bls12-381-test-vectors/test_vectors/dsign_minsig_serde"
          forM_ vectors $ \vec -> do
            let prefix = "MinSig (" <> dsvLabel vec <> ") "
            assertSkRoundTrip
              @BLS12381MinSigDSIGN
              (prefix <> "secret key")
              rawDeserialiseSignKeyDSIGN
              rawSerialiseSignKeyDSIGN
              (dsvSk vec)
            assertVkRoundTrip
              @BLS12381MinSigDSIGN
              (prefix <> "verification key")
              rawDeserialiseVerKeyDSIGN
              rawSerialiseVerKeyDSIGN
              (dsvVk vec)
            assertSigRoundTrip
              @BLS12381MinSigDSIGN
              (prefix <> "signature")
              rawDeserialiseSigDSIGN
              rawSerialiseSigDSIGN
              (dsvSig vec)
            assertPopRoundTrip
              (prefix <> "proof of possession")
              BLSMinSig.rawDeserialisePopBLS
              BLSMinSig.rawSerialisePopBLS
              (dsvPop vec)
      ]

testBlsSignVerify :: TestTree
testBlsSignVerify =
  adjustOption testEnough . testGroup
    "BLS DSIGN sign/verify golden"
    $ [ testCase "MinPk vectors verify" $ do
          vectors <-
            loadSignVectors
              "bls12-381-test-vectors/test_vectors/dsign_minpk_sign_verify"
          forM_ vectors $
            assertSignVector
              (Proxy @BLS12381MinPkDSIGN)
              "MinPk"
      , testCase "MinSig vectors verify" $ do
          vectors <-
            loadSignVectors
              "bls12-381-test-vectors/test_vectors/dsign_minsig_sign_verify"
          forM_ vectors $
            assertSignVector
              (Proxy @BLS12381MinSigDSIGN)
              "MinSig"
      ]
  where
    assertSignVector ::
      forall v.
      ( DSIGNAlgorithm v
      , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
      , Signable v Message
      ) =>
      Proxy v ->
      String ->
      DsignSignVector ->
      IO ()
    assertSignVector _ prefix vec = do
      sk <-
        expectJust
          ("Failed to decode " <> prefix <> " (" <> dsvLabelSV vec <> ") secret key")
          (rawDeserialiseSignKeyDSIGN @v (dsvSkSV vec))
      sig <-
        expectJust
          ("Failed to decode " <> prefix <> " (" <> dsvLabelSV vec <> ") signature")
          (rawDeserialiseSigDSIGN @v (dsvSigSV vec))
      let msg = Message (dsvMsgSV vec)
          ctx :: ContextDSIGN v
          ctx = blsCtxDefault
          regenSig = signDSIGN ctx msg sk
      rawSerialiseSigDSIGN sig @?= dsvSigSV vec
      rawSerialiseSigDSIGN regenSig @?= dsvSigSV vec

testBlsVkAggregationGolden :: TestTree
testBlsVkAggregationGolden =
  testGroup
    "BLS DSIGN vk aggregation golden"
    [ testCase "MinPk aggregated vectors match" $ do
        vectors <-
          loadVkAggregationVectors
            "bls12-381-test-vectors/test_vectors/dsign_minpk_vk_aggregation"
        forM_ vectors $
          assertVkAggregationVector
            (Proxy @BLS12381MinPkDSIGN)
            "MinPk"
            BLSMinPk.aggregateVerKeysDSIGN
    , testCase "MinSig aggregated vectors match" $ do
        vectors <-
          loadVkAggregationVectors
            "bls12-381-test-vectors/test_vectors/dsign_minsig_vk_aggregation"
        forM_ vectors $
          assertVkAggregationVector
            (Proxy @BLS12381MinSigDSIGN)
            "MinSig"
            BLSMinSig.aggregateVerKeysDSIGN
    ]

testBlsSigAggregationSameMsgGolden :: TestTree
testBlsSigAggregationSameMsgGolden =
  testGroup
    "BLS DSIGN signature aggregation (same message) golden"
    [ testCase "MinPk aggregated signatures match" $ do
        vectors <-
          loadSigAggregationVectors
            "bls12-381-test-vectors/test_vectors/dsign_minpk_sig_agg_same_msg"
        forM_ vectors $
          assertSigAggregationVector
            (Proxy @BLS12381MinPkDSIGN)
            "MinPk"
            BLSMinPk.aggregateSignaturesSameMsgDSIGN
    , testCase "MinSig aggregated signatures match" $ do
        vectors <-
          loadSigAggregationVectors
            "bls12-381-test-vectors/test_vectors/dsign_minsig_sig_agg_same_msg"
        forM_ vectors $
          assertSigAggregationVector
            (Proxy @BLS12381MinSigDSIGN)
            "MinSig"
            BLSMinSig.aggregateSignaturesSameMsgDSIGN
    ]

testBlsSigAggregationDistinctMsgGolden :: TestTree
testBlsSigAggregationDistinctMsgGolden =
  testGroup
    "BLS DSIGN signature aggregation (distinct messages) golden"
    [ testCase "MinPk aggregated signatures match" $ do
        vectors <-
          loadSigAggregationVectors
            "bls12-381-test-vectors/test_vectors/dsign_minpk_sig_agg_distinct_msg"
        forM_ vectors $
          assertSigAggregationDistinctVector
            (Proxy @BLS12381MinPkDSIGN)
            "MinPk"
            BLSMinPk.aggregateSignaturesSameMsgDSIGN
    , testCase "MinSig aggregated signatures match" $ do
        vectors <-
          loadSigAggregationVectors
            "bls12-381-test-vectors/test_vectors/dsign_minsig_sig_agg_distinct_msg"
        forM_ vectors $
          assertSigAggregationDistinctVector
            (Proxy @BLS12381MinSigDSIGN)
            "MinSig"
            BLSMinSig.aggregateSignaturesSameMsgDSIGN
    ]

assertVkAggregationVector ::
  forall v.
  DSIGNAlgorithm v =>
  Proxy v ->
  String ->
  ([VerKeyDSIGN v] -> Either BLS.BLSTError (VerKeyDSIGN v)) ->
  DsignVkAggregationVector ->
  IO ()
assertVkAggregationVector _ prefix aggregate vec = do
  inputs <-
    mapM
      ( \(idx, vkBytes) ->
          expectJust
            ( "Failed to decode "
                <> prefix
                <> " ("
                <> dvavLabel vec
                <> ") vk_"
                <> show idx
            )
            (rawDeserialiseVerKeyDSIGN @v vkBytes)
      )
      (zip [(1 :: Int) ..] (dvavInputs vec))
  _expectedAgg <-
    expectJust
      ( "Failed to decode "
          <> prefix
          <> " ("
          <> dvavLabel vec
          <> ") agg_vk"
      )
      (rawDeserialiseVerKeyDSIGN @v (dvavAggVk vec))
  aggregated <-
    case aggregate inputs of
      Left err ->
        assertFailure $
          prefix
            <> " ("
            <> dvavLabel vec
            <> ") aggregateVerKeysDSIGN failed: "
            <> show err
        >> fail "aggregateVerKeysDSIGN failed"
      Right vk -> pure vk
  rawSerialiseVerKeyDSIGN aggregated @?= dvavAggVk vec

assertSigAggregationVector ::
  forall v.
  DSIGNAlgorithm v =>
  Proxy v ->
  String ->
  ([SigDSIGN v] -> Either BLS.BLSTError (SigDSIGN v)) ->
  DsignSigAggregationVector ->
  IO ()
assertSigAggregationVector _ prefix aggregate vec = do
  inputs <-
    mapM
      ( \(idx, signer) ->
          expectJust
            ( "Failed to decode "
                <> prefix
                <> " ("
                <> dsavLabel vec
                <> ") sig_"
                <> show idx
            )
            (rawDeserialiseSigDSIGN @v (dsasSig signer))
      )
      (zip [(1 :: Int) ..] (dsavSigners vec))
  _expectedAgg <-
    expectJust
      ( "Failed to decode "
          <> prefix
          <> " ("
          <> dsavLabel vec
          <> ") agg_sig"
      )
      (rawDeserialiseSigDSIGN @v (dsavAggSig vec))
  aggregated <-
    case aggregate inputs of
      Left err ->
        assertFailure $
          prefix
            <> " ("
            <> dsavLabel vec
            <> ") aggregateSignaturesSameMsgDSIGN failed: "
            <> show err
        >> fail "aggregateSignaturesSameMsgDSIGN failed"
      Right sig -> pure sig
  rawSerialiseSigDSIGN aggregated @?= dsavAggSig vec

assertSigAggregationDistinctVector ::
  forall v.
  ( DSIGNAlgorithm v
  , Signable v Message
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  ) =>
  Proxy v ->
  String ->
  ([SigDSIGN v] -> Either BLS.BLSTError (SigDSIGN v)) ->
  DsignSigAggregationVector ->
  IO ()
assertSigAggregationDistinctVector _ prefix aggregate vec = do
  let ctx :: ContextDSIGN v
      ctx = blsCtxDefault
      expectedSeedLength = fromIntegral (seedSizeDSIGN (Proxy @v))
  signerSigs <-
    forM (zip [(1 :: Int) ..] (dsavSigners vec)) $ \(idx, signer) -> do
      when (BS.length (dsasSeed signer) /= expectedSeedLength) $
        assertFailure $
          prefix
            <> " ("
            <> dsavLabel vec
            <> ") signer "
            <> show idx
            <> " seed length mismatch"
      let seed = mkSeedFromBytes (dsasSeed signer)
          sk = genKeyDSIGN @v seed
          vk = deriveVerKeyDSIGN sk
          msg = Message (dsasMsg signer)
          regenSig = signDSIGN ctx msg sk
      rawSerialiseSignKeyDSIGN sk @?= dsasSk signer
      rawSerialiseVerKeyDSIGN vk @?= dsasVk signer
      rawSerialiseSigDSIGN regenSig @?= dsasSig signer
      pure regenSig
  aggregated <-
    case aggregate signerSigs of
      Left err ->
        assertFailure $
          prefix
            <> " ("
            <> dsavLabel vec
            <> ") aggregateSignaturesSameMsgDSIGN failed: "
            <> show err
        >> fail "aggregateSignaturesSameMsgDSIGN failed"
      Right sig -> pure sig
  rawSerialiseSigDSIGN aggregated @?= dsavAggSig vec

testBlsKeygen :: TestTree
testBlsKeygen =
  adjustOption testEnough . testGroup
    "BLS DSIGN keygen golden"
    $ [ testCase "MinPk keygen vectors round-trip" $ do
          vectors <-
            loadKeygenVectors
              "bls12-381-test-vectors/test_vectors/dsign_minpk_keygen"
          forM_ vectors $
            assertKeygenVector
              (Proxy @BLS12381MinPkDSIGN)
              "MinPk"
      , testCase "MinSig keygen vectors round-trip" $ do
          vectors <-
            loadKeygenVectors
              "bls12-381-test-vectors/test_vectors/dsign_minsig_keygen"
          forM_ vectors $
            assertKeygenVector
              (Proxy @BLS12381MinSigDSIGN)
              "MinSig"
      ]
  where
    assertKeygenVector ::
      forall v.
      DSIGNAlgorithm v =>
      Proxy v ->
      String ->
      DsignKeygenVector ->
      IO ()
    assertKeygenVector _ prefix vec = do
      let seedBytes = dkvSeed vec
          expectedSeedLength = fromIntegral (seedSizeDSIGN (Proxy @v))
      when (BS.length seedBytes /= expectedSeedLength) $
        assertFailure $
          prefix
            <> " ("
            <> dkvLabel vec
            <> ") seed length mismatch: got "
            <> show (BS.length seedBytes)
            <> ", expected "
            <> show expectedSeedLength
      let seed = mkSeedFromBytes seedBytes
          sk = genKeyDSIGN @v seed
          vk = deriveVerKeyDSIGN sk
      rawSerialiseSignKeyDSIGN sk @?= dkvSk vec
      rawSerialiseVerKeyDSIGN vk @?= dkvVk vec

testBlsAggregation :: TestTree
testBlsAggregation =
  adjustOption testEnough . testGroup
    "BLS Aggregation"
    $ [ blsAggregationSuite
          @BLS12381MinPkDSIGN
          "BLS12381MinPkDSIGN"
          (Proxy @BLS12381MinPkDSIGN)
          BLSMinPk.aggregateVerKeysDSIGN
          BLSMinPk.aggregateSignaturesSameMsgDSIGN
          BLSMinPk.verifyAggregateSameMsgDSIGN
          BLSMinPk.verifyAggregateDistinctMsgDSIGN
      , blsAggregationSuite
          @BLS12381MinSigDSIGN
          "BLS12381MinSigDSIGN"
          (Proxy @BLS12381MinSigDSIGN)
          BLSMinSig.aggregateVerKeysDSIGN
          BLSMinSig.aggregateSignaturesSameMsgDSIGN
          BLSMinSig.verifyAggregateSameMsgDSIGN
          BLSMinSig.verifyAggregateDistinctMsgDSIGN
      ]

blsAggregationSuite ::
  forall v.
  ( DSIGNAlgorithm v
  , Signable v Message
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  ) =>
  String ->
  Proxy v ->
  ([VerKeyDSIGN v] -> Either BLS.BLSTError (VerKeyDSIGN v)) ->
  ([SigDSIGN v] -> Either BLS.BLSTError (SigDSIGN v)) ->
  (ContextDSIGN v -> [VerKeyDSIGN v] -> ByteString -> SigDSIGN v -> Either BLS.BLSTError Bool) ->
  (ContextDSIGN v -> [(VerKeyDSIGN v, ByteString)] -> SigDSIGN v -> Either BLS.BLSTError Bool) ->
  TestTree
blsAggregationSuite label _ aggregateVks aggregateSigs verifySame verifyDistinct =
  testGroup
    label
    [ testGroup "same message"
        [ testProperty "default context aggregates verify" $
            forAll (genKeyList keyCount) $ \sks ->
              forAll (arbitrary @Message) $ \msg ->
                let ctx = blsCtxDefault
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = fmap (signDSIGN ctx msg) sks
                    msgBytes = messageBytes msg
                 in aggregatePair vks sigs $
                      \(aggVk, aggSig) ->
                        conjoin
                          [ counterexample "verifyDSIGN aggregated key" $
                              verifyDSIGN ctx aggVk msg aggSig === Right ()
                          , counterexample "verifyAggregateSameMsgDSIGN" $
                              verifySame ctx vks msgBytes aggSig === Right True
                          ]
        , testProperty "custom context aggregates verify" $
            forAll (genKeyList keyCount) $ \sks ->
              forAll (arbitrary @Message) $ \msg ->
                let ctx = blsCtxCert
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = fmap (signDSIGN ctx msg) sks
                    msgBytes = messageBytes msg
                 in aggregatePair vks sigs $
                      \(aggVk, aggSig) ->
                        conjoin
                          [ counterexample "verifyDSIGN aggregated key" $
                              verifyDSIGN ctx aggVk msg aggSig === Right ()
                          , counterexample "verifyAggregateSameMsgDSIGN" $
                              verifySame ctx vks msgBytes aggSig === Right True
                          ]
        , testProperty "mismatched context fails" $
            forAll (genKeyList keyCount) $ \sks ->
              forAll (arbitrary @Message) $ \msg ->
                let ctxSign = blsCtxVote
                    ctxVerify = blsCtxDefault
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = fmap (signDSIGN ctxSign msg) sks
                    msgBytes = messageBytes msg
                 in aggregatePair vks sigs $
                      \(_, aggSig) ->
                        counterexample "aggregate verification should reject mismatched context" $
                          verifySame ctxVerify vks msgBytes aggSig =/= Right True
        , testProperty "singleton aggregate behaves like single signer" $
            forAll (Gen.vectorOf 1 (defaultSignKeyGen @v)) $ \sks ->
              forAll (arbitrary @Message) $ \msg ->
                let ctx = blsCtxDefault
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = fmap (signDSIGN ctx msg) sks
                    msgBytes = messageBytes msg
                 in aggregatePair vks sigs $
                      \(aggVk, aggSig) ->
                        conjoin
                          [ counterexample "verifyDSIGN singleton" $
                              verifyDSIGN ctx aggVk msg aggSig === Right ()
                          , counterexample "verifyAggregateSameMsgDSIGN singleton" $
                              verifySame ctx vks msgBytes aggSig === Right True
                          ]
        ]
    , testGroup "distinct messages"
        [ testProperty "distinct aggregates verify" $
            forAll (genKeyList keyCount) $ \sks ->
              forAll (genDistinctMessageList keyCount) $ \msgs ->
                let ctx = blsCtxVote
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = zipWith (signDSIGN ctx) msgs sks
                    msgBytes = fmap messageBytes msgs
                    pairs = zip vks msgBytes
                 in aggregateSigOnly sigs $
                      \aggSig ->
                        conjoin
                          [ counterexample "verifyAggregateDistinctMsgDSIGN" $
                              verifyDistinct ctx pairs aggSig === Right True
                          , counterexample "permuted pairs should also verify" $
                              verifyDistinct ctx (reverse pairs) aggSig === Right True
                          ]
        , testProperty "misaligned pairs fail" $
            forAll (genKeyList keyCount) $ \sks ->
              forAll (genDistinctMessageList keyCount) $ \msgs ->
                let ctx = blsCtxVote
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = zipWith (signDSIGN ctx) msgs sks
                    msgBytes = fmap messageBytes msgs
                    misalignedPairs = zip (rotateLeft vks) msgBytes
                 in aggregateSigOnly sigs $
                      \aggSig ->
                        counterexample "misaligned pairs must reject" $
                          verifyDistinct ctx misalignedPairs aggSig =/= Right True
        , testProperty "context mismatch rejects distinct aggregates" $
            forAll (genKeyList keyCount) $ \sks ->
              forAll (genMessageList keyCount) $ \msgs ->
                let ctxSign = blsCtxCert
                    ctxVerify = blsCtxWrongDst
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = zipWith (signDSIGN ctxSign) msgs sks
                    msgBytes = fmap messageBytes msgs
                    pairs = zip vks msgBytes
                 in aggregateSigOnly sigs $
                      \aggSig ->
                        counterexample "context mismatch must fail" $
                          verifyDistinct ctxVerify pairs aggSig =/= Right True
        , testProperty "singleton distinct aggregate acts like single signature" $
            forAll (Gen.vectorOf 1 (defaultSignKeyGen @v)) $ \sks ->
              forAll (genMessageList 1) $ \msgs ->
                let ctx = blsCtxDefault
                    vks = fmap deriveVerKeyDSIGN sks
                    sigs = zipWith (signDSIGN ctx) msgs sks
                    msgBytes = fmap messageBytes msgs
                    pairs = zip vks msgBytes
                 in aggregateSigOnly sigs $
                      \aggSig ->
                        counterexample "singleton distinct verify" $
                          verifyDistinct ctx pairs aggSig === Right True
        ]
    , testGroup "edge cases"
        [ testProperty "aggregateVerKeysDSIGN rejects empty input" $
            case aggregateVks [] of
              Left _ -> property True
              Right _ -> counterexample "expected Left for empty keys" False
        , testProperty "aggregateSignaturesSameMsgDSIGN rejects empty input" $
            case aggregateSigs [] of
              Left _ -> property True
              Right _ -> counterexample "expected Left for empty signatures" False
        , testProperty "singleton key aggregation preserves encoding" $
            forAll (defaultVerKeyGen @v) $ \vk ->
              expectRightProp "aggregateVerKeysDSIGN" (aggregateVks [vk]) $
                \aggVk ->
                  rawSerialiseVerKeyDSIGN aggVk === rawSerialiseVerKeyDSIGN vk
        , testProperty "singleton signature aggregation preserves encoding" $
            forAll (Gen.vectorOf 1 (defaultSignKeyGen @v)) $ \sks ->
              forAll (arbitrary @Message) $ \msg ->
                let ctx = blsCtxDefault
                    sigs = fmap (signDSIGN ctx msg) sks
                 in case sigs of
                      [] ->
                        counterexample "vectorOf produced empty signature list" False
                      sig0 : _ ->
                        expectRightProp "aggregateSignaturesSameMsgDSIGN" (aggregateSigs sigs) $
                          \aggSig ->
                            rawSerialiseSigDSIGN aggSig === rawSerialiseSigDSIGN sig0
        ]
    ]
  where
    keyCount = 3
    genKeyList n = Gen.vectorOf n (defaultSignKeyGen @v)
    genMessageList n = Gen.vectorOf n (arbitrary @Message)
    genDistinctMessageList n = do
      seedBytes <- arbitrary @[Word8]
      let seed = BS.pack seedBytes
      pure (zipWith makeDistinct [0 .. n - 1] (repeat seed))
      where
        makeDistinct idx prefix =
          let suffix = BS.singleton (fromIntegral idx)
           in Message (prefix <> suffix)
    rotateLeft [] = []
    rotateLeft (x : xs) = xs ++ [x]
    aggregatePair vks sigs k =
      expectRightProp "aggregateVerKeysDSIGN" (aggregateVks vks) $ \aggVk ->
        expectRightProp "aggregateSignaturesSameMsgDSIGN" (aggregateSigs sigs) $ \aggSig ->
          k (aggVk, aggSig)
    aggregateSigOnly sigs k =
      expectRightProp "aggregateSignaturesSameMsgDSIGN" (aggregateSigs sigs) k

expectRightProp ::
  Show e =>
  String ->
  Either e a ->
  (a -> Property) ->
  Property
expectRightProp label val cont =
  case val of
    Left err ->
      counterexample (label <> " failed with " <> show err) False
    Right x ->
      cont x

blsPopSuite ::
  forall v pop.
  ( DSIGNAlgorithm v
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  ) =>
  String ->
  (ContextDSIGN v -> SignKeyDSIGN v -> ByteString -> pop) ->
  (ContextDSIGN v -> VerKeyDSIGN v -> ByteString -> pop -> Bool) ->
  TestTree
blsPopSuite label derivePop verifyPop =
  testGroup
    label
    [ testProperty "happy path" $
        forAll (defaultSignKeyGen @v) $ \sk ->
          let vk = deriveVerKeyDSIGN sk
              pin = BS.empty
              ctx = blsCtxDefault
              pop = derivePop ctx sk pin
           in verifyPop ctx vk pin pop === True
    , testProperty "rejects wrong verification key" $
        forAll (defaultSignKeyGen @v) $ \sk ->
          forAll (defaultSignKeyGen @v) $ \skMismatch ->
            let vk = deriveVerKeyDSIGN sk
                vkMismatch = deriveVerKeyDSIGN skMismatch
                vkBytes = rawSerialiseVerKeyDSIGN vk
                vkMismatchBytes = rawSerialiseVerKeyDSIGN vkMismatch
                pin = BS.empty
                ctx = blsCtxDefault
                pop = derivePop ctx sk pin
             in vkMismatchBytes /= vkBytes ==> verifyPop ctx vkMismatch pin pop === False
    , testProperty "rejects wrong pin bytes" $
        forAll (defaultSignKeyGen @v) $ \sk ->
          let vk = deriveVerKeyDSIGN sk
              pin = BS.empty
              badPin = BS.singleton 0x00
              ctx = blsCtxDefault
              pop = derivePop ctx sk pin
           in verifyPop ctx vk badPin pop === False
    ]

blsDstAugGroup ::
  forall v.
  ( DSIGNAlgorithm v
  , Signable v Message
  , ContextDSIGN v ~ (Maybe ByteString, Maybe ByteString)
  ) =>
  String ->
  Proxy v ->
  TestTree
blsDstAugGroup label _ =
  testGroup
    label
    [ testProperty "dst default equivalence" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sigDefault = signDSIGN ctxDefault msg sk
              sigExplicit = signDSIGN ctxExplicitDst msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "default context should verify"
                    (verifyDSIGN ctxDefault vk msg sigDefault === Right ())
                , counterexample "explicit default DST should verify"
                    (verifyDSIGN ctxExplicitDst vk msg sigExplicit === Right ())
                , counterexample "signatures should match when DST defaults"
                    (sigDefault === sigExplicit)
                ]
    , testProperty "aug empty equivalence" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sigNothing = signDSIGN ctxExplicitDst msg sk
              sigEmpty = signDSIGN ctxExplicitEmptyAug msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "aug Nothing should verify"
                    (verifyDSIGN ctxExplicitDst vk msg sigNothing === Right ())
                , counterexample "aug empty string should verify"
                    (verifyDSIGN ctxExplicitEmptyAug vk msg sigEmpty === Right ())
                , counterexample "signatures should match when AUG defaults"
                    (sigNothing === sigEmpty)
                ]
    , testProperty "verify fails on wrong dst" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sig = signDSIGN ctxExplicitEmptyAug msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "control context should verify"
                    (verifyDSIGN ctxExplicitEmptyAug vk msg sig === Right ())
                , counterexample "verification should fail with wrong DST"
                    (verifyDSIGN ctxWrongDst vk msg sig =/= Right ())
                ]
    , testProperty "verify fails on wrong aug" $
        forAllShow (defaultSignKeyGen @v) ppShow $ \sk ->
          let msg = blsTestMessage
              sig = signDSIGN ctxVote msg sk
              vk = deriveVerKeyDSIGN sk
           in conjoin
                [ counterexample "control context should verify"
                    (verifyDSIGN ctxVote vk msg sig === Right ())
                , counterexample "verification should fail with wrong AUG"
                    (verifyDSIGN ctxCert vk msg sig =/= Right ())
                ]
    ]
  where
    ctxDefault = (Nothing, Nothing)
    ctxExplicitDst = (Just defaultBlsDst, Nothing)
    ctxExplicitEmptyAug = (Just defaultBlsDst, Just BS.empty)
    ctxWrongDst = (Just badBlsDst, Just BS.empty)
    ctxVote = (Just defaultBlsDst, Just blsAugVote)
    ctxCert = (Just defaultBlsDst, Just blsAugCert)

#ifdef SECP256K1_ENABLED
-- Used for adjusting no of quick check tests
-- By default up to 100 tests are performed which may not be enough to catch hidden bugs
defaultTestEnough :: QuickCheckTests -> QuickCheckTests
defaultTestEnough = testEnough
#endif

{- HLINT ignore "Use <$>" -}
{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: Lock -> TestTree
tests lock =
  testGroup "Crypto.DSIGN"
    [ testGroup "Pure"
      [ testDSIGNAlgorithm () mockSigGen (arbitrary @Message) "MockDSIGN"
      , testDSIGNAlgorithm () ed25519SigGen (arbitrary @Message) "Ed25519DSIGN"
      , testDSIGNAlgorithm () ed448SigGen (arbitrary @Message) "Ed448DSIGN"
      , testDSIGNAlgorithm (Nothing, Nothing) blsMinPkSigGen (arbitrary @Message) "BLS12381MinPkDSIGN"
      , testDSIGNAlgorithm (Nothing, Nothing) blsMinSigSigGen (arbitrary @Message) "BLS12381MinSigDSIGN"
      -- Specific tests related only to BLS12-381
      , testBlsDstAug
      , testBlsPop
      , testBlsPopGolden
      , testBlsSerde
      , testBlsKeygen
      , testBlsSignVerify
      , testBlsVkAggregationGolden
      , testBlsSigAggregationSameMsgGolden
      , testBlsSigAggregationDistinctMsgGolden
      , testBlsAggregation
      , testBlsPopCbor
      , testBlsPopRaw
#ifdef SECP256K1_ENABLED
      , testDSIGNAlgorithm () ecdsaSigGen genEcdsaMsg "EcdsaSecp256k1DSIGN"
      , testDSIGNAlgorithm () schnorrSigGen (arbitrary @Message) "SchnorrSecp256k1DSIGN"
      -- Specific tests related only to ecdsa
      , testEcdsaInvalidMessageHash "EcdsaSecp256k1InvalidMessageHash"
      , testEcdsaWithHashAlgorithm (Proxy @SHA3_256) "EcdsaSecp256k1WithSHA3_256"
      , testEcdsaWithHashAlgorithm (Proxy @Blake2b_256) "EcdsaSecp256k1WithBlake2b_256"
      , testEcdsaWithHashAlgorithm (Proxy @SHA256) "EcdsaSecp256k1WithSHA256"
      , testEcdsaWithHashAlgorithm (Proxy @Keccak256) "EcdsaSecp256k1WithKeccak256"
#endif
      ]
    , testGroup "MLocked"
      [ testDSIGNMAlgorithm lock (Proxy @Ed25519DSIGN) "Ed25519DSIGN"
      ]
    ]

testDSIGNAlgorithm :: forall (v :: Type) (a :: Type).
  (DSIGNAlgorithm v,
   Signable v a,
   Show a,
   Eq (SignKeyDSIGN v),
   Eq a,
   ToCBOR (VerKeyDSIGN v),
   FromCBOR (VerKeyDSIGN v),
   ToCBOR (SignKeyDSIGN v),
   FromCBOR (SignKeyDSIGN v),
   ToCBOR (SigDSIGN v),
   FromCBOR (SigDSIGN v)) =>
  ContextDSIGN v ->
  Gen (SigDSIGN v) ->
  Gen a ->
  String ->
  TestTree
testDSIGNAlgorithm ctx genSig genMsg name = adjustOption testEnough . testGroup name $ [
  testGroup "serialization" [
    testGroup "raw" [
      testProperty "VerKey serialization" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_raw_serialise rawSerialiseVerKeyDSIGN rawDeserialiseVerKeyDSIGN,
      testProperty "VerKey deserialization (wrong length)" .
        forAllShrinkShow (genBadInputFor . expectedVKLen $ expected)
                         (shrinkBadInputFor @(VerKeyDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseVerKeyDSIGN,
      testProperty "SignKey serialization" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_raw_serialise rawSerialiseSignKeyDSIGN rawDeserialiseSignKeyDSIGN,
      testProperty "SignKey deserialization (wrong length)" .
        forAllShrinkShow (genBadInputFor . expectedSKLen $ expected)
                         (shrinkBadInputFor @(SignKeyDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseSignKeyDSIGN,
      testProperty "Sig serialization" .
        forAllShow genSig
                   ppShow $
                   prop_raw_serialise rawSerialiseSigDSIGN rawDeserialiseSigDSIGN,
      testProperty "Sig deserialization (wrong length)" .
        forAllShrinkShow (genBadInputFor . expectedSigLen $ expected)
                         (shrinkBadInputFor @(SigDSIGN v))
                         showBadInputFor $
                         prop_raw_deserialise rawDeserialiseSigDSIGN
      ],
    testGroup "size" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_size_serialise rawSerialiseVerKeyDSIGN (sizeVerKeyDSIGN (Proxy @v)),
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_size_serialise rawSerialiseSignKeyDSIGN (sizeSignKeyDSIGN (Proxy @v)),
      testProperty "Sig" .
        forAllShow genSig
                   ppShow $
                   prop_size_serialise rawSerialiseSigDSIGN (sizeSigDSIGN (Proxy @v))
      ],
    testGroup "direct CBOR" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v)
                   ppShow $
                   prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN,
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v)
                   ppShow $
                   prop_cbor_with encodeSignKeyDSIGN decodeSignKeyDSIGN,
      testProperty "Sig" .
        forAllShow genSig
                   ppShow $
                   prop_cbor_with encodeSigDSIGN decodeSigDSIGN
      ],
    testGroup "To/FromCBOR class" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_cbor
      ],
    testGroup "ToCBOR size" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_cbor_size,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_cbor_size,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_cbor_size
      ],
    testGroup "direct matches class" [
      testProperty "VerKey" .
        forAllShow (defaultVerKeyGen @v) ppShow $
        prop_cbor_direct_vs_class encodeVerKeyDSIGN,
      testProperty "SignKey" .
        forAllShow (defaultSignKeyGen @v) ppShow $
        prop_cbor_direct_vs_class encodeSignKeyDSIGN,
      testProperty "Sig" .
        forAllShow genSig ppShow $
        prop_cbor_direct_vs_class encodeSigDSIGN
      ]
    ],
    testGroup "verify" [
      testProperty "signing and verifying with matching keys" .
        forAllShow ((,) <$> genMsg <*> defaultSignKeyGen @v) ppShow $
        prop_dsign_verify ctx,
      testProperty "verifying with wrong key" .
        forAllShow genWrongKey ppShow $
        prop_dsign_verify_wrong_key ctx,
      testProperty "verifying wrong message" .
        forAllShow genWrongMsg ppShow $
        prop_dsign_verify_wrong_msg ctx
    ],
    testGroup "NoThunks" [
      testProperty "VerKey" . forAllShow (defaultVerKeyGen @v) ppShow $ prop_no_thunks,
      testProperty "SignKey" . forAllShow (defaultSignKeyGen @v) ppShow $ prop_no_thunks,
      testProperty "Sig" . forAllShow genSig ppShow $ prop_no_thunks,
      testProperty "VerKey rawSerialise" . forAllShow (defaultVerKeyGen @v) ppShow $ \vk ->
        prop_no_thunks (rawSerialiseVerKeyDSIGN vk),
      testProperty "VerKey rawDeserialise" . forAllShow (defaultVerKeyGen @v) ppShow $ \vk ->
        prop_no_thunks (fromJust $! rawDeserialiseVerKeyDSIGN @v . rawSerialiseVerKeyDSIGN $ vk)
    ]
  ]
  where
    expected :: ExpectedLengths v
    expected = defaultExpected
    genWrongKey :: Gen (a, SignKeyDSIGN v, SignKeyDSIGN v)
    genWrongKey = do
      sk1 <- defaultSignKeyGen
      sk2 <- Gen.suchThat defaultSignKeyGen (/= sk1)
      msg <- genMsg
      pure (msg, sk1, sk2)
    genWrongMsg :: Gen (a, a, SignKeyDSIGN v)
    genWrongMsg = do
      msg1 <- genMsg
      msg2 <- Gen.suchThat genMsg (/= msg1)
      sk <- defaultSignKeyGen
      pure (msg1, msg2, sk)

testDSIGNMAlgorithm
  :: forall v. ( -- change back to DSIGNMAlgorithm when unsound API is phased out
                 UnsoundDSIGNMAlgorithm v
               , ToCBOR (VerKeyDSIGN v)
               , FromCBOR (VerKeyDSIGN v)
               -- DSIGNM cannot satisfy To/FromCBOR (not even with
               -- UnsoundDSIGNMAlgorithm), because those typeclasses assume
               -- that a non-monadic encoding/decoding exists. Hence, we only
               -- test direct encoding/decoding for 'SignKeyDSIGNM'.
               -- , ToCBOR (SignKeyDSIGNM v)
               -- , FromCBOR (SignKeyDSIGNM v)
               , EqST (SignKeyDSIGNM v)   -- only monadic EqST for signing keys
               , ToCBOR (SigDSIGN v)
               , FromCBOR (SigDSIGN v)
               , ContextDSIGN v ~ ()
               , Signable v Message
               , DirectSerialise (SignKeyDSIGNM v)
               , DirectDeserialise (SignKeyDSIGNM v)
               , DirectSerialise (VerKeyDSIGN v)
               , DirectDeserialise (VerKeyDSIGN v)
               )
  => Lock
  -> Proxy v
  -> String
  -> TestTree
testDSIGNMAlgorithm lock _ n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (rawDeserialiseVerKeyDSIGN . rawSerialiseVerKeyDSIGN $ vk) === Just vk
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              bracket
                (rawDeserialiseSignKeyDSIGNM serialized)
                (maybe (return ()) forgetSignKeyDSIGNM)
                (\msk' -> Just sk ==! msk')
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig <- signDSIGNM () msg sk
              return $ (rawDeserialiseSigDSIGN . rawSerialiseSigDSIGN $ sig) === Just sig
        ]
      , testGroup "size"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk <- deriveVerKeyDSIGNM sk
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyDSIGN $ vk) === sizeVerKeyDSIGN (Proxy @v)
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyDSIGNM sk
              evaluate ((fromIntegral . BS.length $ serialized) == sizeSignKeyDSIGN (Proxy @v))
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ (fromIntegral . BS.length . rawSerialiseSigDSIGN $ sig) === sizeSigDSIGN (Proxy @v)
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_with encodeVerKeyDSIGN decodeVerKeyDSIGN vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) -> do
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_with encodeSigDSIGN decodeSigDSIGN sig
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor sig
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyDSIGNM', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_size sig
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              return $ prop_cbor_direct_vs_class encodeVerKeyDSIGN vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigDSIGN v <- signDSIGNM () msg sk
              return $ prop_cbor_direct_vs_class encodeSigDSIGN sig
        ]
      , testGroup "DirectSerialise"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              serialized <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
              vk' <- directDeserialiseFromBS serialized
              return $ vk === vk'
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
              sk' <- directDeserialiseFromBS serialized
              equals <- sk ==! sk'
              forgetSignKeyDSIGNM sk'
              return $
                counterexample ("Serialized: " ++ hexBS serialized ++ " (length: " ++ show (BS.length serialized) ++ ")") $
                equals
        ]
      , testGroup "DirectSerialise matches raw"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyDSIGN v <- deriveVerKeyDSIGNM sk
              direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
              let raw = rawSerialiseVerKeyDSIGN vk
              return $ direct === raw
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
              raw <- rawSerialiseSignKeyDSIGNM sk
              return $ direct === raw
        ]
      ]

    , testGroup "verify"
      [ testProperty "verify positive" $
          prop_dsignm_verify_pos lock (Proxy @v)
      , testProperty "verify negative (wrong key)" $
          prop_dsignm_verify_neg_key lock (Proxy @v)
      , testProperty "verify negative (wrong message)" $
          prop_dsignm_verify_neg_msg lock (Proxy @v)
      ]

    , testGroup "seed extraction"
      [ testProperty "extracted seed equals original seed" $ prop_dsignm_seed_roundtrip (Proxy @v)
      ]

    , testGroup "forgetting"
      [ testProperty "key overwritten after forget" $ prop_key_overwritten_after_forget (Proxy @v)
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> prop_no_thunks_IO (deriveVerKeyDSIGNM sk)
      , testProperty "SignKey" $
          ioPropertyWithSK @v lock $ prop_no_thunks_IO . return
      , testProperty "Sig"     $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ prop_no_thunks_IO . signDSIGNM () msg
      , testProperty "SignKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
            prop_no_thunks_IO (return $! direct)
      , testProperty "SignKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyDSIGN (Proxy @v)) sk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(SignKeyDSIGNM v) $! direct)
      , testProperty "VerKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk <- deriveVerKeyDSIGNM sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
            prop_no_thunks_IO (return $! direct)
      , testProperty "VerKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk <- deriveVerKeyDSIGNM sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyDSIGN (Proxy @v)) vk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(VerKeyDSIGN v) $! direct)
      ]
    ]

-- | Wrap an IO action that requires a 'SignKeyDSIGNM' into one that takes an
-- mlocked seed to generate the key from. The key is bracketed off to ensure
-- timely forgetting. Special care must be taken to not leak the key outside of
-- the wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
withSK :: (DSIGNMAlgorithm v) => PinnedSizedBytes (SeedSizeDSIGN v) -> (SignKeyDSIGNM v -> IO b) -> IO b
withSK seedPSB action =
  withMLockedSeedFromPSB seedPSB $ \seed ->
    bracket
      (genKeyDSIGNM seed)
      forgetSignKeyDSIGNM
      action

-- | Wrap an IO action that requires a 'SignKeyDSIGNM' into a 'Property' that
-- takes a non-mlocked seed (provided as a 'PinnedSizedBytes' of the
-- appropriate size). The key, and the mlocked seed necessary to generate it,
-- are bracketed off, to ensure timely forgetting and avoid leaking mlocked
-- memory. Special care must be taken to not leak the key outside of the
-- wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
ioPropertyWithSK :: forall v a. (Testable a, DSIGNMAlgorithm v)
                 => Lock
                 -> (SignKeyDSIGNM v -> IO a)
                 -> PinnedSizedBytes (SeedSizeDSIGN v)
                 -> Property
ioPropertyWithSK lock action seedPSB =
  ioProperty . withLock lock $ withSK seedPSB action

prop_key_overwritten_after_forget
  :: forall v.
     (DSIGNMAlgorithm v
     )
  => Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_key_overwritten_after_forget p seedPSB =
  ioProperty . withMLockedSeedFromPSB seedPSB $ \seed -> do
    sk <- genKeyDSIGNM seed
    mlockedSeedFinalize seed

    seedBefore <- getSeedDSIGNM p sk
    bsBefore <- mlsbToByteString . mlockedSeedMLSB $ seedBefore
    mlockedSeedFinalize seedBefore

    forgetSignKeyDSIGNM sk

    seedAfter <- getSeedDSIGNM p sk
    bsAfter <- mlsbToByteString . mlockedSeedMLSB $ seedAfter
    mlockedSeedFinalize seedAfter

    return (bsBefore =/= bsAfter)

prop_dsignm_seed_roundtrip
  :: forall v.
     ( DSIGNMAlgorithm v
     )
  => Proxy v
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_seed_roundtrip p seedPSB = ioProperty . withMLockedSeedFromPSB seedPSB $ \seed -> do
  sk <- genKeyDSIGNM seed
  seed' <- getSeedDSIGNM p sk
  bs <- mlsbToByteString . mlockedSeedMLSB $ seed
  bs' <- mlsbToByteString . mlockedSeedMLSB $ seed'
  forgetSignKeyDSIGNM sk
  mlockedSeedFinalize seed'
  return (bs === bs')

-- If we sign a message with the key, we can verify the signature with the
-- corresponding verification key.
prop_dsign_verify ::
  forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  (a, SignKeyDSIGN v) ->
  Property
prop_dsign_verify ctx (msg, sk) =
  let signed = signDSIGN ctx msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN ctx vk msg signed === Right ()

-- If we sign a message with one key, and try to verify with another, then
-- verification fails.
prop_dsign_verify_wrong_key ::
  forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  (a, SignKeyDSIGN v, SignKeyDSIGN v) ->
  Property
prop_dsign_verify_wrong_key ctx (msg, sk, sk') =
  let signed = signDSIGN ctx msg sk
      vk' = deriveVerKeyDSIGN sk'
    in verifyDSIGN ctx vk' msg signed =/= Right ()

prop_dsignm_verify_pos
  :: forall v. (DSIGNMAlgorithm v, ContextDSIGN v ~ (), Signable v Message)
  => Lock
  -> Proxy v
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_verify_pos lock _ msg =
  ioPropertyWithSK @v lock $ \sk -> do
    sig <- signDSIGNM () msg sk
    vk <- deriveVerKeyDSIGNM sk
    return $ verifyDSIGN () vk msg sig === Right ()

-- | If we sign a message @a@ with one signing key, if we try to verify the
-- signature (and message @a@) using a verification key corresponding to a
-- different signing key, then the verification fails.
--
prop_dsignm_verify_neg_key
  :: forall v. (DSIGNMAlgorithm v, ContextDSIGN v ~ (), Signable v Message)
  => Lock
  -> Proxy v
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_verify_neg_key lock _ msg seedPSB seedPSB' =
  ioProperty . withLock lock $ do
    sig <- withSK @v seedPSB $ signDSIGNM () msg
    vk' <- withSK @v seedPSB' deriveVerKeyDSIGNM
    return $
      seedPSB /= seedPSB' ==> verifyDSIGN () vk' msg sig =/= Right ()

-- If we sign a message with a key, but then try to verify with a different
-- message, then verification fails.
prop_dsign_verify_wrong_msg ::
  forall (v :: Type) (a :: Type) .
  (DSIGNAlgorithm v, Signable v a) =>
  ContextDSIGN v ->
  (a, a, SignKeyDSIGN v) ->
  Property
prop_dsign_verify_wrong_msg ctx (msg, msg', sk) =
  let signed = signDSIGN ctx msg sk
      vk = deriveVerKeyDSIGN sk
    in verifyDSIGN ctx vk msg' signed =/= Right ()

data ExpectedLengths (v :: Type) =
  ExpectedLengths {
    expectedVKLen :: Int,
    expectedSKLen :: Int,
    expectedSigLen :: Int
    }

defaultExpected ::
  forall (v :: Type) .
  (DSIGNAlgorithm v) =>
  ExpectedLengths v
defaultExpected = ExpectedLengths {
  expectedVKLen = fromIntegral . sizeVerKeyDSIGN $ Proxy @v,
  expectedSKLen = fromIntegral . sizeSignKeyDSIGN $ Proxy @v,
  expectedSigLen = fromIntegral . sizeSigDSIGN $ Proxy @v
  }

#ifdef SECP256K1_ENABLED
testEcdsaInvalidMessageHash :: String -> TestTree
testEcdsaInvalidMessageHash name = adjustOption defaultTestEnough . testGroup name $ [
    testProperty "MessageHash deserialization (wrong length)" .
      forAllShrinkShow (genBadInputFor expectedMHLen)
                       (shrinkBadInputFor @MessageHash)
                       showBadInputFor $ prop_raw_deserialise toMessageHash
  ]
  where
    expectedMHLen :: Int
    expectedMHLen = fromIntegral $ natVal $ Proxy @SECP256K1_ECDSA_MESSAGE_BYTES

testEcdsaWithHashAlgorithm ::
  forall (h :: Type).
  (HashAlgorithm h, SizeHash h ~ SECP256K1_ECDSA_MESSAGE_BYTES) =>
  Proxy h -> String -> TestTree
testEcdsaWithHashAlgorithm _ name = adjustOption defaultTestEnough . testGroup name $ [
    testProperty "Ecdsa sign and verify" .
    forAllShow ((,) <$> genMsg <*> defaultSignKeyGen @EcdsaSecp256k1DSIGN) ppShow $
      prop_dsign_verify ()
  ]
  where
    genMsg :: Gen MessageHash
    genMsg = hashAndPack (Proxy @h) . messageBytes <$> arbitrary
#endif

prop_dsignm_verify_neg_msg
  :: forall v. (DSIGNMAlgorithm v, ContextDSIGN v ~ (), Signable v Message)
  => Lock
  -> Proxy v
  -> Message
  -> Message
  -> PinnedSizedBytes (SeedSizeDSIGN v)
  -> Property
prop_dsignm_verify_neg_msg lock _ a a' =
  ioPropertyWithSK @v lock $ \sk -> do
    sig <- signDSIGNM () a sk
    vk <- deriveVerKeyDSIGNM sk
    return $
      a /= a' ==> verifyDSIGN () vk a' sig =/= Right ()

-- TODO: verify that DSIGN and DSIGNM implementations match (see #363)
