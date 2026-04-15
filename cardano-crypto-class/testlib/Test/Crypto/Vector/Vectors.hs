{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Test.Crypto.Vector.Vectors (
  defaultSKey,
  defaultMessage,
  signAndVerifyTestVectors,
  wrongEcdsaVerKeyTestVector,
  wrongSchnorrVerKeyTestVector,
  wrongLengthMessageHashTestVectors,
  ecdsaVerKeyAndSigVerifyTestVectors,
  schnorrVerKeyAndSigVerifyTestVectors,
  ecdsaMismatchMessageAndSignature,
  schnorrMismatchMessageAndSignature,
  verKeyNotOnCurveTestVectorRaw,
  wrongLengthVerKeyTestVectorsRaw,
  ecdsaWrongLengthSigTestVectorsRaw,
  schnorrWrongLengthSigTestVectorsRaw,
  ecdsaNegSigTestVectors,
  minSigBLS12381DSIGNSignature,
  minVerKeyBLS12381DSIGNSignature,
  minVerKeyBLS12381DSIGNPoP,
  minSigBLS12381DSIGNPoP,
  minVerKeyBLS12381DSIGNAggregatedSignature,
  minSigBLS12381DSIGNAggregatedSignature,
)
where

import Cardano.Binary (FromCBOR)
import Cardano.Crypto.DSIGN (
  BLS12381MinSigDSIGN,
  BLS12381MinVerKeyDSIGN,
  DSIGNAggregatable (PossessionProofDSIGN),
  DSIGNAlgorithm (SigDSIGN, SignKeyDSIGN, VerKeyDSIGN),
  EcdsaSecp256k1DSIGN,
  SchnorrSecp256k1DSIGN,
 )
import Data.ByteString (ByteString)
import Test.Crypto.Vector.SerializationUtils (
  HexStringInCBOR (..),
  popParser,
  sKeyParser,
  sigParser,
  unsafeUnHex,
  vKeyParser,
 )

defaultSKey :: forall d. FromCBOR (SignKeyDSIGN d) => SignKeyDSIGN d
defaultSKey = sKeyParser "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"

defaultMessage :: ByteString
defaultMessage = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

-- These vectors contains secret key which first signs the given message and verifies using generated signature and derived vKey
signAndVerifyTestVectors :: forall d. FromCBOR (SignKeyDSIGN d) => [(SignKeyDSIGN d, ByteString)]
signAndVerifyTestVectors =
  map
    (\(sk, m) -> (sKeyParser sk, m))
    [
      ( "0000000000000000000000000000000000000000000000000000000000000003"
      , "0000000000000000000000000000000000000000000000000000000000000000"
      )
    ,
      ( "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
      , "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
      )
    ,
      ( "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
      , "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
      )
    ,
      ( "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"
      , "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      )
    ]

-- It is used for testing already given message, signature and vKey so that Ver should be sucessful without needing secret key to sign the message for ecdsa.
ecdsaVerKeyAndSigVerifyTestVectors ::
  (VerKeyDSIGN EcdsaSecp256k1DSIGN, ByteString, SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaVerKeyAndSigVerifyTestVectors =
  ( vKeyParser "02599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b"
  , "0000000000000000000000000000000000000000000000000000000000000000"
  , sigParser
      "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114"
  )

ecdsaNegSigTestVectors ::
  (VerKeyDSIGN EcdsaSecp256k1DSIGN, ByteString, SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaNegSigTestVectors =
  ( vKeyParser "02599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b"
  , "0000000000000000000000000000000000000000000000000000000000000000"
  , sigParser
      "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a09dab0f6ea6ca0cc46e4314e92b900d7d6b493e4b47b6fb999fd9e841575e602d"
  )

-- It is used for testing already given message, signature and vKey so that Ver should be sucessful without needing secret key to sign the message for schnorr.
schnorrVerKeyAndSigVerifyTestVectors ::
  (VerKeyDSIGN SchnorrSecp256k1DSIGN, ByteString, SigDSIGN SchnorrSecp256k1DSIGN)
schnorrVerKeyAndSigVerifyTestVectors =
  ( vKeyParser "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b"
  , "0000000000000000000000000000000000000000000000000000000000000000"
  , sigParser
      "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9b"
  )

-- Wrong length message hash are used to test ecdsa toMessageHash function
wrongLengthMessageHashTestVectors :: [ByteString]
wrongLengthMessageHashTestVectors =
  [ "0"
  , "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
  ]

wrongEcdsaVerKeyTestVector :: VerKeyDSIGN EcdsaSecp256k1DSIGN
wrongEcdsaVerKeyTestVector = vKeyParser "02D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"

wrongSchnorrVerKeyTestVector :: VerKeyDSIGN SchnorrSecp256k1DSIGN
wrongSchnorrVerKeyTestVector = vKeyParser "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"

-- Raw string verification key that is not on the curve should result in ver key parse failed
verKeyNotOnCurveTestVectorRaw :: HexStringInCBOR
verKeyNotOnCurveTestVectorRaw = "02EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"

-- Parse these vectors and expect the errors on tests with parity bit
wrongLengthVerKeyTestVectorsRaw :: [HexStringInCBOR]
wrongLengthVerKeyTestVectorsRaw =
  [ -- Ver key of length 30 bytes
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B50"
  , -- Ver key of length 34 bytes
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659FF"
  ]

-- Raw hexstring to be used in invalid length signature parser tests for ecdsa
ecdsaWrongLengthSigTestVectorsRaw :: [HexStringInCBOR]
ecdsaWrongLengthSigTestVectorsRaw =
  [ "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e1"
  , "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114FF"
  ]

-- Raw hexstring to be used in invalid length signature parser tests for schnorr
schnorrWrongLengthSigTestVectorsRaw :: [HexStringInCBOR]
schnorrWrongLengthSigTestVectorsRaw =
  [ "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a"
  , "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9bFF"
  ]

ecdsaMismatchMessageAndSignature ::
  [(ByteString, VerKeyDSIGN EcdsaSecp256k1DSIGN, SigDSIGN EcdsaSecp256k1DSIGN)]
ecdsaMismatchMessageAndSignature =
  map
    (\(vm, vKey, sig) -> (vm, vKeyParser vKey, sigParser sig))
    --  verifyMessage, vKey, signature
    [
      ( "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
      , "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517"
      , "3dccc57be49991e95b112954217e8b4fe884d4d26843dfec794feb370981407b79151d1e5af85aba21721876896957adb2b35bcbb84986dcf82daa520a87a9f9" -- wrong verify message but right signature
      )
    ,
      ( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      , "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517"
      , "5ef63d477c5d1572550016ccf72a2310c7368beeb843c85b1b5697290872222a09e7519702cb2c9a65bbce92d273080a0193b77588bc2eac6dbcbfc15c6dfefd" -- right verify message but wrong signature
      )
    ]

schnorrMismatchMessageAndSignature ::
  [(ByteString, VerKeyDSIGN SchnorrSecp256k1DSIGN, SigDSIGN SchnorrSecp256k1DSIGN)]
schnorrMismatchMessageAndSignature =
  map
    (\(vm, vKey, sig) -> (vm, vKeyParser vKey, sigParser sig))
    -- verifyMessage, vKey, signature
    [
      ( "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
      , "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b"
      , "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9b" -- wrong verify message but right signature
      )
    ,
      ( "0000000000000000000000000000000000000000000000000000000000000000"
      , "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b"
      , "18a66fb829009a9df6312e1d7f4b53af0ac8a6aa17c2b7ff5941b57a27b24c23531f01bd11135dd844318f814241ea41040cc68958a6c47da489a32f0e22b805" -- right verify message but wrong signature
      )
    ]

-- The test vectors below are extracted from https://github.com/input-output-hk/bls-e2e-testvectors

minVerKeyBLS12381DSIGNSignature ::
  (VerKeyDSIGN BLS12381MinVerKeyDSIGN, ByteString, SigDSIGN BLS12381MinVerKeyDSIGN)
minVerKeyBLS12381DSIGNSignature =
  (\(vKey, msg, sig) -> (vKeyParser vKey, unsafeUnHex msg, sigParser sig))
    ( "aa04a34d4db073e41505ebb84eee16c0094fde9fa22ec974adb36e5b3df5b2608639f091bff99b5f090b3608c3990173"
    , "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e"
    , "808ccec5435a63ae01e10d81be2707ab55cd0dfc235dfdf9f70ad32799e42510d67c9f61d98a6578a96a76cf6f4c105d09262ec1d86b06515360b290e7d52d347e48438de2ea2233f3c72a0c2221ed2da5e115367bca7a2712165032340e0b29"
    )

minSigBLS12381DSIGNSignature ::
  (VerKeyDSIGN BLS12381MinSigDSIGN, ByteString, SigDSIGN BLS12381MinSigDSIGN)
minSigBLS12381DSIGNSignature =
  (\(vKey, msg, sig) -> (vKeyParser vKey, unsafeUnHex msg, sigParser sig))
    ( "b4953c4ba10c4d4196f90169e76faf154c260ed73fc77bb65dc3be31e0cec614a7287cda94195343676c2c57494f0e651527e6504c98408e599a4eb96f7c5a8cfb85d2fdc772f28504580084ef559b9b623bc84ce30562ed320f6b7f65245ad4"
    , "5032ec38bbc5da98ee0c6f568b872a65a08abf251deb21bb4b56e5d8821e68aa"
    , "8e02b7950198d335c7b352d18880e2f6b4e7f6780298872b67840db1faa069f9a8be48800ce2ee5565a811d8230d3f05"
    )

minVerKeyBLS12381DSIGNPoP ::
  (VerKeyDSIGN BLS12381MinVerKeyDSIGN, PossessionProofDSIGN BLS12381MinVerKeyDSIGN)
minVerKeyBLS12381DSIGNPoP =
  (\(vKey, pop) -> (vKeyParser vKey, popParser pop))
    ( "aa04a34d4db073e41505ebb84eee16c0094fde9fa22ec974adb36e5b3df5b2608639f091bff99b5f090b3608c3990173"
    , "a873bfe32ed52ffb33a490aafb69955fee8dc4ea243be0d6fbb77dad5537a7146f559fb93422583153b6d37d6beec9c0103b8a6d4de51678191c20c1ab6b280bdb7594fc644fe70c315d3dbf35e31ef4bf9f6de97fe6e7828be4d5c14dfacb91"
    )

minSigBLS12381DSIGNPoP ::
  (VerKeyDSIGN BLS12381MinSigDSIGN, PossessionProofDSIGN BLS12381MinSigDSIGN)
minSigBLS12381DSIGNPoP =
  (\(vKey, pop) -> (vKeyParser vKey, popParser pop))
    ( "b4953c4ba10c4d4196f90169e76faf154c260ed73fc77bb65dc3be31e0cec614a7287cda94195343676c2c57494f0e651527e6504c98408e599a4eb96f7c5a8cfb85d2fdc772f28504580084ef559b9b623bc84ce30562ed320f6b7f65245ad4"
    , "9775f532816da49dd464f1239f7d70a16ca9d26e7abbd7a781e5332f6723749cbedb88cea0d8451ceb9c2fbd3fc42fcd"
    )

minVerKeyBLS12381DSIGNAggregatedSignature ::
  ( [VerKeyDSIGN BLS12381MinVerKeyDSIGN]
  , ByteString
  , SigDSIGN BLS12381MinVerKeyDSIGN
  )
minVerKeyBLS12381DSIGNAggregatedSignature =
  ( map
      vKeyParser
      [ "b91cacee903a53383c504e9e9a39e57d1eaa6403d5d38fc9496e5007d54ca92d106d1059f09461972aa98514d07000ae"
      , "8477e8491acc1cfbcf675acf7cf6b92e027cad7dd604a0e8205703aa2cc590066c1746f89e10d492d0230e6620c29726"
      , "887e8fd9c5f80beb5d0c50a2c536dffd5563dcd7fcc09dcf1aace5f481429344514b380affbc28f116a8e137fec52e90"
      , "b4928475f56d224ef82ee50ee5abc393e5894d0222068c4ade1d5a5118861b3c1486b747a759142ef75c61c74abcb82c"
      , "b15f02441de609ab5ee7b61c3350116461a48b7d530f8b1f3abf57d1fc29659d3fe05d6b7dae6ad26ba36921a91c935a"
      , "a1199c1a689c1b27ac1e902afdf3eb42f0a5231c9db61420fdeb58cd531ff98ebb7035c2fb6803aaaaad90c74e3ab6f3"
      , "b632708c4fe78944ae481ddfcbe51eb38b18292966bdce5870ed2d16a556e6a60e2f72f16643244f533c26dd97e309f4"
      , "96804e572530fd75667fc38da98ef71eda385000c5a5e1ce96ec54cfa94f494fb63c9a2bf94fda410934a5d1cb04218f"
      , "a0c2f005e87379a00a38d92fcc4927087b84a3a5284feac624db3ad6bdcc4174f25d3422b4427e2674c7546f180825ea"
      , "a14d1004c8166915fc125f03b2c5c80976c440d0c819e87912bd4f32d5dd914c3767b355bd8baef2a671d421a792e4a8"
      ]
  , unsafeUnHex "0558db9aff738e5421439601e7f30e88b74f43b80c1d172b5d371ce0dc05c912"
  , sigParser
      "b359beeff652ba34474f98019f389e39bac0ff8f3b49bdb9a6e0a67da895c50431746da1faf0e8ec53d15aa90e02aef7045147840791d7d205d077acc797a40b14880769f3568babf49f45a59b2d7de199369386c7a7267fcdddc2bc36b67318"
  )

minSigBLS12381DSIGNAggregatedSignature ::
  ( [VerKeyDSIGN BLS12381MinSigDSIGN]
  , ByteString
  , SigDSIGN BLS12381MinSigDSIGN
  )
minSigBLS12381DSIGNAggregatedSignature =
  ( map
      vKeyParser
      [ "99325b8e11a6a1d137a4ccc09574dcfa54162f3eca88656e4aa8a8ee0e32842ff9bdbcf90800ff4b6196421a930def3d00e948c1fc67b71597ad78819fd1163daa68b419556be8dc64e48086b7604583d8beaffe755710b4b80effa910c6050d"
      , "b82da86bd84f82cc6b3f1df65ebe754d2199e49f6791a0d6db136304ab4610fadcbdf7bac09e6e10b6850aafa0b258bb08bee0214ce3fbfaa97371e67d57fc27bb423ba07d092bf6f584c5f2be72a8b2c02045de23af01bb04e9bf5be0a1d15c"
      , "99a7fff545393ac442bdf0c6043de7461301ad7ea3402f4ddf89e19c671faf28989c28251ad63385ec9dbb81857b9d3301ff6ebe7e16f21a86bf48c40f64fd27fad2c2a6b93305ae6448ba8b3756ea4d6fbbac859231e65b0242916a34b0a67a"
      , "a6444b7a2ef32fc83d85973945569d30a6dff7feb5840254a9a81fc0f78a70a97905cf196faa5f47ab6f26a0750b8f610b000537c8f73a511db4bd1657c47b531b95be021817bde5345d1c6daf10064a219def36465b0bf5c295df2ebde63535"
      , "ab92c359bdccc19e44fd47120cc6d0a1d3955af9e6be18c1b084e397442055c597ff92ec134c9d8f2a788a96b28f3af4108239e00339840f3bfb666eea21e87c02bd69edca6502f7805a6dfd29fb4db4052a321abbb857621992fc383f368c91"
      , "872e0b3f67274e0808e326601ef42e22edf880f12d4d044ba5d75bf078aa0ebcad085376c15d1cc09eb8c8c9797572da003826536c8a06bdea226e6b2e0cc111ad1e645fd6c38190a72f42f514397d470534c161d028690dafb95cb1f19ff9c0"
      , "acfc575fee9be2dd324940c3cb873213532a9eddc2f546a2d8c56b5b015e2521173a4d2c05acca14aa97c6224a223b46140b3483f06ea7a2a2db3961a74074e58653549220713aa6edc8a21bbb04f468d684f7656882543143ed4cf3d5bcae69"
      , "ac0c74306cf12d21d4889d7b28e562278a6849b0b2e152968cc23dbe7b6cf7a75a62858068d9f1dde5bf90a35e89a81e0a008a28dbcd81697fb87f603895b6361c8dfdf21110633e93f33120d8e0f7ba7c0693173e55d5b3e1284a18be5ec773"
      , "8b7cd629f5a07ddca6be75585cfc12622789811edf9d4c86ce433927450ed484942b7b377eaa383746d54bcedf1d616d0cb0fa2101e5358884578860a5960653664dbd77bb3afa61af7434c10a74636c2cbe1d61db5b47102ee017c1ab81fe7f"
      , "a27b12206e80a5e0d52d9b817bfb0097c87534b4332f430f1ad1978d8a9e33cfe63123029f64408fea181e22d25dc7c80756cb011387ad545026cc7af9a7047043b44bf07682c03a0fc7f61017ba21d842535b449afe1e7d5d51a7660f71f6b3"
      ]
  , unsafeUnHex "0558db9aff738e5421439601e7f30e88b74f43b80c1d172b5d371ce0dc05c912"
  , sigParser
      "b0887f5c2e85596a8233cc26ce0ae94cdf0e1da3465075016a633d77de8acaefbc86497b484cf0beb36a3af90b38c3ce"
  )
