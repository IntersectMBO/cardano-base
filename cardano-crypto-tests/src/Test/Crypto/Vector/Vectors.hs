{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Test.Crypto.Vector.Vectors
  ( defaultSKey,
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
  )
where

import Cardano.Binary (DecCBOR)
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm (SigDSIGN, SignKeyDSIGN, VerKeyDSIGN),
    EcdsaSecp256k1DSIGN,
    SchnorrSecp256k1DSIGN,
  )
import Data.ByteString (ByteString)
import Test.Crypto.Vector.SerializationUtils
  ( HexStringInCBOR (..),
    sKeyParser,
    sigParser,
    vKeyParser,
  )

defaultSKey :: forall d. (DecCBOR (SignKeyDSIGN d)) => SignKeyDSIGN d
defaultSKey = sKeyParser "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"

defaultMessage :: ByteString
defaultMessage = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

-- These vectors contains secret key which first signs the given message and verifies using generated signature and derived vKey
signAndVerifyTestVectors :: forall d. (DecCBOR (SignKeyDSIGN d)) => [(SignKeyDSIGN d, ByteString)]
signAndVerifyTestVectors =
  map
    (\(sk, m) -> (sKeyParser sk, m))
    [ ( "0000000000000000000000000000000000000000000000000000000000000003",
        "0000000000000000000000000000000000000000000000000000000000000000"
      ),
      ( "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
      ),
      ( "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
      ),
      ( "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      )
    ]

-- It is used for testing already given message, signature and vKey so that Ver should be sucessful without needing secret key to sign the message for ecdsa.
ecdsaVerKeyAndSigVerifyTestVectors :: (VerKeyDSIGN EcdsaSecp256k1DSIGN, ByteString, SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaVerKeyAndSigVerifyTestVectors =
  ( vKeyParser "02599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b",
    "0000000000000000000000000000000000000000000000000000000000000000",
    sigParser "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114"
  )

ecdsaNegSigTestVectors :: (VerKeyDSIGN EcdsaSecp256k1DSIGN, ByteString, SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaNegSigTestVectors =
  ( vKeyParser "02599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b",
    "0000000000000000000000000000000000000000000000000000000000000000",
    sigParser "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a09dab0f6ea6ca0cc46e4314e92b900d7d6b493e4b47b6fb999fd9e841575e602d"
  )

-- It is used for testing already given message, signature and vKey so that Ver should be sucessful without needing secret key to sign the message for schnorr.
schnorrVerKeyAndSigVerifyTestVectors :: (VerKeyDSIGN SchnorrSecp256k1DSIGN, ByteString, SigDSIGN SchnorrSecp256k1DSIGN)
schnorrVerKeyAndSigVerifyTestVectors =
  ( vKeyParser "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b",
    "0000000000000000000000000000000000000000000000000000000000000000",
    sigParser "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9b"
  )

-- Wrong length message hash are used to test ecdsa toMessageHash function
wrongLengthMessageHashTestVectors :: [ByteString]
wrongLengthMessageHashTestVectors =
  [ "0",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
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
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B50",
    -- Ver key of length 34 bytes
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659FF"
  ]

-- Raw hexstring to be used in invalid length signature parser tests for ecdsa
ecdsaWrongLengthSigTestVectorsRaw :: [HexStringInCBOR]
ecdsaWrongLengthSigTestVectorsRaw =
  [ "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e1",
    "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114FF"
  ]

-- Raw hexstring to be used in invalid length signature parser tests for schnorr
schnorrWrongLengthSigTestVectorsRaw :: [HexStringInCBOR]
schnorrWrongLengthSigTestVectorsRaw =
  [ "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a",
    "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9bFF"
  ]

ecdsaMismatchMessageAndSignature :: [(ByteString, VerKeyDSIGN EcdsaSecp256k1DSIGN, SigDSIGN EcdsaSecp256k1DSIGN)]
ecdsaMismatchMessageAndSignature =
  map
    (\(vm, vKey, sig) -> (vm, vKeyParser vKey, sigParser sig))
    --  verifyMessage, vKey, signature
    [ ( "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        "3dccc57be49991e95b112954217e8b4fe884d4d26843dfec794feb370981407b79151d1e5af85aba21721876896957adb2b35bcbb84986dcf82daa520a87a9f9" -- wrong verify message but right signature
      ),
      ( "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        "5ef63d477c5d1572550016ccf72a2310c7368beeb843c85b1b5697290872222a09e7519702cb2c9a65bbce92d273080a0193b77588bc2eac6dbcbfc15c6dfefd" -- right verify message but wrong signature
      )
    ]

schnorrMismatchMessageAndSignature :: [(ByteString, VerKeyDSIGN SchnorrSecp256k1DSIGN, SigDSIGN SchnorrSecp256k1DSIGN)]
schnorrMismatchMessageAndSignature =
  map
    (\(vm, vKey, sig) -> (vm, vKeyParser vKey, sigParser sig))
    -- verifyMessage, vKey, signature
    [ ( "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b",
        "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9b" -- wrong verify message but right signature
      ),
      ( "0000000000000000000000000000000000000000000000000000000000000000",
        "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b",
        "18a66fb829009a9df6312e1d7f4b53af0ac8a6aa17c2b7ff5941b57a27b24c23531f01bd11135dd844318f814241ea41040cc68958a6c47da489a32f0e22b805" -- right verify message but wrong signature
      )
    ]
