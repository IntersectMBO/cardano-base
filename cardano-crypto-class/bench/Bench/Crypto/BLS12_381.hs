{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Compare checked point decoding (with subgroup check) against the unchecked
-- variants that skip it.
module Bench.Crypto.BLS12_381 (
  benchmarks,
) where

import Cardano.Crypto.EllipticCurve.BLS12_381

import Criterion

benchmarks :: Benchmark
benchmarks =
  bgroup
    "BLS12_381"
    [ benchDecode @Curve1 "G1"
    , benchDecode @Curve2 "G2"
    ]

benchDecode :: forall curve. BLS curve => String -> Benchmark
benchDecode lbl =
  env (return (blsCompress p, blsSerialize p)) $ \ ~(compressed, serialized) ->
    bgroup
      lbl
      [ bgroup
          "uncompress"
          [ bench "checked" $ whnf (decode . blsUncompress @curve) compressed
          , bench "unchecked" $ whnf (decodeUnchecked . blsUncompressUnchecked @curve) compressed
          ]
      , bgroup
          "deserialize"
          [ bench "checked" $ whnf (decode . blsDeserialize @curve) serialized
          , bench "unchecked" $ whnf (decodeUnchecked . blsDeserializeUnchecked @curve) serialized
          ]
      , bench "blsInGroup" $ whnf blsInGroup p
      ]
  where
    -- A generic subgroup point, rather than the generator itself.
    p :: Point curve
    p = blsMult (blsGenerator @curve) 0x5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e5a1e

    decode :: Either BLSTError (Point curve) -> ()
    decode = either (error . show) (const ())

    decodeUnchecked :: Either BLSTError (UncheckedPoint curve) -> ()
    decodeUnchecked = either (error . show) (const ())
