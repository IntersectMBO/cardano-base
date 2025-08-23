# Changelog for `cardano-crypto-tests`

## 2.2.2.1

*

## 2.2.2.0

* Add test for `blsMSM`
* fix bls property test for final verify to depent on group algebra
* Drop GHC <= 9.4 support

## 2.2.1.1

*

## 2.2.1.0

* Add test for `SHA512` and `SHA3_512` algorithms.
* Add tests using standard test vectors and generated ones for Praos and PraosBatchCompat

## 2.2.0.0

* Memlocking functionality

## 2.1.2.0

* Add tests for BLST

## 2.1.1.0

* Add benchmark for `HASH`

## 2.1.0.2

* GHC-9.6 compatibility

## 2.1.0.1

* Remove `development` flag: #372

## 2.1.0.0

* Addition of `DSIGN` benchmarks. New modules:
  * `Bench.Crypto.DSIGN`
  * `Bench.Crypto.BenchData`
* Addition of `DSIGN` vector tests. New modules:
  * `Test.Crypto.Vector.Secp256k1DSIGN`
  * `Test.Crypto.Vector.Vectors`
  * `Test.Crypto.Vector.StringConstants`
  * `Test.Crypto.Vector.SerializationUtils`

## 2.0.0.1

* Initial release
