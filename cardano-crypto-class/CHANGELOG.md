# Changelog for `cardano-crypto-class`

## 2.3.0.0

* Remove `Serialise` instance for `PackedBytes` as unused
* Switch `OutputVRF` to use `ByteArray` instead of `ByteString`. Change field accessor name to `getOutputVRFByteArray`
* Add `byteArrayToNatural`, `naturalToByteArray` and `byteArrayToInteger`.
* Expose `bytesToInteger`
* Add `hashToByteArray`
* Add `BLS12-381` aggregatable signature schemes
* Add Cabal components using code moved from `cardano-crypto-tests`:
  - `lib:testlib`
  - `lib:benchlib`
  - `test:tests`
  - `bench:bench`
* Add `cbits/blst_util.h` to `c-sources`
* Add `ToCBOR` and `FromCBOR` instances for `MessageHash`
* Add `ToCBOR` and `FromCBOR` instances for `PinnedSizedBytes`
* Add `ToCBOR` and `FromCBOR` instances for `PackedBytes`
* Add `packByteString`
* Add `packShortByteString` and `packShortByteStringWithOffset`
* Deprecate `packBytesMaybe`
* Refactor BLS12-381 module to use `PinnedSizedBytes`

### `testlib`

* Add with modules:
  - `Test.Crypto.AllocLog`
  - `Test.Crypto.DSIGN`
  - `Test.Crypto.EllipticCurve`
  - `Test.Crypto.EqST`
  - `Test.Crypto.Hash`
  - `Test.Crypto.Instances`
  - `Test.Crypto.KES`
  - `Test.Crypto.Regressions`
  - `Test.Crypto.RunIO`
  - `Test.Crypto.Util`
  - `Test.Crypto.Vector.SerializationUtils`

### `benchlib`

* Add with module:
  - `Bench.Crypto.BenchData`

## 2.2.3.2

* Fix `FromCBOR` instance for `Hash`

## 2.2.3.1

* Add package bound on pkg-config lib blst in #544

## 2.2.3.0

* Add `blsMSM` to the BLS12_381 interface
* Drop GHC <= 9.4 support

## 2.2.2.1

*

## 2.2.2.0

* Add `SHA512` and `SHA3_512` algorithms.

## 2.2.1.0

* Add `NoThunks` constraint on `UnsoundPureSignKeyKES` that was missed during KES changes

## 2.2.0.0

* Add required `HashAlgorithm` constraint to `Hash` serialization.
* Add `MemPack` instance for `Hash` and `PackedBytes`
* Introduce memory locking and secure forgetting functionality:
  [#255](https://github.com/input-output-hk/cardano-base/pull/255)
  [#404](https://github.com/input-output-hk/cardano-base/pull/404)
* KES started using the new memlocking functionality:
  [#255](https://github.com/input-output-hk/cardano-base/pull/255)
  [#404](https://github.com/input-output-hk/cardano-base/pull/404)
* Introduction of `DSIGNM` that uses the new memlocking functionality:
  [#404](https://github.com/input-output-hk/cardano-base/pull/404)
* Included bindings to `blst` library to enable operations over curve BLS12-381
  [#266](https://github.com/input-output-hk/cardano-base/pull/266)
* Introduction of `DirectSerialise` / `DirectDeserialise` APIs, providing
  direct access to mlocked keys in RAM:
  [#404](https://github.com/input-output-hk/cardano-base/pull/404)
* Restructuring of libsodium bindings and related APIs:
  [#404](https://github.com/input-output-hk/cardano-base/pull/404)
* Re-introduction of non-mlocked KES implementations to support a smoother
  migration path:
  [#504](https://github.com/IntersectMBO/cardano-base/pull/504)
* Exposing constructors of the BLS12-381 internals: [#509](https://github.com/IntersectMBO/cardano-base/pull/509)

## 2.1.0.2

* Deserialization performance improvements
* GHC-9.6 compatibility

## 2.1.0.1

* Remove `development` flag: #372

## 2.1.0.0

* Fixed the name `encodedSignKeyDESIGNSizeExpr` -> `encodedSignKeyDSIGNSizeExpr`
* Add `IsString` instance for `Code Q (Hash h a)`, so `$$"deadbeaf"` would work with GHC-9.2

## 2.0.0.1

* Initial release

