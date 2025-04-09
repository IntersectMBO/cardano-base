# Changelog for `cardano-crypto-class`

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

