# Changelog for `cardano-base`

## 0.1.2.0

* Add `Cardano.Base.Bytes` containing:
  - `byteArrayToByteString`
  - `byteStringToByteArray`
  - `slice`
  - `splitsAt`
* Add `Cardano.Base.IP` module with `IPv4` and `IPv6` newtype wrappers to avoid orphan instances and laziness

### `testlib`

* Add `Test.Cardano.Base.Bytes` containing:
  - `genByteArray`
  - `genByteString`
  - `genLazyByteString`
  - `genShortByteString`
* Add `testlib` for `Arbitrary` and `ToExpr` instances

## 0.1.1.0

* Added `Cardano.Base.Proxy`

## 0.1.0.0

* Added `Cardano.Base.FeatureFlag`.
