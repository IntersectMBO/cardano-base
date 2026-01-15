# Changelog for `cardano-strict-containers`

## 0.1.6.0

* Added to `Data.Sequence.Strict`:
  - `scanr`
  - `tails`
  - `inits`
  - `breakl`
  - `breakr`

### `testlib`

* Added `Arbitrary` instances for `StrictMaybe`, `StrictSeq`
* Initial release

## 0.1.5.0

* Added `Eq1`, `Ord1`, `Read1` and `Show1` instances for `StrictMaybe`
* Added `filter` function to `Data.Sequence.Strict`

## 0.1.4.0

* GHC-8.10 compatibility
* Added `takeWhileR` and `takeWhileL` to `Data.Sequence.Strict`

## 0.1.3.0

* Added `IsList` instance for `StrictSeq`

## 0.1.2.1

* Remove `development` flag: #372

## 0.1.2.0

* Added `ToCBOR` and `FromCBOR` instances for `StrictSeq`: [#361](https://github.com/input-output-hk/cardano-base/pull/361)

## 0.1.1.0

* Added instances of `Monoid` and `Semigroup` for `StrictMaybe`: [#314](https://github.com/input-output-hk/cardano-base/pull/314)

## 0.1.0.1

* Initial release
