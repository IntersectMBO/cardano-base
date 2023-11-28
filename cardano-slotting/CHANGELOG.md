# Changelog for `cardano-slotting`

## 0.1.2.0

* New `Test.Cardano.Slotting.TreeDiff` module extracted from
  `cardano-ledger-binary`. It lives in a new public sublibrary `testlib`.

## 0.1.1.1

* GHC-9.6 compatibility

## 0.1.1.0

* Remove `development` flag: #372
* Addition of `ToJSON`/`FromJSON` instances for:
  * `WithOrigin`
  * `BlockNo`
  * `SystemStart`
  * `RelativeTime` and `SlotLength`

## 0.1.0.1

* Initial release
