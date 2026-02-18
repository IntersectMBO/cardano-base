# Changelog for `cardano-binary`

## 1.9.0.0

*

### `testlib`

* Add `Arbitrary` instances for `ByteArray`, `SlicedByteArray` and `Term` from `cborg`

## 1.8.0.0

* Bump version to reflect changes added in `1.7.3.0`:
  - Change `DecoderError(DecoderErrorUnknownTag)` to use `Word` instead of `Word8`
* Add `FromCBOR` and `ToCBOR` instances for `Codec.CBOR.ByteArray.ByteArray` and `Data.Array.Byte.ByteArray`

## 1.7.3.0

*DEPRECATED* - introduced a breaking change

* Change `DecoderError(DecoderErrorUnknownTag)` to use `Word` instead of `Word8`
* Add `FromCBOR` and `ToCBOR` instances for `Codec.CBOR.ByteArray.ByteArray` and `Data.Array.Byte.ByteArray`

## 1.7.2.0

*

### `testlib`

* Expose modules:
  - `Test.Cardano.Binary.Helpers`
  - `Test.Cardano.Binary.Helpers.GoldenRoundTrip`
* Remove the need for `cardano-binary-test` package.

## 1.7.1.1

* Drop GHC <= 9.4 support

## 1.7.1.0

* New `Test.Cardano.Binary.TreeDiff` module extracted from
  `cardano-ledger-binary`. It lives in a new public sublibrary `testlib`.
* Add `FromCBOR` instance for `TermToken`

## 1.7.0.1

* GHC-9.6 compatibility

## 1.7.0.0

* Remove `development` flag: #372
* Remove `To/FromCBOR` instances for `NominalDiffTime`, since they did rounding.  Newly
  added functions `encodeNominalDiffTimeMicro`/`decodedNominalDiffTimeMicro` can be used
  to recover previous behavior. Correct instances that do not perform any rounding will
  be added in some future version, for now `decodeNominalDiffTime` and
  `encodeNominalDiffTime` can be used.
* Add `decodeNominalDiffTime` and `encodeNominalDiffTime`
* Add `To/FromCBOR` for all `Fixed a`, not just `Nano` and `Pico`

## 1.6.0.0

* Removed `Cardano.Binary.Annotated` and `Cardano.Binary.Drop` modules. They have been
  replaced by equivalent in
  [`cardano-ledger-binary`](https://github.com/input-output-hk/cardano-ledger/blob/master/libs/cardano-ledger-binary)
* Removed `Cardano.Binary.Raw`. It has moved into:
  [`cardano-crypto-wrapper:Cardano.Crypto.Raw`](https://github.com/input-output-hk/cardano-ledger/blob/master/eras/byron/crypto/src/Cardano/Crypto/Raw.hs)
* Generalized `cborError` and `toCborError` to `MonadFail`
* Add `ToCBOR` instance for `Tokens -> Tokens`
* Add `To/FromCBOR` instances for `Term` and `ToCBOR` for `Encoding`
* Add `To/FromCBOR` instances for 6-tuples and 8-tuples
* Remove `FromCBOR` instance for `Ratio` in favor of `Rational`.
* Add `To/FromCBOR` instances for `Double`.
* Rename `toCBORMaybe` -> `encodeMaybe` with deprecation.
* Rename `decCBORMaybe` -> `decodeMaybe` with deprecation.
* Add `encodeNullMaybe` and `decodeNullMaybe`.
* Add `To/FromCBOR` instances for `Seq`
* Deprecate `serializeEncoding` and `serializeEncoding'` in favor of `serialize` and
  `serialize'` respectively, since `Encoding` now has the `ToCBOR` instance.
* Add `decodeFullDecoder'` that accepts strict `ByteString`.
