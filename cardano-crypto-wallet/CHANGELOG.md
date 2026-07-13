# Changelog for cardano-crypto-wallet

## 0.2.0.0

* Breaking: `encryptedDerivePublic` now returns `Either XPrvError (PublicKey, ChainCode)`
  instead of throwing on hardened indices.
* Breaking: `XPrvHardenedDerivationUnsupported` constructor added to `XPrvError`.

## 0.1.0.0

* Initial release providing HD wallet key management.
* Keys are stored as authenticated v2 envelopes (Argon2id + XChaCha20-Poly1305).
* HMAC-SHA512 key derivation uses libsodium; vendored @hmac.h@ removed.
