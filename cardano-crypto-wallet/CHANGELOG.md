# Changelog for cardano-crypto-wallet

## 0.1.0.1

*

## 0.1.0.0

* Initial release providing HD wallet key management.
* Keys are stored as authenticated v2 envelopes (Argon2id + XChaCha20-Poly1305).
* HMAC-SHA512 key derivation uses libsodium; vendored @hmac.h@ removed.
