# 2.1.1.0

* Addition of `Cardano.Crypto.VRF.PraosBatchCompat`.
* Addition of conversion functions: `vkToBatchCompat`, `skToBatchCompat`, `outputToBatchCompat`.

# 2.1.0.0

* Remove redundant and unused `unsafeRawSeed`, `io_crypto_vrf_publickeybytes` and
  `io_crypto_vrf_secretkeybytes`.
* Stop exporting internal `crypto_vrf_publickeybytes`, `crypto_vrf_secretkeybytes`,
  `crypto_vrf_proofbytes`, `crypto_vrf_outputbytes` and `crypto_vrf_seedbytes` in favor of
  `sizeVerKeyVRF`, `sizeSignKeyVRF`, `sizeCertVRF`, `sizeOutputVRF` and `seedSizeVRF`
  respectfully.
* Export `proofFromBytes`, `skFromBytes` and `vkFromBytes`
* Expose internal types without constructors: `Proof`, `SignKey`, `VerKey` and `Output`

# 2.0.0.1

* Initial version released on [CHaP](https://github.com/input-output-hk/cardano-haskell-packages)
