# Changelog for `cardano-crypto-leios`

## 0.2.0.0

* Remove:
  - `encodeLeiosCert`
  - `decodeLeiosCert`
  - `encodeLeiosVoterId`
  - `decodeLeiosVoterId`
  - `encodeBitField`
  - `decodeBitField`
* Export `BitField` constructor

## 0.1.0.1

*

## 0.1.0.0

* Initial version of `Cardano.Crypto.Leios` that introduces `LeiosCert`, `LeiosCommittee`, and `LeiosVoterId` types, as well as main functions to interact with the types: `resolveLeiosVoter`, `getLeiosVoterId`, `aggregateLeiosCert`, and `verifyLeiosCert`  being notable functions.
