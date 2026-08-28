# Changelog for `cardano-crypto-leios`

## 0.3.0.0

* Rename committee seat types and accessors, reflecting that a committee is an ordered set of seats derived from the stake distribution:
  - `LeiosVoter` -> `LeiosSeat`, with fields `voterWeight` -> `seatWeight` and `voterVKey` -> `seatVKey`
  - `LeiosVoterId` -> `LeiosSeatId`
  - `resolveLeiosVoter` -> `resolveLeiosSeat`
  - `getLeiosVoterId` -> `getLeiosSeatId`
  - `leiosCommitteeVoters` -> `leiosCommitteeSeats`
* A committee seat may now be keyless: `seatVKey` is a `StrictMaybe LeiosVerificationKey`. This lets a committee always mirror the full stake distribution, with a seat per pool whether or not it has registered a Leios key.
* Rename the `LeiosCommittee` data constructor to `UnsafeLeiosCommittee`. Add `mkLeiosCommittee` to use instead: a seat with an invalid proof of possession becomes a keyless seat.
* Add `SignerWithoutKey (NonEmpty LeiosSeatId)` to `VerificationError`. `verifyLeiosCert` now rejects a certificate whose signer bitfield selects any keyless seat, before counting weight, so a keyless seat cannot pad the total towards the threshold.
* Moved several generators from test suite to `testlib`.
* Add `maxLeiosCommitteeSize`, the most seats a `LeiosSeatId` can address.
* Add `TooManySigners Int` to `AggregationError`. `aggregateLeiosCert` now rejects a committee past `maxLeiosCommitteeSize`, which it would otherwise have given a bitfield with a bit for every seat, including the unaddressable ones.
* Add `MalformedCommittee Int` to `VerificationError`. `verifyLeiosCert` now rejects a committee past `maxLeiosCommitteeSize` under it, distinct from the `MalformedSigners` it reports for a bitfield whose length does not match the committee. Previously a bit set for a seat at index ≥ 2^16 wrapped around and was counted against a low seat, borrowing its key and weight.

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
