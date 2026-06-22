# Component default configurations

Each file here is the **default configuration of one component**, in the same
shape as that component's section in a node configuration. They are the base
layer that `resolveConfiguration` applies underneath the user's configuration
file and the CLI arguments, so that a resolved `NodeConfiguration` is complete.

## Ownership

`cardano-config` is currently the *origin* of these files, but each component is
ultimately **owned by the layer that implements it** (the networking layer owns
`Network.json`, consensus owns `Consensus.json`, and so on). The intended flow
is:

1. We author the initial defaults here.
2. They are copied out to the owning layers, which adopt them as the canonical
   defaults for their component.
3. A CI check (see the package test-suite) keeps the copies here byte-for-byte
   aligned with the upstream ones, so this package stays the single place that
   parses the configuration while the *values* are owned upstream.

## Provenance / TODO

Values confirmed from source:

- `Network.json`: peer targets, accepted-connection limits, churn intervals and
  block-fetch concurrency from
  `ouroboros-network` `Ouroboros/Network/Diffusion/Configuration.hs` and
  `cardano-diffusion` `Cardano/Network/Diffusion/Configuration.hs`
  (`defaultDeadlineTargets` (Relay), `defaultSyncTargets`,
  `defaultAcceptedConnectionsLimit`, `defaultChainSyncIdleTimeout = 3373`,
  `defaultEgressPollInterval = 0`, `bfcMaxConcurrencyBulkSync/Deadline = 1`).

Values still to be confirmed by the owning layer (currently best-effort
placeholders — search for `TODO` is not possible in JSON, so they are listed
here):

- `Network.json`: `ProtocolIdleTimeout`, `TimeWaitTimeout`,
  `MinBigLedgerPeersForTrustedState`, `PeerSharing` (Relay default is enabled,
  block-producer default is disabled — node-role dependent),
  `ResponderCoreAffinityPolicy`, `TxSubmissionLogicVersion`,
  `TxSubmissionInitDelay`.
- `Mempool.json`: the three timeouts.
- `Protocol.json`: the genesis files/hashes are **network-specific** and are
  intentionally *not* defaulted here; they remain required in the user
  configuration.

Genesis files are deliberately omitted from the defaults: defaulting them to
mainnet would silently mis-configure other networks.
