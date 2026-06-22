# Component default configurations

Each file here is part of the **default configuration of one component**, in the
same shape as that component's section in a node configuration. They are the base
layer that `resolveConfiguration` applies underneath the user's configuration
file and the CLI arguments, so that a resolved `NodeConfiguration` is complete.

## File naming

- `<Component>.json` — the component's role- and network-agnostic defaults.
- `<Component>.<variant>.json` — overrides for a particular **network** or node
  **role**, layered on top of the base file. Present variants:
  - `Protocol.mainnet.json`, `Protocol.preview.json`, `Protocol.preprod.json`
    — the network-specific genesis files/hashes, `RequiresNetworkMagic` and
    `LastKnownBlockVersion-*` (these legitimately differ per network, so they
    are not in the base `Protocol.json`).
  - `Network.relay.json`, `Network.blockproducer.json` — the deadline peer
    targets and `PeerSharing`, which differ between a relay and a
    block-producing node (`defaultDeadlineTargets` / `defaultPeerSharing`).

Genesis files are network-specific and only ever appear in a `Protocol.<network>`
variant, never in the base: defaulting them to mainnet would silently
mis-configure other networks.

## Ownership

`cardano-config` is currently the *origin* of these files, but each component is
ultimately **owned by the layer that implements it** (networking owns
`Network*.json`, consensus owns `Consensus.json`, and so on). The intended flow:

1. We author the initial defaults here.
2. They are copied out to the owning layers, which adopt them as the canonical
   defaults for their component.
3. A CI check keeps the copies here byte-for-byte aligned with the upstream ones,
   so this package stays the single place that parses the configuration while the
   *values* are owned upstream.

## Field classification

Within a resolved component, a field is one of:

- **Resolved (`Identity`)** — has a default here (base or variant), so it always
  has a value after resolution. Most fields.
- **Optional (`Maybe`)** — "unset" is a real, intended state, so it stays
  `Maybe` and its default simply *is* "none": the `*GenesisHash` fields,
  `PBftSignatureThreshold`, `CheckpointsFile`/`Hash`, `SocketPath`,
  `RpcSocketPath`, `MempoolCapacityBytesOverride` (`NoOverride`), the three
  mempool timeouts (the node's default is no timeout), and the Testing
  `Test<Era>HardForkAt*` / `DijkstraGenesis*` knobs.

`LedgerDB.Snapshots` (default `Mithril`) and `LedgerDB.QueryBatchSize` (default
100000) *do* have defaults and are resolved.

## Provenance / TODO

Confirmed from source (`ouroboros-network`
`Ouroboros/Network/Diffusion/Configuration.hs` and `cardano-diffusion`
`Cardano/Network/Diffusion/Configuration.hs`): the peer targets,
`AcceptedConnectionsLimit`, `ChainSyncIdleTimeout = 3373`,
`EgressPollInterval = 0`, `MaxConcurrency{BulkSync,Deadline} = 1`,
`PeerSharing` per role. Genesis values from the published `mainnet`, `preview`
and `preprod` configs.

**Placeholder values to be confirmed by the owning layer** (currently
best-effort so the type can be fully resolved; JSON cannot carry comments):

- `Network.json`: `ProtocolIdleTimeout` (5), `TimeWaitTimeout` (60),
  `TxSubmissionInitDelay` (0), `MinBigLedgerPeersForTrustedState` (0),
  `TxSubmissionLogicVersion` (`"V1"`), `ResponderCoreAffinityPolicy`
  (`"Disabled"`).

The mempool timeouts are intentionally absent: the node's default is to apply no
mempool timeout (`Maybe MempoolTimeoutConfig` = `Nothing`).
