# Component default configurations

Each file here is part of the **default configuration of one component**, in the
same shape as that component's section in a node configuration. They are the base
layer that `resolveConfiguration` applies underneath the user's configuration
file and the CLI arguments, so that a resolved `NodeConfiguration` is complete.

## File naming

- `<Component>.json` — the component's role- and network-agnostic defaults. This
  base file is **always** read as the bottom layer during resolution.
- `<Component>.variants/<Component>.<variant>.json` — overrides for a particular
  **network** or node **role**, kept in a `.variants/` subdirectory to make clear
  they are opt-in overlays. A configuration selects one (or several) by
  referencing them, and they are deep-merged on top of the base file. Present
  variants:
  - `Protocol.variants/Protocol.{mainnet,preview,preprod}.json` — the
    network-specific genesis files/hashes, `RequiresNetworkMagic` and
    `LastKnownBlockVersion-*` (these legitimately differ per network, so they
    are not in the base `Protocol.json`).
  - `Consensus.variants/Consensus.{preview,preprod}.json` — `ConsensusMode`,
    which is `GenesisMode` on the test networks but `PraosMode` (the base
    default) on mainnet.
  - `Testing.variants/Testing.preview.json` — preview forces the Shelley…Alonzo
    hard forks at epoch 0 (it launched with those eras already active).
  - `Network.variants/Network.{relay,blockproducer}.json` — the deadline peer
    targets and `PeerSharing`, which differ between a relay and a
    block-producing node (`defaultDeadlineTargets` / `defaultPeerSharing`).

Because divergence spans several components, selecting a network means referencing
its variant in *each* affected section (e.g. preview pulls in
`Protocol.variants/Protocol.preview.json`, `Consensus.variants/Consensus.preview.json`
and `Testing.variants/Testing.preview.json`).

## Divergence coverage

Comparing the published mainnet/preview/preprod configs, the variants above cover
all the differences this library parses, **except**:

- `LedgerDB.SnapshotInterval` differs (mainnet/preprod 4320, preview 864). It is
  not yet captured as a `Storage` variant because the base default uses the
  `Mithril` snapshot policy rather than an explicit interval; whether the
  per-network interval still applies under `Mithril` needs confirming before
  adding a `Storage.variants/Storage.preview.json`.
- `MaxKnownMajorProtocolVersion` (present in mainnet/testnet config files) is
  intentionally **not parsed**. The node's own parser
  (`Cardano.Node.Configuration.POM`) does not read this key either — it only
  reads `LastKnownBlockVersion-Major`/`-Minor`/`-Alt` — so it is a vestigial key
  that the node ignores, and this library matches that behaviour (it surfaces as
  an unrecognised-key warning).

The role variants fully capture the block-producer/relay divergence
(`TargetNumberOfRootPeers`, `TargetNumberOfKnownPeers`, `PeerSharing`; the other
targets are role-independent).

A configuration can layer them with the list form, e.g.
`"Network": ["Network.variants/Network.relay.json"]`, which is merged on top of
the always-read base `Network.json`.

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
