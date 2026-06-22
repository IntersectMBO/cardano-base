# `cardano-config`

This package exposes a library that defines:

- A parser for CLI options based on `optparse-applicative` (see `parseCliArgs`).

- Instances for parsing the configuration files from JSON/YAML (see `parseConfigurationFiles`).

- A function (`resolveConfiguration`) for combining the two above into a
  datatype representing the configuration of the `cardano-node` (`NodeConfiguration`).

The goal of this library is to offer a single entry-point for applications that
need access to the configuration file of the node, such as [`cardano-cli`](https://github.com/IntersectMBO/cardano-cli),
[`dmq-node`](https://github.com/IntersectMBO/dmq-node/), [the `ouroboros-consensus` tools](https://github.com/IntersectMBO/ouroboros-consensus/tree/main/ouroboros-consensus-cardano#consensus-db-tools), ...

## CLI options

`parseCliArgs` is an `optparse-applicative` parser producing a `CliArgs` value.
The flag names, metavars and help text match those historically accepted by
`cardano-node`, so existing operator scripts keep working. The recognised flags
are:

| Group | Flag(s) | Metavar | Notes |
| --- | --- | --- | --- |
| | `--config` | `FILEPATH` | Main configuration file (defaults to `./configuration/cardano/mainnet-config.yaml`). |
| | `--topology` | `FILEPATH` | Topology file (defaults to the mainnet `./configuration/cardano/mainnet-topology.yaml`). |
| | `--socket-path` | `FILEPATH` | Socket for local clients; overrides `LocalConnections.SocketPath`. |
| | `--grpc-enable` | | [EXPERIMENTAL] Enable the gRPC endpoint; overrides `LocalConnections.EnableRpc`. Absent means *unset* (falls back to the config file), not `False`. |
| | `--grpc-socket-path` | `FILEPATH` | [EXPERIMENTAL] gRPC socket path; overrides `LocalConnections.RpcSocketPath`. Defaults to `rpc.sock` next to the node socket. |
| Storage | `--database-path`, `--volatile-database-path`, `--immutable-database-path` | `FILEPATH` | Overrides `Storage.DatabasePath`. |
| Storage | `--validate-db` | | Validate all on-disk database files. |
| Credentials | `--byron-delegation-certificate`, `--byron-signing-key` | `FILEPATH` | Byron operational credentials. |
| Credentials | `--shelley-kes-key` *or* `--shelley-kes-agent-socket` | `FILEPATH` / `SOCKET_FILEPATH` | KES key source — a key file path **or** a KES Agent socket. Mutually exclusive. |
| Credentials | `--shelley-vrf-key`, `--shelley-operational-certificate`, `--bulk-credentials-file` | `FILEPATH` | Remaining Shelley credentials. |
| Credentials | `--start-as-non-producing-node` | | Start without block-production credentials. |
| Host | `--host-addr`, `--host-ipv6-addr` | `IPV4` / `IPV6` | Optional bind addresses. |
| Host | `--port` | `PORT` | Listening port (defaults to an ephemeral port). |
| Tracing | `--tracer-socket-network-accept`, `--tracer-socket-network-connect` | `HOST:PORT` | Connect to / accept a `cardano-tracer` over the network. |
| Tracing | `--tracer-socket-path-accept`, `--tracer-socket-path-connect` | `FILEPATH` | Connect to / accept a `cardano-tracer` over a local socket. |
| Shutdown | `--shutdown-ipc` | `FD` | Shut down when this inherited FD reaches EOF. |
| Shutdown | `--shutdown-on-slot-synced`, `--shutdown-on-block-synced` | `SLOT` / `BLOCK` | Shut down once the ChainDB is synced to the given target. |

`resolveConfiguration` combines `CliArgs` with the parsed file: where a CLI flag
overrides a file key (e.g. `--socket-path`, `--grpc-enable`,
`--grpc-socket-path`), the CLI value takes precedence and the file value is the
fallback.

## What this library parses

The configuration is a single JSON/YAML object. The parsers are derived from
[`autodocodec`](https://hackage.haskell.org/package/autodocodec) codecs, and the
**authoritative, always-up-to-date key listing** (including nested fields,
defaults and validation) is the JSON Schema derived from those very codecs. Dump
it with the bundled executable:

```console
$ cardano-config-schema          # the whole configuration
$ cardano-config-schema --list   # the available components
$ cardano-config-schema Storage  # one component
```

The generated schemas are also committed under [`schemas/`](schemas/) — the whole
configuration (`schemas/config.schema.json`) and one per component
(`schemas/<Component>.schema.json`). The test-suite asserts they match the codecs
(so they cannot drift); regenerate them with `scripts/gen-schemas.sh`.

Keys that none of the parsers below recognise produce a **warning** by default
(so typos are noticed); `parseConfigurationFilesWith RejectUnknownKeys` turns
them into a hard error instead.

The recognised keys are grouped into the following components. Unless noted
otherwise, every key is optional and, when omitted, the node falls back to its
own default.

Every component may be given inline, as a sub-file path, or as a list of sources
(see [Single-file and split forms](#single-file-and-split-forms)).

| Component | Top-level keys |
| --- | --- |
| **Storage** | `DatabasePath`, `LedgerDB` (`Snapshots`, `QueryBatchSize`, `Backend` = `V2InMemory`/`V2LSM`, `LSMDatabasePath`, `LSMExportPath`) |
| **Consensus** | `ConsensusMode` (`PraosMode`/`GenesisMode`), `LowLevelGenesisOptions` (`EnableCSJ`, `EnableLoEAndGDD`, `EnableLoP`, `BlockFetchGracePeriod`, `BucketCapacity`, `BucketRate`, `CSJJumpSize`, `GDDRateLimit`) — Genesis mode only |
| **Protocol** | `ByronGenesisFile`/`ByronGenesisHash`, `RequiresNetworkMagic`, `PBftSignatureThreshold`, `LastKnownBlockVersion-Major`/`-Minor`/`-Alt`, `ShelleyGenesisFile`/`Hash`, `AlonzoGenesisFile`/`Hash`, `ConwayGenesisFile`/`Hash`, `StartAsNonProducingNode`, `CheckpointsFile`/`CheckpointsFileHash` |
| **Network** | `DiffusionMode`, `MaxConcurrencyBulkSync`, `MaxConcurrencyDeadline`, `ProtocolIdleTimeout`, `TimeWaitTimeout`, `EgressPollInterval`, `ChainSyncIdleTimeout`, `AcceptedConnectionsLimit`, the `TargetNumberOf*`/`SyncTargetNumberOf*` peer targets, `MinBigLedgerPeersForTrustedState`, `PeerSharing`, `ResponderCoreAffinityPolicy`, `ExperimentalProtocolsEnabled`, `TxSubmissionLogicVersion`, `TxSubmissionInitDelay` |
| **LocalConnections** | `SocketPath`, `EnableRpc`, `RpcSocketPath` |
| **Mempool** | `MempoolCapacityBytesOverride`, `MempoolTimeoutSoft`, `MempoolTimeoutHard`, `MempoolTimeoutCapacity` |
| **Testing** | `ExperimentalHardForksEnabled`, the `Test<Era>HardForkAtEpoch`/`Test<Era>HardForkAtVersion` knobs (Shelley … Dijkstra), `DijkstraGenesisFile`/`DijkstraGenesisHash` |

### Mandatory vs optional keys

Only **six** keys are mandatory — they have no default and parsing fails if they
are absent:

- `ByronGenesisFile`, `ShelleyGenesisFile`, `AlonzoGenesisFile`,
  `ConwayGenesisFile` (the established-era genesis files), and
- `LastKnownBlockVersion-Major`, `LastKnownBlockVersion-Minor`.

These are network-specific, so they are deliberately *not* in the base defaults;
supply them either directly in your configuration or by referencing a
`Protocol.variants/Protocol.<network>.json` file (which provides them for that
network).

**Every other key is optional**: it either has a default (applied from the
`defaults/` layer — see [Defaults and layering](#defaults-and-layering)) or is
optional by nature, meaning "unset" is a valid state (the `*Hash` keys,
`PBftSignatureThreshold`, `CheckpointsFile`, `LedgerDB.Snapshots`,
`SocketPath`/`RpcSocketPath`, `MempoolCapacityBytesOverride`, the mempool
timeouts, the experimental `DijkstraGenesisFile`, and the `Test<Era>HardForkAt*`
knobs).

### Tracing is *not* parsed

Tracing is owned by the node's tracing system (hermod / `trace-dispatcher`), not
by this library. It is given under a single `HermodTracing` key, whose value is
either an inline object or a path (a string) to a separate file holding it. The
key is recognised and captured **opaquely**: it appears in the schema so that
users can see it exists, but its contents are neither interpreted nor validated
here. The authoritative schema for them lives in `trace-dispatcher`.

## Single-file and split forms

In the **single-file form**, all of the keys above live directly at the top level
of one object:

```console
$ cat config.json
{
    "ConsensusMode": "PraosMode",
    "ByronGenesisFile": "byron-genesis.json",
    "LastKnownBlockVersion-Major": 3,
    "LastKnownBlockVersion-Minor": 0,
    "ShelleyGenesisFile": "shelley-genesis.json",
    "LedgerDB": {
        "Backend": "V2InMemory",
        "NumOfDiskSnapshots": 2,
        "QueryBatchSize": 100000,
        "SnapshotInterval": 4320
    }
}
```

Alternatively, any component (`Storage`, `Consensus`, `Protocol`, `Network`,
`LocalConnections`, `Mempool`, `Testing`) may be **split into a sub-file**: give
the component key a string path (relative to the main config file) instead of an
inline object.

Tracing is handled the same way but by the node's tracing system, not this
library: set `HermodTracing` to a path (relative to the config file) of a
separate file holding all the tracing options. That is the recommended form; an
inline object is also accepted. Either way the contents are passed through
opaquely (see ["Tracing is *not* parsed"](#tracing-is-not-parsed)).

```console
$ cat config.json
{
    "Protocol": "protocol.json",
    "Storage": "storage.json"
}
$ cat storage.json
{
    "LedgerDB": {
        "Backend": "V2InMemory",
        "NumOfDiskSnapshots": 2,
        "QueryBatchSize": 100000,
        "SnapshotInterval": 4320
    }
}
```

A component key may also hold a **list** of sources (paths and/or inline
objects), which are deep-merged in order — a later entry overrides an earlier one,
and nested objects merge recursively:

```console
$ cat config.json
{
    "Network": ["Network.variants/Network.relay.json", { "PeerSharing": false }]
}
```

## Versioning

The configuration may optionally be wrapped in an envelope so the format can
evolve:

```json
{ "Version": 1, "Configuration": { ... } }
```

A document without an envelope is read as version 1 (the keys live at the top
level), so existing configurations keep working.

## Defaults and layering

Every component ships a **default file** under
[`defaults/`](defaults/) (see [`defaults/README.md`](defaults/README.md)). For
each component the layering, from lowest to highest precedence, is:

1. the package's base default (`defaults/<Component>.json`), always applied;
2. the component's value in the configuration file (an inline object, a sub-file
   path, or a list of them merged in order — including the opt-in
   `defaults/<Component>.variants/*` overlays the configuration chooses to
   reference);
3. the matching CLI flag, where one exists.

`cardano-config` is the *origin* of these default files, but each is ultimately
owned by the layer that implements the component (networking, consensus, …); a CI
check keeps the copies here aligned with upstream.

## Design principles

To keep new fields from each making an ad-hoc choice:

- **Where defaults live.** A field that has a real default carries it in the
  `defaults/` files (so the schema only enumerates keys and types, and defaults
  are applied by layering, not baked into the codecs). A field whose "unset"
  state is meaningful (an override, a hash, a feature toggle) stays `Maybe` and
  its default simply *is* "none".
- **Where validation lives.** Structural validation of a single value lives in
  its codec (and thus in the schema). Cross-field validation — constraints that
  span CLI and file values or several components — lives in `resolveConfiguration`
  as a list of `ConfigCheck`s; consumers can add their own with
  `resolveConfigurationWith`.
- **Errors.** File/JSON failures are reported as `ConfigurationParsingError`,
  which records the offending file, section and JSON path. Resolution failures
  are reported as `ConfigResolutionError`, listing the violated checks.
