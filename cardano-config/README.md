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
| | `--config` | `FILEPATH` | Main configuration file (defaults to the mainnet config). |
| | `--topology` | `FILEPATH` | Topology file (defaults to the mainnet topology). |
| | `--socket-path` | `FILEPATH` | Socket for local clients; overrides `LocalConnections.SocketPath`. |
| | `--grpc-enable` | | [EXPERIMENTAL] Enable the gRPC endpoint; overrides `LocalConnections.EnableRpc`. Absent means *unset* (falls back to the file), not `False`. |
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

Keys that none of the parsers below recognise are **ignored** (parsing neither
fails nor preserves them).

The recognised keys are grouped into the following components. Unless noted
otherwise, every key is optional and, when omitted, the node falls back to its
own default.

| Component | Top-level keys | Sub-file? |
| --- | --- | --- |
| **Storage** | `DatabasePath`, `LedgerDB` (`Snapshots`, `QueryBatchSize`, `Backend` = `V2InMemory`/`V2LSM`, `LSMDatabasePath`, `LSMExportPath`) | yes |
| **Consensus** | `ConsensusMode` (`PraosMode`/`GenesisMode`), `LowLevelGenesisOptions` (`EnableCSJ`, `EnableLoEAndGDD`, `EnableLoP`, `BlockFetchGracePeriod`, `BucketCapacity`, `BucketRate`, `CSJJumpSize`, `GDDRateLimit`) — Genesis mode only | yes |
| **Protocol** | `ByronGenesisFile`/`ByronGenesisHash`, `RequiresNetworkMagic`, `PBftSignatureThreshold`, `LastKnownBlockVersion-Major`/`-Minor`/`-Alt`, `ShelleyGenesisFile`/`Hash`, `AlonzoGenesisFile`/`Hash`, `ConwayGenesisFile`/`Hash`, `StartAsNonProducingNode`, `CheckpointsFile`/`CheckpointsFileHash` | yes |
| **Network** | `DiffusionMode`, `MaxConcurrencyBulkSync`, `MaxConcurrencyDeadline`, `ProtocolIdleTimeout`, `TimeWaitTimeout`, `EgressPollInterval`, `ChainSyncIdleTimeout`, `AcceptedConnectionsLimit`, the `TargetNumberOf*`/`SyncTargetNumberOf*` peer targets, `MinBigLedgerPeersForTrustedState`, `PeerSharing`, `ResponderCoreAffinityPolicy`, `ExperimentalProtocolsEnabled`, `TxSubmissionLogicVersion`, `TxSubmissionInitDelay` | yes |
| **LocalConnections** | `SocketPath`, `EnableRpc`, `RpcSocketPath` | no |
| **Mempool** | `MempoolCapacityBytesOverride`, `MempoolTimeoutSoft`, `MempoolTimeoutHard`, `MempoolTimeoutCapacity` | no |
| **Testing** | `ExperimentalHardForksEnabled`, the `Test<Era>HardForkAtEpoch`/`Test<Era>HardForkAtVersion` knobs (Shelley … Dijkstra), `DijkstraGenesisFile`/`DijkstraGenesisHash` | no |

The genesis files for the established eras — `ByronGenesisFile`,
`ShelleyGenesisFile`, `AlonzoGenesisFile`, `ConwayGenesisFile` — and the
`LastKnownBlockVersion-Major` / `-Minor` keys are required; everything else
(including the `*Hash` keys, the experimental `DijkstraGenesisFile` and
`CheckpointsFile`) is optional.

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

Alternatively, the `Storage`, `Consensus`, `Protocol` and `Network` components
may each be **split into a sub-file**: give the component key a string path
(relative to the main config file) instead of an inline object. The remaining
components (`LocalConnections`, `Mempool`, `Testing`) and the tracing keys are
always read from the main file's top level.

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
