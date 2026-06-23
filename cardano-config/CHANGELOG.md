# Revision history for cardano-config

## 0.1.0.0 -- YYYY-mm-dd

* First version. Released on an unsuspecting world.
* CLI option parser (`parseCliArgs`), JSON/YAML file parsing
  (`parseConfigurationFiles`) and resolution (`resolveConfiguration`) for the
  `cardano-node` configuration, with an `autodocodec`-derived JSON Schema.
* `cardano-config` executable with two subcommands:
  * `cardano-config schema` dumps the `autodocodec`-derived JSON Schema (the
    whole configuration or a single component). The schemas declare a `type` for
    every scalar field (string enumerations use `enum`), flag filesystem paths
    with `"format": "path"`, and carry `title`/`$id` so documentation generators
    (e.g. `jsonschema2md`) render names rather than `Untitled`/`undefined`. Each
    key's `default` is filled in from the `defaults/` files (the single source of
    truth for defaults), so the documented default matches the applied one. The
    whole-configuration schema covers both the single-file and split-file forms
    and the version envelope.
  * `cardano-config resolve` resolves a configuration (defaults + file + CLI
    flags) and prints the complete result as YAML, using the documented
    configuration keys (`Cardano.Configuration.Render` exposes this as
    `nodeConfigurationToJSON`).
* Configuration sources are layered with a deep merge: an always-applied
  per-component default (`defaults/`), then the configuration file (a value, a
  sub-file path, or a list of them), then CLI flags.
* Optional `{ Version, Configuration }` envelope for forward-compatibility.
* Structured parse errors (`ConfigurationParsingError`) and resolution-time
  cross-field checks (`ConfigCheck` / `ConfigResolutionError`).
* Unrecognised top-level keys warn by default; `RejectUnknownKeys` makes them an
  error.
* The whole-configuration schema encodes section/top-level exclusivity: a
  component must be given either under its section key or as its top-level keys,
  not both, so a generic JSON Schema validator flags the combination too.
* Shadowed top-level keys (a component supplied as its own section while one of
  its keys also appears at the top level, where it is then ignored) warn by
  default and are rejected under `RejectUnknownKeys`.
