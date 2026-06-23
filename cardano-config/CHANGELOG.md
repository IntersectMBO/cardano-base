# Revision history for cardano-config

## 0.1.0.0 -- YYYY-mm-dd

* First version. Released on an unsuspecting world.
* CLI option parser (`parseCliArgs`), JSON/YAML file parsing
  (`parseConfigurationFiles`) and resolution (`resolveConfiguration`) for the
  `cardano-node` configuration, with an `autodocodec`-derived JSON Schema
  (`cardano-config-schema`).
* Configuration sources are layered with a deep merge: an always-applied
  per-component default (`defaults/`), then the configuration file (a value, a
  sub-file path, or a list of them), then the optional top-level `Custom`
  override layer (an inline object or a sub-file path), then CLI flags.
* Top-level `Custom` key: a whole-configuration object (given inline or as a
  path to a JSON/YAML file) deep-merged on top of every other file layer, so it
  overrides individual keys while leaving their siblings intact. CLI arguments
  still take precedence.
* Optional `{ Version, Configuration }` envelope for forward-compatibility.
* Structured parse errors (`ConfigurationParsingError`) and resolution-time
  cross-field checks (`ConfigCheck` / `ConfigResolutionError`).
* Unrecognised top-level keys warn by default; `RejectUnknownKeys` makes them an
  error.
