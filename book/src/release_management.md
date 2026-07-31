# Release management

The process for releasing a new version of OpenMLS.

## Versioning

The versioning follows the Rust and semantic [versioning guidelines].

## Release Notes

Release notes are published on GitHub with a full changelog and a discussion in
the "Release" section.
In addition, the release notes are prepended to the CHANGELOG file in each crate's
root folder.
The entries in the CHANGELOG file should follow the [keep a changelog guide].

## Pre-release strategy

Before releasing a minor or major version of the OpenMLS crate, a pre-release version
must be published to crates.io.
Pre-release versions are defined by appending a hyphen, and a series of dot-separated identifiers, i.e., `-rc.x` where `x` gets counted up starting at 1.
Pre-releases must be tagged but don't require release notes or other documentation.
It is also sufficient to tag only the most high-level crate being published.

---

## Crates in this Repository

Publish the workspace with:

```sh
cargo publish --workspace
```

This publishes every workspace member that isn't marked `publish = false` (currently: `traits`, `memory_storage`, `openmls_rust_crypto`, `libcrux_crypto`, `basic_credential`, `openmls_test`, `sqlite_storage`, `serialization_helpers`, `openmls`), resolving the dependency order automatically — you no longer need to publish crate-by-crate in a fixed order. Use `--dry-run` first to verify everything resolves before publishing for real.

`openmls_sqlx_storage` is **not** a workspace member (it's excluded in the root `Cargo.toml` due to build conflicts) and is not covered by `cargo publish --workspace`. Publish it separately:

```sh
cd sqlx_storage
cargo publish --dry-run
cargo publish
```

Its only workspace dependency is `openmls_traits`, so publish it any time after `traits` has gone out — either before or after the `--workspace` batch.

## Release note and changelog template

```markdown
## 0.0.0 (2022-02-22)

### Added

- the feature ([#000])

### Changed

- the change ([#000])

### Deprecated

- the deprecated feature ([#000])

### Removed

- the removed feature ([#000])

### Fixed

- the fixed bug ([#000])

### Security

- the fixed security bug ([#000])

[#000]: https://github.com/openmls/openmls/pull/000
```

## Release checklist

- [ ] If this is a minor or major release, has a pre-release version been published at least a week before the release?
  - If not, first do so and push the release one week.
- [ ] Describe the release in the CHANGELOG.md file of each crate.
- [ ] Create and publish a git tag for each crate, e.g. `openmls/v0.4.0-rc.99`.
- [ ] Create and publish release notes on Github.
- [ ] Publish the workspace with `cargo publish --workspace` (see [Crates in this Repository](#crates-in-this-repository) above), then publish `openmls_sqlx_storage` separately.

[versioning guidelines]: https://semver.org
[keep a changelog guide]: https://keepachangelog.com/en/1.0.0/
