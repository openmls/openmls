# Interop Client

Interoperability between MLS implementations is tested using a [test-runner] that tells different MLS
implementations what to do, e.g., to create a group, export a group info, make a proposal, commit, etc.

To receive these actions from the test-runner, all implementations need to expose their group handling logic through
a unified gRPC interface. Technically, this interface is exposed through a gRPC server, although the idea is really that
OpenMLS acts like a member of a group.

The gRPC server for OpenMLS is provided here. The test-runner, [MLS++], and [mls-rs] -- other MLS implementations -- are
provided through Docker, which is the supported way to run interop.

## Quickstart

We need three components: the OpenMLS gRPC server, another MLS implementation's gRPC server (MLS++ or mls-rs), and the
test-runner that drives them. All are provided as Docker images and wired together with `docker compose`.

The quickest path is the wrapper script, which builds everything, runs **all** config files against both peers, and
refreshes the [interop status table](#interop-status):

```
cd docker
python3 run-interop.py                      # all configs, both peers (mls-rs + MLS++)
python3 run-interop.py --peers mls-rs       # only against mls-rs
python3 run-interop.py --configs commit.json,welcome_join.json
```

For ad-hoc, single-config runs, drive `docker compose` directly (next section). Running natively without docker is still
possible but **not well tested** -- see [Running natively](#running-natively-not-well-tested).

### Docker compose

Simply navigate to the `./docker` folder and run `docker compose up`. This will build the images, start the services, and run the test.

This will run the `welcome_join.json` config file in the test-runner. To choose a different one, set the environment variable `CONFIG_RUN` prior to starting the services to the desired file name. The variable is set during container creation, so in order to change, it needs to be recreated.

```
CONFIG_RUN=commit.json docker compose up
```

By default, only the OpenMLS service is started. To include MLS++ or mls-rs, use profiles:

```
# Run with MLS++
docker compose --profile mlspp up

# Run with mls-rs
docker compose --profile mls-rs up

# Run with both MLS++ and mls-rs
docker compose --profile all up
```

Alternatively, you can run the test runner directly through this command. Use the `CLIENTS` environment variable to specify which clients to use:

```
# Run with OpenMLS and MLS++
docker compose run test-runner -client openmls:50051 -client mlspp:50052 -config=../configs/commit.json

# Run with OpenMLS and mls-rs
docker compose --profile mls-rs run test-runner -client openmls:50051 -client mls-rs:50053 -config=../configs/commit.json

# Or using the CLIENTS environment variable. Note: do NOT pass any arguments
# after `test-runner` here -- they replace compose's whole command (including the
# -client flags CLIENTS interpolates in), leaving the runner with no clients.
# Select the config with the CONFIG_RUN env var instead.
CLIENTS="-client openmls:50051 -client mls-rs:50053" CONFIG_RUN=commit.json docker compose --profile mls-rs run test-runner
```

All the parameters after the `test-runner` will be passed to the executable. The configs are in the `../configs` folder. The default hostnames and ports are:
- OpenMLS: `openmls:50051`
- MLS++: `mlspp:50052`
- mls-rs: `mls-rs:50053`

The ports are open to the host so one can manually call each of the services. To change the port, set the environment variables `OPENMLS_PORT`, `MLSPP_PORT`, or `MLSRS_PORT` prior to the container creation.

### Running the full matrix

`docker/run-interop.py` is the recommended entry point. It builds the images, starts `openmls` plus the requested peers,
waits for them to be ready (the OpenMLS server compiles on first start), then runs every config file against each peer
and regenerates the status table in this README.

```
Usage:
  python3 run-interop.py [--peers mls-rs,mlspp] [--configs a.json,b.json] [--timeout SECONDS]
                         [--suite N] [--mode both|public|private] [--no-build] [--no-readme] [--no-clean]
```

Run all configs, except for `deep_random`:

```
python3 run-interop.py --configs application.json,branch.json,commit.json,external_join.json,external_proposals.json,reinit.json,welcome_join.json
```

For every config the test-runner is invoked once per peer as `-client openmls:50051 -client <peer>`. The runner then
exercises every client/suite/handshake combination (OpenMLS↔OpenMLS, OpenMLS↔peer in both directions, and peer↔peer);
results are bucketed per pairing to build the [interop status table](#interop-status) and the
[detailed failures](#detailed-failures) list. Each run is bounded by `--timeout` (default 900s). The `deep_random`
stress config is finite but slow (~1670 steps per pairing/suite/mode); pass `--timeout 0` to disable the per-run
timeout and wait for it to complete rather than have it reported as "not completed".

**Faster debugging.** The full fan-out (all ciphersuites × both handshake modes) is slow for a single config. Narrow
it with `--suite N` (a single ciphersuite) and/or `--mode public|private` (a single wire format), e.g.
`python3 run-interop.py --configs external_proposals.json --suite 1 --mode public`. A restricted run prints the table
to stdout but does **not** rewrite the README (its counts are partial). One-off `docker compose run` test-runner
containers are detached from the driver and survive an interrupted run, where they keep loading the shared OpenMLS
server; they are removed automatically after each run and on Ctrl-C (pass `--no-clean` to keep them).

Requires `docker`, `docker compose`, and Python 3.8+ (no external `nc`/`timeout` binaries -- readiness uses sockets and
the per-run timeout is native). It exits non-zero only when there are *genuine* interop failures (🚫 / 🔶 / not-completed
gaps are ignored), so it can gate CI; pass `--exit-zero` to always return 0. See
[Client capabilities and known gaps](#client-capabilities-and-known-gaps) for what the excused gaps mean.

### Notes on interop testing

- Each "step" in the config files is translated to one (or more) gRPC calls. For example, `"action": "externalJoin"` will request a group info, request an external commit from the joiner, and request all members to process the commit.
- References such as `"byReference": [5, 6]` in the config files refer to the **index** of a step in the scenario.
- Currently, the supported ciphersuites are fixed by a patch to `[1, 2, 3]` in the test-runner.
- In order to pinpoint discrepancies, it might help to add (more) logging to OpenMLS or MLS++. Use a Docker volume to persist your changes.

## Interop status

Generated by `docker/run-interop.py` (see [Running the full matrix](#running-the-full-matrix)). Each cell is
`passed/total` script runs for that pairing across ciphersuites 1–3 and both handshake-encryption modes:
✅ all pass, ⚠️ some genuine failures, ❌ all fail, 🚫 no genuine failures but some steps hit an unsupported feature
(reported as a clean gRPC `Unimplemented`, e.g. ReInit), 🔶 no genuine failures but some steps hit a **peer-side
limitation** — either the peer sent RFC-non-conformant data that OpenMLS correctly rejects, or the peer rejected
RFC-valid data that OpenMLS sent (see
[Client capabilities and known gaps](#client-capabilities-and-known-gaps)), — not run. A cell with **any**
genuine failure shows ⚠️/❌ regardless of expected gaps in the same config, so a real bug is never masked by
a 🚫/🔶 alongside it. Only genuine failures (⚠️/❌) are treated as interop bugs; `run-interop.py` exits
non-zero for those and ignores 🚫 / 🔶 gaps, so it can gate CI. The [detailed failures](#detailed-failures)
list every genuine bug up front under **Genuine interop failures** (with a real error sample, never an
`Unimplemented`/GREASE one) before the expected-gap buckets. See
[Client capabilities and known gaps](#client-capabilities-and-known-gaps) for the details behind partial rows.

<!-- INTEROP-TABLE:START -->
| Scenario (config) | OpenMLS ↔ OpenMLS | OpenMLS ↔ mls-rs | OpenMLS ↔ MLS++ |
|---|:---:|:---:|:---:|
| application | ✅ 18/18 | ✅ 36/36 | ✅ 36/36 |
| branch | ✅ 24/24 | 🔶 630/720 | ✅ 720/720 |
| commit | ✅ 54/54 | ✅ 2508/2508 | 🔶 746/2508 |
| external_join | ✅ 30/30 | ✅ 228/228 | ✅ 228/228 |
| external_proposals | ✅ 48/48 | ✅ 696/696 | 🔶 658/696 |
| reinit | ✅ 36/36 | ✅ 1080/1080 | ✅ 1080/1080 |
| welcome_join | ✅ 24/24 | ✅ 48/48 | ✅ 48/48 |
<!-- INTEROP-TABLE:END -->

### Detailed failures

The per-script failures behind the table above, grouped by pairing, each with a representative error. Also generated by
`docker/run-interop.py`; remaining gaps are explained in
[Client capabilities and known gaps](#client-capabilities-and-known-gaps).

<!-- INTEROP-FAILURES:START -->
**Genuine interop failures (interop bugs)**

_No genuine interop failures._

**OpenMLS ↔ mls-rs — peer-side limitation (not counted)**

- `branch / with_extensions` — 90/180 affected — step 1 `branch`: rpc error: code = Aborted desc = Aborted with error ReInitExtensionsMismatch

**OpenMLS ↔ MLS++ — peer-side limitation (not counted)**

- `commit / add` — 1309/1524 affected — step 6 `fullCommit`: rpc error: code = Aborted desc = mls group error A key package extension is not supported in the leaf's capabilities.
- `commit / all_together_alice_proposes` — 169/372 affected — step 15 `fullCommit`: rpc error: code = Aborted desc = mls group error A key package extension is not supported in the leaf's capabilities.
- `commit / all_together_bob_proposes` — 206/372 affected — step 16 `fullCommit`: rpc error: code = Aborted desc = mls group error A key package extension is not supported in the leaf's capabilities.
- `commit / remove` — 78/180 affected — step 7 `fullCommit`: rpc error: code = Aborted desc = mls group error A key package extension is not supported in the leaf's capabilities.
- `external_proposals / external_add` — 33/84 affected — step 5 `fullCommit`: rpc error: code = Aborted desc = mls group error A key package extension is not supported in the leaf's capabilities.
- `external_proposals / joiner_signed_add` — 5/12 affected — step 2 `fullCommit`: rpc error: code = Aborted desc = mls group error A key package extension is not supported in the leaf's capabilities.
<!-- INTEROP-FAILURES:END -->

## Client capabilities and known gaps

The interop client implements the full `MlsClient` surface exercised by the configs above, including
external commits, external self-Add (`new_member_add_proposal`), external signers
(`create_external_signer` / `add_external_signer`), and external-sender proposals for Add / Remove /
GroupContextExtensions / PreSharedKey (external and resumption) / ReInit (see `ExternalProposal` in
`openmls/src/messages/external_proposals.rs`).

`external_proposals` has no genuine OpenMLS failures: every sub-script passes on our side, including
`external_reinit` — external-sender ReInit proposals are now supported (`ExternalProposal::new_reinit`,
accepted on the receiving side and committed into the existing suspend/successor flow). The
`external_add` / `joiner_signed_add` sub-scripts fail 🔶 **only** against MLS++, from its GREASE
non-conformance (see below); they pass against mls-rs and OpenMLS-self.

### Unimplemented (🚫, reported as gRPC `Unimplemented`, never counted as a failure)

_None across the configs exercised above._ Both member-initiated and external-sender **ReInit** are now
implemented (`re_init_proposal`, `re_init_commit`, `handle_*_re_init_*`, `re_init_welcome`, and the
`external_signer_proposal` `reinit` sub-type).

### Peer-side limitations (🔶, not counted)

Two flavours, both classified 🔶 and excluded from the failure count by `run-interop.py` (`is_peer_nonconformance`
and `is_peer_limitation`):

**MLS++ GREASE non-conformance.** MLS++ stamps random GREASE values into `key_package.extensions` without also
listing them in that leaf's `capabilities`. RFC 9420 §7.2 requires every non-default extension in a leaf's
`extensions` to appear in its `capabilities` (no GREASE exemption); OpenMLS (`KeyPackageIn::validate`) and mls-rs
both enforce this, so MLS++ is the outlier. The interop client cannot fix a peer-minted key package, so this error
(`A key package extension is not supported in the leaf's capabilities`) is excluded. Worth filing upstream with
cisco/mlspp.

**mls-rs branch extension strictness.** On `branch / with_extensions`, mls-rs rejects with `ReInitExtensionsMismatch`
when OpenMLS creates the subgroup and mls-rs joins it. mls-rs implements branch by reusing its ReInit join path
(`mls-rs/src/group/resumption.rs`, `join()`), which asserts the subgroup's group-context extensions equal the
**parent's**; its `branch()` ignores any requested new extensions. RFC 9420 §11.3 does not require the subgroup's
extensions to match the parent's — OpenMLS and MLS++ both accept a branch that adds extensions (OpenMLS ↔ MLS++
passes this scenario), and OpenMLS's `StagedWelcome::new_from_branch` deliberately performs no extension-equality
check. This is an mls-rs limitation, not an OpenMLS bug; scoped to the `branch` config so a genuine ReInit mismatch
is never masked. Worth filing upstream with awslabs/mls-rs.

### External-join remove-prior is an application responsibility

Removing the joiner's previous leaf on an external "resync" join (`remove_prior`) is up to the
**application**, not OpenMLS: OpenMLS deliberately does not interpret credentials, so it cannot decide by
identity which existing leaf is "the same member". As a convenience, `ExternalCommitBuilder::build_group`
(`openmls/src/group/mls_group/commit_builder/external_commits.rs`) auto-adds the remove-prior proposal when
an existing member's **signature key** equals the joiner's. An application that rotates signature keys on
rejoin must instead arrange the remove itself (it knows its own identity mapping).

The interop client relies on the signature-key convenience: on `remove_prior` it reuses its prior leaf's
signing key (matched by group id **and** own-leaf identity, to disambiguate self-interop where alice and
bob share one server). This is a legitimate application choice — the client owns its signing key — and makes
OpenMLS↔OpenMLS, OpenMLS↔mls-rs, and OpenMLS↔MLS++ `external_join / removing_prior` all pass.

### deep_random

`deep_random` is a large but finite stress config. The Go test-runner accumulates the entire result tree
in memory and may get OOM-killed (exit 137) while marshaling it, so it may report as "not completed"
even with `--timeout 0`; running it needs a lot of memory for the `test-runner` container.

## Running natively (not well tested)

> **Note:** Docker is the supported path. The native instructions below are kept for convenience but are not regularly
> tested and may be out of date.

Be aware that the network flag used here for docker only works on Linux. Consider using the docker compose in other platforms.

#### Build & start the OpenMLS gRPC server

The OpenMLS gRPC server can be started with ...

```sh
RUST_LOG=interop=info cargo run
```

... and will listen for gRPC commands on port 50051.

You can use the `RUST_LOG` environment variable to control what is logged, e.g., `RUST_LOG=interop=trace,openmls=debug`.
Furthermore, OpenMLS provides the `crypto-debug` feature that unlocks logging of sensitive values such as private keys.

#### Build & start the MLS++ gRPC server

The MLS++ gRPC server can be started by using the provided Dockerfile:

```sh
docker build --tag mlspp docker/mlspp
docker run -p 12345:12345 -it mlspp -live 12345
```

Note: We use an interactive session here in case you want to debug discrepancies between OpenMLS and MLS++.

#### Build & start the mls-rs gRPC server

The mls-rs gRPC server can be started by using the provided Dockerfile:

```sh
docker build --tag mls-rs docker/mls-rs
docker run -p 50053:50053 -it mls-rs -p 50053
```

Note: We use an interactive session here in case you want to debug discrepancies between OpenMLS and mls-rs.

#### Build & run the test-runner

The test-runner can be started by using the provided Dockerfile:

```sh
docker build --tag test-runner docker/test-runner
docker run --network host -it test-runner -fail-fast -client localhost:50051 -client localhost:12345 -config=../configs/welcome_join.json
```

You should now see how the test-runner orchestrated the "welcome" scenario between OpenMLS and MLS++. You can run more scenarios by specifying another config file.

### Native test script

The interop client can be used to have OpenMLS perform interop testing against
itself by running the `test_with_runner.py` script (native, not well tested — prefer `docker/run-interop.py`).

```
USAGE:
    interop_client [OPTIONS]

OPTIONS:
    -h, --host <HOST>    [default: [::1]]
        --help           Print help information
    -p, --port <PORT>    [default: 50051]
```

The script requires

- `cargo` to compile the `interop_client`
- `git` to checkout the code of the test runner
- `go` to compile the `test-runner`

[test-runner]: https://github.com/mlswg/mls-implementations/tree/main/interop/test-runner
[MLS++]: https://github.com/cisco/mlspp
[mls-rs]: https://github.com/awslabs/mls-rs
