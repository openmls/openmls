#!/usr/bin/env python3
"""Run the full MLS interop matrix (OpenMLS vs mls-rs / MLS++) via docker compose
and refresh the status table + failure list in ../README.md.

For every config file, the test-runner is invoked once per peer with
`-client openmls:50051 -client <peer>`. The runner's ClientModeAll then
exercises every client/suite/handshake combination, which yields three buckets
per run: openmls-self, peer-self, and openmls x peer (both directions). We parse
each run's JSON result tree, bucket every ScriptResult by the client name in its
`actors` map, and regenerate two blocks in README.md: a per-config status table
(INTEROP-TABLE markers) and a detailed per-script failure list (INTEROP-FAILURES
markers).

Failures are classified into three kinds, and only the first counts as an
interop bug:
  * genuine bug      — a real interoperability failure (⚠️ if some cases still
                       pass, ❌ if all fail).
  * unsupported (🚫) — the error carries `code = Unimplemented`; a feature
                       OpenMLS does not implement (e.g. reinit, branch).
  * peer RFC          non-conformance (🔶) — the *peer* sent RFC-non-conformant
                       data that OpenMLS correctly rejects (see
                       PEER_NONCONFORMANCE_MARKERS). Cannot be fixed from our
                       side; not our bug.

Usage:
  ./run-interop.py [--peers mls-rs,mlspp] [--configs a.json,b.json]
                   [--timeout SECONDS] [--suite N] [--mode both|public|private]
                   [--no-build] [--no-readme] [--no-clean] [--exit-zero]

Defaults: both peers, all config files in the test-runner image, all
ciphersuites, both handshake modes, build images, 900s per-run timeout, update
the README, clean up leftover test-runner containers. Pass `--timeout 0` to
disable the per-run timeout entirely and wait for completion (needed for
`deep_random`, a long but finite stress config).

Debugging: `--suite N` (single ciphersuite) and `--mode public|private` (single
handshake wire format) shrink the fan-out dramatically for quick iteration. A
restricted run does not rewrite the README, since its counts are partial.

Cleanup: on exit (normal or Ctrl-C) the driver removes the one-off `docker
compose run` test-runner containers and brings the services it started (openmls
+ the selected peers) down. Pass `--no-clean` to leave everything running, e.g.
to iterate with `debug-scenario.py` or manual `docker compose` against the same
services.

CI: by default the run exits non-zero iff there is at least one *genuine* interop
bug. Unsupported features (🚫), peer RFC non-conformance (🔶), and not-completed
runs (e.g. deep_random timing out) are expected and do not fail the run. Pass
--exit-zero to always return 0 (local convenience when you just want the table).

Requires: docker, docker compose, and Python 3.8+. No external `nc`/`timeout`
binaries are used (readiness uses sockets; the per-run timeout is native).
"""

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

# The name each client reports via the `Name` RPC (recorded in every result's
# `actors` map). OpenMLS reports the constant "OpenMLS" (IMPLEMENTATION_NAME in
# interop_client/src/main.rs); peers report their own names (e.g. mls-rs reports
# "Wickr MLS on port 50053"). We bucket results by this OpenMLS name, not by the
# host:port we dial.
OPENMLS_ID_NAME = "OpenMLS"

OPENMLS_HOSTPORT = "openmls:50051"
# host:port each client is reached at from *inside* the compose network, and the
# port each service publishes to the host (for readiness checks) + its profile.
PEER_HOSTPORT = {"mls-rs": "mls-rs:50053", "mlspp": "mlspp:50052"}
HOST_PORT = {"openmls": 50051, "mlspp": 50052, "mls-rs": 50053}
PROFILE = {"mlspp": "mlspp", "mls-rs": "mls-rs"}

T_START, T_END = "<!-- INTEROP-TABLE:START -->", "<!-- INTEROP-TABLE:END -->"
F_START, F_END = "<!-- INTEROP-FAILURES:START -->", "<!-- INTEROP-FAILURES:END -->"
COL_TITLE = {
    "self": "OpenMLS ↔ OpenMLS",
    "mls-rs": "OpenMLS ↔ mls-rs",
    "mlspp": "OpenMLS ↔ MLS++",
}


def parse_args():
    p = argparse.ArgumentParser(
        description="Run the OpenMLS interop matrix and refresh the README status table.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--peers", default="mls-rs,mlspp",
                   help="comma-separated peers to test against (mls-rs,mlspp)")
    p.add_argument("--configs", default="",
                   help="comma-separated config files; default = all in the test-runner image")
    p.add_argument("--timeout", type=int, default=900,
                   help="per (config, peer) run timeout in seconds (default 900); "
                        "0 disables the timeout and waits for completion "
                        "(needed for the finite-but-slow deep_random config)")
    p.add_argument("--suite", type=int, default=0,
                   help="restrict to a single ciphersuite (test-runner -suite N) for "
                        "faster debugging; 0 = all ciphersuites (default). A restricted "
                        "run does not rewrite the README (partial counts).")
    p.add_argument("--mode", choices=["both", "public", "private"], default="both",
                   help="restrict handshake wire format: 'public' (PublicMessage) or "
                        "'private' (PrivateMessage) for faster debugging; 'both' = default. "
                        "A restricted run does not rewrite the README (partial counts).")
    p.add_argument("--no-build", dest="build", action="store_false",
                   help="do not rebuild images before starting")
    p.add_argument("--no-readme", dest="readme", action="store_false",
                   help="print the generated blocks to stdout instead of writing README.md")
    p.add_argument("--no-clean", dest="clean", action="store_false",
                   help="leave all containers running after the run; by default the driver "
                        "removes the one-off test-runner containers AND brings the services it "
                        "started (openmls + peers) down, also on Ctrl-C. Use this to keep the "
                        "services up for manual `docker compose` / debug-scenario.py runs")
    p.add_argument("--exit-zero", action="store_true",
                   help="always exit 0; by default the run exits non-zero when there "
                        "are genuine interop bugs (for CI), ignoring expected gaps")
    return p.parse_args()


def run(cmd, **kw):
    """Thin subprocess.run wrapper (list command, no shell)."""
    return subprocess.run(cmd, **kw)


def compose(profile_args, *args, **kw):
    return run(["docker", "compose", *profile_args, *args], **kw)


def list_configs(profile_args):
    """Enumerate config files from inside the test-runner image."""
    res = compose(
        profile_args, "run", "--rm", "-T", "--entrypoint", "sh", "test-runner",
        "-c", "ls -1 ../configs/*.json",
        capture_output=True, text=True,
    )
    cfgs = [os.path.basename(line.strip())
            for line in res.stdout.splitlines() if line.strip()]
    return cfgs


def wait_port(name, port, timeout, profile_args):
    print(f"==> waiting for {name} on :{port} ", end="", flush=True)
    waited = 0
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                print(f" ready ({waited}s)")
                return
        except OSError:
            pass
        time.sleep(2)
        waited += 2
        print(".", end="", flush=True)
        if waited >= timeout:
            print(" TIMEOUT")
            print(f"    {name} did not become ready in {timeout}s", file=sys.stderr)
            compose(profile_args, "logs", "--tail=40", name)
            sys.exit(1)


def run_one(cfg, peer, timeout, profile_args, suite=0, mode="both"):
    """Run the test-runner for one (config, peer). Returns (rc, stdout, timed_out).

    A `timeout` of 0 (or None) disables the per-run timeout and waits for the run
    to finish -- required for the finite-but-slow `deep_random` config.

    `suite` (non-zero) restricts to a single ciphersuite and `mode`
    ('public'/'private') restricts the handshake wire format -- both for faster
    debugging (they map to the test-runner's -suite / -public / -private flags)."""
    runner_args = []
    if suite:
        runner_args += ["-suite", str(suite)]
    if mode == "public":
        runner_args += ["-public"]
    elif mode == "private":
        runner_args += ["-private"]
    cmd = [
        "docker", "compose", *profile_args, "run", "--rm", "-T", "test-runner",
        "-client", OPENMLS_HOSTPORT, "-client", PEER_HOSTPORT[peer],
        *runner_args,
        f"-config=../configs/{cfg}",
    ]
    try:
        res = run(cmd, capture_output=True, text=True, timeout=timeout or None)
        return res.returncode, res.stdout, res.stderr, False
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = e.stderr or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        return None, out, err, True


def clean_runners():
    """Force-remove leftover one-off test-runner containers.

    `docker compose run` spawns detached `*-test-runner-run-*` containers that
    outlive this driver if it is interrupted (Ctrl-C / kill / crash). Left alone,
    they keep driving the shared OpenMLS server and slow every subsequent run, so
    we clean them up defensively after the matrix and on signals."""
    try:
        res = run(["docker", "ps", "-aq", "--filter", "name=test-runner-run"],
                  capture_output=True, text=True)
        ids = [i for i in res.stdout.split() if i]
        if ids:
            run(["docker", "rm", "-f", *ids], capture_output=True, text=True)
            print(f"==> cleaned {len(ids)} leftover test-runner container(s)")
    except Exception as e:  # best-effort; never mask the real result
        print(f"    WARNING: failed to clean test-runner containers: {e}",
              file=sys.stderr)


def teardown(profile_args):
    """Stop and remove the compose services this driver started.

    We bring the whole `mls-interop` project down (openmls + the selected peers
    + the network). This driver starts those services with `compose up -d`, so
    without an explicit teardown they keep running long after the matrix
    finishes. The openmls service mounts the repo (and thus its `target/`) from
    the host, so a later run recompiles only incrementally -- tearing the
    services down here is cheap. `docker compose down` also removes any container
    still attached to the network, so it is called after `clean_runners()`."""
    try:
        compose(profile_args, "down", "--remove-orphans",
                capture_output=True, text=True)
        print("==> stopped interop services")
    except Exception as e:  # best-effort; never mask the real result
        print(f"    WARNING: failed to stop interop services: {e}",
              file=sys.stderr)


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #

def bucket(actors, peer):
    """Map a result's actor->client map to a pairing column, or None to skip."""
    names = set(actors.values())
    if names == {OPENMLS_ID_NAME}:
        return "self"
    if OPENMLS_ID_NAME in names and len(names) == 2:
        return peer            # openmls x peer (either direction)
    return None                # peer-self or unrelated -- not shown


def sample_of(r):
    err = r.get("error")
    step = r.get("failed_step")
    action = ""
    fj = r.get("failed_step_json")
    if fj:
        try:
            action = json.loads(fj).get("action", "")
        except Exception:
            action = ""
    txt = "" if err is None else str(err)
    txt = txt.replace("\n", " ").strip()
    if len(txt) > 200:
        txt = txt[:197] + "..."
    where = f"step {step}" + (f" `{action}`" if action else "")
    return f"{where}: {txt}" if txt else where


def is_unsupported(r):
    """A failed result whose error reports a clean gRPC Unimplemented status is an
    expected 'feature not supported' gap, not an interop bug."""
    err = r.get("error")
    return err is not None and "code = Unimplemented" in str(err)


# Errors that are the *peer's* RFC violation, not an OpenMLS interop bug. OpenMLS
# correctly rejects the message; the failure is expected and must not count.
#
# - MLS++ sprinkles GREASE values into `key_package.extensions` that it does not
#   also list in that leaf's `capabilities`. RFC 9420 §7.2 requires every
#   non-default extension type in a leaf's `extensions` to appear in that same
#   leaf's `capabilities`, with no GREASE exemption; mls-rs and OpenMLS both
#   enforce this. OpenMLS rejects with the marker below. This cannot be fixed
#   from our side: the offending key package is minted by the peer.
PEER_NONCONFORMANCE_MARKERS = (
    "A key package extension is not supported in the leaf's capabilities",
)


def is_peer_nonconformance(r):
    """A failed result caused by the *peer* sending RFC-non-conformant data that
    OpenMLS correctly rejects. Not an interop bug on our side."""
    err = r.get("error")
    if err is None:
        return False
    text = str(err)
    return any(m in text for m in PEER_NONCONFORMANCE_MARKERS)


def is_peer_limitation(name, r):
    """A failed result caused by a *peer's* over-strict limitation rejecting
    RFC-valid data that OpenMLS sends. The mirror image of `is_peer_nonconformance`
    (there the peer sends bad data we reject; here the peer rejects our good data).
    Not an interop bug on our side.

    - mls-rs reuses its ReInit join path for branch and asserts the subgroup's
      group-context extensions equal the *parent's* (`resumption.rs` `join()`),
      so it rejects a branch that adds new extensions with `ReInitExtensionsMismatch`.
      RFC 9420 §11.3 does not require the subgroup's extensions to match the
      parent's; OpenMLS and MLS++ both accept it (our `new_from_branch` does not
      check extension-equality). Scoped to the `branch` config so a genuine ReInit
      mismatch (were ReInit ever implemented) is never masked.
    """
    err = r.get("error")
    return name == "branch" and err is not None and "ReInitExtensionsMismatch" in str(err)


def aggregate(manifest, peer_order):
    """Build the status table and detailed-failures markdown from the run manifest.

    manifest: list of (config_name, peer, path|"MISSING"|"TIMEOUT").
    Returns (table_md, failures_md).
    """
    cols = ["self"] + peer_order
    # stats[config][col] = {"passed", "unsupported", "nonconformant", "total"}
    stats = {}
    # fails[col][(config, script)] = {"failed", "unsupported", "nonconformant",
    #                                 "total", "sample"}
    fails = {c: {} for c in cols}
    not_completed = []          # (config, peer, reason)
    seen_self = set()           # dedupe openmls-self across peer runs
    configs = []

    def acc(config, col):
        return stats.setdefault(config, {}).setdefault(
            col, {"passed": 0, "unsupported": 0, "nonconformant": 0, "total": 0})

    for cfg, peer, path in manifest:
        name = cfg[:-5] if cfg.endswith(".json") else cfg
        if name not in stats:
            stats[name] = {}
            configs.append(name)
        if path in ("MISSING", "TIMEOUT"):
            not_completed.append(
                (name, peer, "timeout" if path == "TIMEOUT" else "no result"))
            continue
        with open(path) as fh:
            data = json.load(fh)
        for script, results in data.get("scripts", {}).items():
            for r in results:
                col = bucket(r.get("actors", {}), peer)
                if col is None:
                    continue
                if col == "self":
                    key = (name, script, r.get("cipher_suite"), r.get("encrypt_flag"))
                    if key in seen_self:
                        continue
                    seen_self.add(key)
                a = acc(name, col)
                a["total"] += 1
                if r.get("failed_step") is None:
                    a["passed"] += 1
                    continue
                unsupported = is_unsupported(r)
                nonconformant = not unsupported and (
                    is_peer_nonconformance(r) or is_peer_limitation(name, r))
                if unsupported:
                    a["unsupported"] += 1
                elif nonconformant:
                    a["nonconformant"] += 1
                fe = fails[col].setdefault(
                    (name, script),
                    {"failed": 0, "unsupported": 0, "nonconformant": 0,
                     "total": 0, "sample": "", "genuine_sample": ""})
                fe["failed"] += 1
                if unsupported:
                    fe["unsupported"] += 1
                elif nonconformant:
                    fe["nonconformant"] += 1
                if not fe["sample"]:
                    fe["sample"] = sample_of(r)
                # Track a sample from a *genuine* failure separately, so the bugs
                # bucket never renders an `Unimplemented`/GREASE message (which
                # would make a real bug read as a known gap).
                if not unsupported and not nonconformant and not fe["genuine_sample"]:
                    fe["genuine_sample"] = sample_of(r)
        # second pass: per (col, script) totals for "n/N failed" context
        for script, results in data.get("scripts", {}).items():
            for r in results:
                col = bucket(r.get("actors", {}), peer)
                if col is None:
                    continue
                fe = fails[col].get((name, script))
                if fe is not None:
                    fe["total"] += 1

    def genuine_fails(v):
        return v["total"] - v["passed"] - v["unsupported"] - v["nonconformant"]

    def cell(v):
        if v is None or v["total"] == 0:
            return "—"
        passed, total = v["passed"], v["total"]
        unsup, nonconf = v["unsupported"], v["nonconformant"]
        genuine_fail = genuine_fails(v)
        if genuine_fail > 0:
            mark = "⚠️" if passed else "❌"
        elif unsup and nonconf:
            mark = "🚫"        # mixed expected gaps (feature + peer-side limitation)
        elif nonconf:
            mark = "🔶"        # peer-side limitation (peer sends bad data we reject,
                               # or peer rejects RFC-valid data we send); not our bug
        elif unsup:
            mark = "🚫"        # only unsupported features remain
        else:
            mark = "✅"
        return f"{mark} {passed}/{total}"

    # --- status table ---
    header = "| Scenario (config) | " + " | ".join(COL_TITLE[c] for c in cols) + " |"
    sep = "|" + "---|" + "".join(":---:|" for _ in cols)
    tbl = [header, sep]
    for name in sorted(configs):
        tbl.append(f"| {name} | "
                   + " | ".join(cell(stats[name].get(c)) for c in cols) + " |")
    table = "\n".join(tbl)

    # --- detailed failures ---
    # Each (config, script) entry is placed in exactly one bucket: genuine bugs
    # (something failed beyond expected gaps), else peer non-conformance, else
    # unsupported feature.
    def fe_genuine(fe):
        return fe["failed"] - fe["unsupported"] - fe["nonconformant"]

    # Bucket every (config, script) failure per pairing: genuine bug, else peer
    # non-conformance, else unsupported feature.
    buckets = {}  # col -> (bugs, nonconf, unsup)
    for c in cols:
        bugs, nonconf, unsup = {}, {}, {}
        for k, fe in fails[c].items():
            if fe_genuine(fe) > 0:
                bugs[k] = fe
            elif fe["nonconformant"] >= fe["unsupported"]:
                nonconf[k] = fe
            else:
                unsup[k] = fe
        buckets[c] = (bugs, nonconf, unsup)

    fl = []

    # --- genuine interop failures first, loudly and unmistakably ---
    # These are the only errors that count as interop bugs; list them at the top,
    # across all pairings, with a *genuine* error sample (never an
    # `Unimplemented`/GREASE message) so a real bug is never mistaken for a known
    # gap like ReInit.
    fl.append("**Genuine interop failures (interop bugs)**")
    fl.append("")
    any_genuine = any(buckets[c][0] for c in cols)
    if not any_genuine:
        fl.append("_No genuine interop failures._")
    else:
        for c in cols:
            bugs = buckets[c][0]
            for (name, script) in sorted(bugs):
                fe = bugs[(name, script)]
                sample = fe["genuine_sample"] or fe["sample"]
                fl.append(f"- ⚠️ `{name} / {script}` — {COL_TITLE[c]}"
                          f" — {fe_genuine(fe)}/{fe['total']} failed — {sample}")
    fl.append("")

    # --- expected gaps, grouped by pairing ---
    for c in cols:
        bugs, nonconf, unsup = buckets[c]
        if not (nonconf or unsup):
            continue
        if nonconf:
            fl.append(f"**{COL_TITLE[c]} — peer-side limitation (not counted)**")
            fl.append("")
            for (name, script) in sorted(nonconf):
                fe = nonconf[(name, script)]
                fl.append(f"- `{name} / {script}` — {fe['failed']}/{fe['total']} affected"
                          f" — {fe['sample']}")
            fl.append("")
        if unsup:
            fl.append(f"**{COL_TITLE[c]} — unsupported (expected)**")
            fl.append("")
            for (name, script) in sorted(unsup):
                fe = unsup[(name, script)]
                fl.append(f"- `{name} / {script}` — {fe['failed']}/{fe['total']} unsupported"
                          f" — {fe['sample']}")
            fl.append("")
    if not_completed:
        items = ", ".join(f"{n} vs {p} ({why})" for (n, p, why) in not_completed)
        fl.append(f"_Not completed: {items}._")
    failures = "\n".join(fl).rstrip()

    total_genuine = sum(genuine_fails(v) for cfg in stats.values()
                        for v in cfg.values())
    return table, failures, total_genuine


def splice(text, start, end, body, label):
    block = f"{start}\n{body}\n{end}"
    if start in text and end in text:
        return text[:text.index(start)] + block + text[text.index(end) + len(end):]
    sys.stderr.write(f"WARNING: {label} markers not found in README; block not written\n")
    return text


def extract_block(text, start, end):
    """The text strictly between the `start` and `end` markers, or "" if absent."""
    if start in text and end in text:
        return text[text.index(start) + len(start):text.index(end)].strip("\n")
    return ""


# --- partial-run merge ---------------------------------------------------------
# A partial run (`--configs a.json` and/or `--peers x`) only produces data for the
# configs/pairings it ran. To avoid clobbering the rest of the README, the newly
# rendered blocks are MERGED with the existing ones: cells/bullets for the
# configs+columns run this session are replaced; everything else is preserved.
# A full run (no `--configs`) naturally regenerates every row.

_TITLE_TO_COL = {v: k for k, v in COL_TITLE.items()}
_CANON_COLS = ["self", "mls-rs", "mlspp"]


def parse_table_cells(block):
    """Parse a rendered status table into `{config: {col_key: cell}}` plus the
    ordered list of column keys seen in its header."""
    rows = {}
    lines = [ln for ln in block.splitlines() if ln.strip().startswith("|")]
    if len(lines) < 2:
        return rows, []
    header = [c.strip() for c in lines[0].strip().strip("|").split("|")]
    col_keys = [_TITLE_TO_COL.get(t) for t in header[1:]]
    for line in lines[2:]:  # skip header + separator row
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or not cells[0]:
            continue
        name = cells[0]
        rows[name] = {ck: val for ck, val in zip(col_keys, cells[1:]) if ck}
    return rows, [c for c in col_keys if c]


def merge_table_block(existing_block, new_block):
    """Cell-level merge: a config+column that was rendered fresh in `new_block`
    wins; any other cell (config not run, or peer not run this session) is kept
    from `existing_block`."""
    old, old_cols = parse_table_cells(existing_block)
    new, new_cols = parse_table_cells(new_block)
    seen = set(old_cols) | set(new_cols)
    cols = [c for c in _CANON_COLS if c in seen]
    configs = sorted(set(old) | set(new))

    def cell_for(name, col):
        if name in new and col in new[name]:
            return new[name][col]
        if name in old and col in old[name]:
            return old[name][col]
        return "—"

    header = "| Scenario (config) | " + " | ".join(COL_TITLE[c] for c in cols) + " |"
    sep = "|" + "---|" + "".join(":---:|" for _ in cols)
    out = [header, sep]
    for name in configs:
        out.append("| " + name + " | "
                   + " | ".join(cell_for(name, c) for c in cols) + " |")
    return "\n".join(out)


def parse_failure_bullets(block):
    """Parse a rendered failures block into `{(kind, col): {config: [bullet, ...]}}`,
    where `kind` is 'genuine'/'nonconf'/'unsup' and `col` is the pairing key (None
    for the genuine section). The trailing `_Not completed: …_` line, if any, is
    returned separately."""
    entries = {}
    not_completed = None
    kind, col = None, None
    for line in block.splitlines():
        s = line.strip()
        if s.startswith("**") and s.endswith("**"):
            title = s.strip("*").strip()
            if title.startswith("Genuine interop failures"):
                kind, col = "genuine", None
            elif title.endswith("— peer-side limitation (not counted)"):
                kind, col = "nonconf", _TITLE_TO_COL.get(title.split(" — ")[0])
            elif title.endswith("— unsupported (expected)"):
                kind, col = "unsup", _TITLE_TO_COL.get(title.split(" — ")[0])
            else:
                kind, col = None, None
            continue
        if s.startswith("_Not completed:"):
            not_completed = s
            continue
        if s.startswith("- ") and kind is not None:
            m = re.search(r"`([^`]+)`", s)
            if not m:
                continue
            cfg = m.group(1).split(" / ")[0].strip()
            entries.setdefault((kind, col), {}).setdefault(cfg, []).append(line)
    return entries, not_completed


def merge_failures_block(existing_block, new_block, run_configs):
    """Merge failure bullets: for configs run this session use the fresh bullets
    (which may be none, i.e. now-fixed), and preserve bullets for every other
    config. Re-render in the same layout as `aggregate`."""
    old, _ = parse_failure_bullets(existing_block)
    new, new_not_completed = parse_failure_bullets(new_block)
    run = set(run_configs)

    merged = {}
    for key in set(old) | set(new):
        d = {cfg: b for cfg, b in old.get(key, {}).items() if cfg not in run}
        d.update(new.get(key, {}))  # fresh entries for run configs (drops stale)
        if d:
            merged[key] = d

    fl = ["**Genuine interop failures (interop bugs)**", ""]
    genuine = merged.get(("genuine", None), {})
    if not genuine:
        fl.append("_No genuine interop failures._")
    else:
        for cfg in sorted(genuine):
            fl.extend(genuine[cfg])
    fl.append("")
    for c in _CANON_COLS:
        for kind, label in (("nonconf", "peer-side limitation (not counted)"),
                            ("unsup", "unsupported (expected)")):
            section = merged.get((kind, c))
            if not section:
                continue
            fl.append(f"**{COL_TITLE[c]} — {label}**")
            fl.append("")
            for cfg in sorted(section):
                fl.extend(section[cfg])
            fl.append("")
    if new_not_completed:
        fl.append(new_not_completed)
    return "\n".join(fl).rstrip()


def main():
    args = parse_args()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    readme = "../README.md"

    peers = [p for p in args.peers.split(",") if p]
    for p in peers:
        if p not in PEER_HOSTPORT:
            sys.exit(f"unknown peer: {p} (want mls-rs and/or mlspp)")

    profile_args = []
    services = ["openmls"]
    for p in peers:
        profile_args += ["--profile", PROFILE[p]]
        services.append(p)

    if args.configs:
        config_list = [c for c in args.configs.split(",") if c]
    else:
        config_list = list_configs(profile_args)
        if not config_list:
            sys.exit("could not list config files from the test-runner image")

    # A restricted (single-suite / single-mode) run produces partial counts, so
    # it must not overwrite the README's full-matrix table.
    restricted = args.suite != 0 or args.mode != "both"
    if restricted and args.readme:
        args.readme = False
        print("==> restricted run (suite/mode): not writing README")

    # Clean up leftover one-off runners on Ctrl-C / termination, then exit.
    if args.clean:
        def _on_signal(signum, _frame):
            print(f"\n==> received signal {signum}; cleaning up", file=sys.stderr)
            clean_runners()
            teardown(profile_args)
            sys.exit(128 + signum)
        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)

    print(f"==> peers:    {' '.join(peers)}")
    print(f"==> configs:  {' '.join(config_list)}")
    print(f"==> suite:    {args.suite if args.suite else 'all'}")
    print(f"==> mode:     {args.mode}")
    print(f"==> timeout:  {f'{args.timeout}s per run' if args.timeout else 'disabled (wait for completion)'}")

    # --- bring services up ---
    if args.build:
        print(f"==> building & starting services ({' '.join(services)})")
        compose(profile_args, "up", "-d", "--build", *services, check=True)
    else:
        print(f"==> starting services ({' '.join(services)})")
        compose(profile_args, "up", "-d", *services, check=True)

    wait_port("openmls", HOST_PORT["openmls"], 900, profile_args)  # first run compiles
    for p in peers:
        wait_port(p, HOST_PORT[p], 180, profile_args)

    # --- run the matrix ---
    manifest = []
    try:
        with tempfile.TemporaryDirectory() as out_dir:
            for cfg in config_list:
                for p in peers:
                    print(f"==> running {cfg} against {p}")
                    rc, out, err, timed_out = run_one(
                        cfg, p, args.timeout, profile_args,
                        suite=args.suite, mode=args.mode)
                    path = os.path.join(out_dir, f"{cfg[:-5]}__{p}.json")
                    with open(path, "w") as fh:
                        fh.write(out)
                    try:
                        json.loads(out)
                        manifest.append((cfg, p, path))
                    except json.JSONDecodeError:
                        if timed_out:
                            print(f"    TIMEOUT after {args.timeout}s ({cfg}/{p})",
                                  file=sys.stderr)
                            manifest.append((cfg, p, "TIMEOUT"))
                        else:
                            print(f"    WARNING: no valid JSON from {cfg}/{p} "
                                  f"(connection or config error, rc={rc}):", file=sys.stderr)
                            for line in (err or "").splitlines()[-3:]:
                                print(f"      {line}", file=sys.stderr)
                            manifest.append((cfg, p, "MISSING"))

            table, failures, genuine_fails = aggregate(manifest, peers)
    finally:
        if args.clean:
            clean_runners()
            teardown(profile_args)

    print()
    print(table)
    print()
    print(failures)

    if args.readme:
        with open(readme) as fh:
            text = fh.read()
        # Merge into the existing README rather than replacing it wholesale, so a
        # partial run (`--configs`/`--peers`) only updates the rows/bullets it
        # actually produced and leaves the rest intact.
        run_config_names = [c[:-5] if c.endswith(".json") else c for c in config_list]
        table = merge_table_block(extract_block(text, T_START, T_END), table)
        failures = merge_failures_block(
            extract_block(text, F_START, F_END), failures, run_config_names)
        text = splice(text, T_START, T_END, table, "INTEROP-TABLE")
        text = splice(text, F_START, F_END, failures, "INTEROP-FAILURES")
        with open(readme, "w") as fh:
            fh.write(text)
        sys.stderr.write(f"==> updated table + failures in {readme}\n")

    # CI exit status: only *genuine* interop bugs are fatal. Unsupported features
    # (🚫) and peer RFC non-conformance (🔶) are expected and do not fail the run.
    # Timeouts / missing results are reported but not fatal (e.g. deep_random
    # never terminates). Pass --exit-zero to always return 0 (local convenience).
    print("==> done")
    if genuine_fails and not args.exit_zero:
        sys.stderr.write(
            f"==> {genuine_fails} genuine interop failure(s) — exiting non-zero\n")
        sys.exit(1)
    print(f"==> no genuine interop failures ({genuine_fails} bugs, excused gaps ignored)")


if __name__ == "__main__":
    main()
