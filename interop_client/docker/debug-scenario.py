#!/usr/bin/env python3
"""Run a single interop config against one peer and dump the OpenMLS server logs.

This is the helper used to debug individual interop failures: it brings up
`openmls` plus one peer, runs one config file through the test-runner (fail-fast
by default so it stops at the first failing step), then prints the OpenMLS logs
so you can inspect requests/responses and any `trace!`/`info!` you added while
debugging.

Because the `openmls` service mounts the repo and runs `cargo run`, changes to
`interop_client/src` (e.g. a temporary `info!`/`trace!` to dump a peer's key
package extensions) are picked up on `--recreate` (the default). Bump verbosity
with `--log`, e.g. `--log interop=trace`.

Examples:
  ./debug-scenario.py welcome_join.json --peer mlspp --grep "key package"
  ./debug-scenario.py commit.json --peer mls-rs --log interop=trace
"""

import argparse
import os
import socket
import subprocess
import sys
import time

PEER_HOSTPORT = {"mls-rs": "mls-rs:50053", "mlspp": "mlspp:50052"}
HOST_PORT = {"openmls": 50051, "mlspp": 50052, "mls-rs": 50053}
PROFILE = {"mlspp": "mlspp", "mls-rs": "mls-rs"}


def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("config", help="config file name, e.g. welcome_join.json")
    p.add_argument("--peer", default="mlspp", choices=sorted(PEER_HOSTPORT),
                   help="peer to test against (default mlspp)")
    p.add_argument("--grep", default="",
                   help="only print OpenMLS log lines containing this substring")
    p.add_argument("--log", default="interop=info",
                   help="RUST_LOG for the openmls server (default interop=info)")
    p.add_argument("--tail", type=int, default=200,
                   help="number of OpenMLS log lines to show (default 200)")
    p.add_argument("--timeout", type=int, default=180,
                   help="test-runner timeout in seconds (default 180)")
    p.add_argument("--no-fail-fast", dest="fail_fast", action="store_false",
                   help="run the whole config instead of stopping at the first failure")
    p.add_argument("--no-recreate", dest="recreate", action="store_false",
                   help="do not recreate the openmls container (skip picking up source edits)")
    return p.parse_args()


def wait_port(name, port, timeout):
    print(f"==> waiting for {name} on :{port} ", end="", flush=True)
    waited = 0
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                print(f" ready ({waited}s)")
                return
        except OSError:
            pass
        time.sleep(3)
        waited += 3
        print(".", end="", flush=True)
        if waited >= timeout:
            print(" TIMEOUT")
            sys.exit(f"{name} did not become ready in {timeout}s")


def main():
    args = parse_args()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    peer = args.peer
    profile_args = ["--profile", PROFILE[peer]]
    env = {**os.environ, "RUST_LOG": args.log}

    up = ["docker", "compose", *profile_args, "up", "-d"]
    if args.recreate:
        up.append("--force-recreate")
    up += ["openmls", peer]
    print(f"==> starting openmls + {peer} (RUST_LOG={args.log})")
    subprocess.run(up, check=True, env=env)

    wait_port("openmls", HOST_PORT["openmls"], 600)  # first start compiles
    wait_port(peer, HOST_PORT[peer], 180)

    run = ["docker", "compose", *profile_args, "run", "--rm", "-T", "test-runner"]
    if args.fail_fast:
        run.append("-fail-fast")
    run += ["-client", "openmls:50051", "-client", PEER_HOSTPORT[peer],
            f"-config=../configs/{args.config}"]
    print(f"==> running {args.config} against {peer}")
    try:
        res = subprocess.run(run, capture_output=True, text=True, timeout=args.timeout)
        rc = res.returncode
        print(res.stdout[-4000:])
        if res.stderr.strip():
            print(res.stderr[-2000:], file=sys.stderr)
    except subprocess.TimeoutExpired:
        rc = None
        print(f"    test-runner timed out after {args.timeout}s")

    print(f"\n==> OpenMLS logs (test-runner rc={rc}):")
    logs = subprocess.run(
        ["docker", "compose", *profile_args, "logs", "--no-color", "openmls"],
        capture_output=True, text=True)
    lines = logs.stdout.splitlines()
    if args.grep:
        lines = [ln for ln in lines if args.grep in ln]
    for ln in lines[-args.tail:]:
        print(ln)


if __name__ == "__main__":
    main()
