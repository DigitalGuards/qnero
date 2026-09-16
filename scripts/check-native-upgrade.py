#!/usr/bin/env python3
"""Mine and reconnect two ordinary loopback dev forks using supplied fresh binaries.

This is a shallow fork/restart smoke. Deep forks and shorter heavier candidates
have separate transport tests. It does not build, deploy, or alter an existing DB.
Only facts.json contains the public result; the private scratch databases are
kept under ignored target/. Wallet seeds and stores are removed during cleanup.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


REPO = Path(__file__).resolve().parents[1]
PROFILE_KEY = "0xcad93014ca4e3d270e8f2677345d6f09f3593aefbef3dca83dba417658faf114"
PHASE_SECONDS = 180
STOP_SECONDS = 30
CAP = ["taskset", "-c", "0-7", "nice", "-n", "19"]
INTERRUPTED = False


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def interrupted(_signum, _frame):
    # Defer raising until after a newly spawned child has been registered.
    global INTERRUPTED
    INTERRUPTED = True


def check_interrupt():
    if INTERRUPTED:
        raise InterruptedError("smoke interrupted")


def sync_error(output):
    """Keep a bounded error chain, excluding private encodings and terminal controls."""
    text = output[-32768:]
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(char for char in text if char.isprintable() or char in "\n\t")
    start = re.search(r"(?im)^(?:error:|thread .*panicked)", text)
    if start is None:
        return "no structured error message was returned"
    text = text[start.start():]
    text = re.sub(r"\b(?:qnm1|qn1)[a-z0-9]+", "[wallet encoding omitted]", text)
    text = re.sub(r"(?i)(?:0x)?[0-9a-f]{64,}", "[long hex omitted]", text)
    text = re.sub(r"\[(?:\s*\d{1,3}\s*,){15,}\s*\d{1,3}\s*\]", "[byte array omitted]", text)
    text = re.sub(
        r"(?im)^.*\b(?:seed|mnemonic|spend[_ -]?key|view(?:ing)?[_ -]?key|miner[_ -]?key|rho)\s*[:=].*$",
        "[private field omitted]", text,
    )
    return "\n".join(text.splitlines()[:24])[:4096].replace(chr(0x2014), ":")


def binary_identity(path, source_roots):
    path = path.resolve(strict=True)
    check(path.is_file() and os.access(path, os.X_OK), f"binary is not executable: {path}")
    newest = 0
    for root in source_roots:
        if root.is_file():
            newest = max(newest, root.stat().st_mtime_ns)
            continue
        for directory, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name not in {"target", ".git", "node_modules"}]
            for name in files:
                source = Path(directory) / name
                if source.suffix in {".rs", ".toml", ".lock"}:
                    newest = max(newest, source.stat().st_mtime_ns)
    check(path.stat().st_mtime_ns >= newest,
          f"binary predates its source inputs: {path}; supply a fresh build")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return path, {"name": path.name, "sha256": digest.hexdigest()}


class Child:
    def __init__(self, process, label, log_path=None, capture=False):
        self.process = process
        self.label = label
        self.output = bytearray()
        self.reader_error = None

        def read_output():
            try:
                log = log_path.open("w", encoding="utf-8") if log_path else None
                logged = 0
                try:
                    while line := process.stdout.readline(65536):
                        if capture:
                            check(len(self.output) + len(line) <= 1024 * 1024,
                                  f"{label} output exceeded its limit")
                            self.output.extend(line)
                        if log:
                            text = line.decode("utf-8", errors="replace")
                            # Startup prints part of the miner viewing key. Exclude that
                            # whole line, and any complete bech32 miner key, from logs.
                            if "miner key" in text.lower() or re.search(r"qnm1[a-z0-9]+", text):
                                text = "[miner viewing-key log omitted]\n"
                            log.write(text)
                            log.flush()
                            logged += len(line)
                            if logged >= 8 * 1024 * 1024:
                                log.write("[log size limit reached]\n")
                                log.close()
                                log = None
                finally:
                    if log:
                        log.close()
            except Exception as error:
                self.reader_error = str(error)

        self.reader = threading.Thread(target=read_output, daemon=True)
        self.reader.start()

    def alive(self):
        check(self.process.poll() is None, f"{self.label} exited before its phase completed")
        check(self.reader_error is None, f"{self.label} log capture failed")

    def stop(self):
        deadline = time.monotonic() + STOP_SECONDS
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=STOP_SECONDS - 5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=max(0.1, deadline - time.monotonic()))
        self.reader.join(timeout=max(0, deadline - time.monotonic()))
        self.process.stdout.close()


class Smoke:
    def __init__(self, node_bin, wallet_bin, work):
        self.node_bin = node_bin
        self.wallet_bin = wallet_bin
        self.work = work
        self.children = []
        self.reservations = {}
        self.ports = {}
        self.deadline = time.monotonic() + PHASE_SECONDS
        self.env = {**os.environ, "RAYON_NUM_THREADS": "4", "RUST_LOG": "info", "NO_COLOR": "1"}
        self.env.pop("QNERO_MINER_KEY", None)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for name in ("a", "b"):
            pair = []
            for _ in range(2):
                reserved = socket.socket()
                reserved.bind(("127.0.0.1", 0))
                pair.append(reserved.getsockname()[1])
                self.reservations[pair[-1]] = reserved
            self.ports[name] = pair

    def start(self, binary, args, label, miner_key=None, capture=False, log=False):
        check_interrupt()
        env = dict(self.env)
        if miner_key is not None:
            env["QNERO_MINER_KEY"] = miner_key
        process = subprocess.Popen(
            [*CAP, str(binary), *args], cwd=self.work, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        # Register ownership before starting any optional log handling.
        try:
            child = Child(process, label, self.work / f"{label}.log" if log else None, capture)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=STOP_SECONDS)
            raise
        self.children.append(child)
        return child

    def wallet(self, name, command, capture=False):
        self.deadline = time.monotonic() + PHASE_SECONDS
        diagnose_sync = command == ["sync"]
        child = self.start(self.wallet_bin, [
            "--node", f"http://127.0.0.1:{self.ports[name][0]}",
            "--file", str(self.work / f"{name}.seed"), *command,
        ], f"wallet-{name}-{command[0]}", capture=capture or diagnose_sync)
        while child.process.poll() is None:
            check_interrupt()
            check(time.monotonic() < self.deadline, f"{child.label} timed out")
            time.sleep(0.1)
        child.reader.join(timeout=5)
        check(child.reader_error is None, f"{child.label} output capture failed")
        result = child.output.decode("utf-8", errors="replace")
        child.output.clear()
        if child.process.returncode != 0:
            detail = sync_error(result) if diagnose_sync else "wallet output was not logged"
            raise RuntimeError(f"{child.label} exited with {child.process.returncode}: {detail}")
        return result if capture else ""

    def node(self, name, miner_key=None):
        rpc_port, p2p_port = self.ports[name]
        for port in self.ports[name]:
            reserved = self.reservations.pop(port, None)
            if reserved:
                reserved.close()
        args = [
            "--base-path", str(self.work / f"node-{name}"),
            "--rpc-port", str(rpc_port), "--rpc-methods", "unsafe",
            "--listen-addr", f"/ip4/127.0.0.1/tcp/{p2p_port}",
            "--reserved-only", "--no-mdns", "--no-telemetry", "--no-prometheus",
            "--sync", "full", "--state-pruning", "archive", "--blocks-pruning", "archive",
            "--max-parallel-downloads", "1", "--max-blocks-per-request", "1",
        ]
        args.extend(["--dev", "--mining-threads", "1"] if miner_key is not None
                    else ["--chain", "dev", "--mining-threads", "0"])
        role = "mining" if miner_key is not None else "follower"
        return self.start(self.node_bin, args, f"{name}-{role}", miner_key=miner_key, log=True)

    def rpc(self, name, method, params=None):
        check_interrupt()
        remaining = self.deadline - time.monotonic()
        check(remaining > 0, "RPC phase exceeded its 180-second deadline")
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                              "params": params or []}).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.ports[name][0]}",
                                         data=payload, headers={"Content-Type": "application/json"})
        with self.opener.open(request, timeout=min(3, remaining)) as answer:
            raw = answer.read(16 * 1024 * 1024 + 1)
        check(len(raw) <= 16 * 1024 * 1024, f"{method} response exceeded its limit")
        result = json.loads(raw)
        check("error" not in result and "result" in result, f"{name}: {method} failed")
        return result["result"]

    def wait(self, label, children, predicate):
        self.deadline = time.monotonic() + PHASE_SECONDS
        while time.monotonic() < self.deadline:
            check_interrupt()
            for child in children:
                child.alive()
            try:
                value = predicate()
                if value:
                    return value
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass  # Startup and peer handshake may not be ready yet.
            time.sleep(0.1)
        raise RuntimeError(f"{label} timed out after {PHASE_SECONDS} seconds")

    def head(self, name):
        block_hash = self.rpc(name, "chain_getBlockHash")
        header = self.rpc(name, "chain_getHeader", [block_hash])
        return {"hash": block_hash, "number": int(header["number"], 16), "header": header}

    def work_at(self, name, tip):
        check(0 < tip["number"] <= 64, "smoke tip is outside the bounded 1-64 block range")
        work, block_hash = 1, tip["hash"]  # Consensus initializes genesis work to one.
        for _ in range(tip["number"]):
            header = self.rpc(name, "chain_getHeader", [block_hash])
            parent = header["parentHash"]
            encoded = self.rpc(name, "state_call", ["QPoWApi_get_difficulty", "0x", parent])
            raw = bytes.fromhex(encoded.removeprefix("0x"))
            check(len(raw) == 64, "difficulty runtime API must return a SCALE U512")
            work += int.from_bytes(raw, "little")
            block_hash = parent
        return work

    def profile_at(self, name, block_hash):
        header = self.rpc(name, "chain_getHeader", [block_hash])
        version = self.rpc(name, "state_getRuntimeVersion", [block_hash])
        check(version["specVersion"] == 105, "smoke requires runtime spec_version 105")
        value = self.rpc(name, "state_getStorage", [PROFILE_KEY, block_hash])
        check(isinstance(value, str), "active protocol profile is absent")
        profile = bytes.fromhex(value.removeprefix("0x"))
        check(len(profile) == 192 and profile[:8] == b"QNRPRF01", "unexpected protocol profile")
        check(profile[76] == 1 and int.from_bytes(profile[80:84], "little") == 64,
              "unexpected ciphertext retention profile")
        proof = self.rpc(name, "state_getReadProof", [[PROFILE_KEY], block_hash])
        check(proof["at"] == block_hash and bool(proof["proof"]), "missing pinned state proof")
        return {"header": header, "runtime": version, "profile": value, "read_proof": proof}

    def cleanup(self):
        errors = []
        for child in reversed(self.children):
            try:
                child.stop()
            except Exception:
                errors.append(f"could not stop owned child {child.label}")
        for reserved in self.reservations.values():
            reserved.close()
        self.reservations.clear()
        for name in ("a", "b"):
            for suffix in (".seed", ".seed.store.json"):
                (self.work / f"{name}{suffix}").unlink(missing_ok=True)
            # WalletStore::save can be interrupted before its atomic rename.
            for temporary in self.work.glob(f"{name}.seed.store.json.tmp.*"):
                temporary.unlink()
        for port in sum(self.ports.values(), []):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    errors.append(f"port {port} still accepts connections")
            except OSError:
                pass
            try:
                with socket.socket() as probe:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    probe.bind(("127.0.0.1", port))
            except OSError:
                errors.append(f"port {port} is not bindable after cleanup")
        return errors


def exercise(smoke, facts):
    print("Mining isolated A, then isolated B, with one mining thread at a time.", flush=True)
    tips = {}
    for name, target in (("a", 1), ("b", 2)):
        smoke.wallet(name, ["keygen"])
        key_output = smoke.wallet(name, ["miner-address"], capture=True)
        keys = re.findall(r"^qnm1[a-z0-9]+$", key_output, flags=re.MULTILINE)
        check(len(keys) == 1, "wallet did not return exactly one miner viewing key")
        child = smoke.node(name, miner_key=keys[0])
        del key_output, keys
        if name == "b":
            target = max(target, tips["a"]["number"] + 1)
        tips[name] = smoke.wait(f"mine {name}", [child],
                               lambda: (head if (head := smoke.head(name))["number"] >= target else None))
        child.stop()

    a, b = smoke.node("a"), smoke.node("b")
    smoke.wait("follower restart", [a, b], lambda: smoke.head("a") and smoke.head("b"))
    tips = {name: smoke.head(name) for name in ("a", "b")}
    genesis = smoke.rpc("a", "chain_getBlockHash", [0])
    check(smoke.rpc("b", "chain_getBlockHash", [0]) == genesis, "dev genesis differs between nodes")
    check(tips["a"]["hash"] != tips["b"]["hash"], "isolated mining did not produce distinct tips")
    work = {name: smoke.work_at(name, tips[name]) for name in ("a", "b")}
    check(work["b"] > work["a"], "B must carry more configured work than A; repeat if A overshot")
    facts.update({"genesis": genesis, "partition_tips": tips, "configured_work": work})
    before_a = smoke.profile_at("a", tips["a"]["hash"])
    before_a_block = smoke.rpc("a", "chain_getBlock", [tips["a"]["hash"]])
    check(before_a_block is not None, "A tip body is missing before reconnect")

    print("Reconnecting followers and checking work selection and archive retention.", flush=True)
    peer_ids = {name: smoke.rpc(name, "system_localPeerId") for name in ("a", "b")}
    for local, remote in (("a", "b"), ("b", "a")):
        address = f"/ip4/127.0.0.1/tcp/{smoke.ports[remote][1]}/p2p/{peer_ids[remote]}"
        smoke.rpc(local, "system_addReservedPeer", [address])
    expected = tips["b"]["hash"]
    smoke.wait("fork convergence", [a, b], lambda: all(
        smoke.rpc(name, "chain_getBlockHash") == expected for name in ("a", "b")))
    for name in ("a", "b"):
        check(smoke.rpc(name, "chain_getFinalizedHead") == genesis, "non-genesis finalization observed")
        retained_block = smoke.rpc(name, "chain_getBlock", [tips["a"]["hash"]])
        # A can adopt B before B completes ancestry discovery. In that honest
        # ordering B may never request the former A tip; retention is required
        # on A, which actually imported and selected it before the reconnect.
        if name == "b" and retained_block is None:
            facts["former_a_on_b"] = {"available": False}
            continue
        check(retained_block == before_a_block, "former A block body was not retained")
        archived = smoke.profile_at(name, tips["a"]["hash"])
        check(archived["header"] == before_a["header"] and archived["profile"] == before_a["profile"],
              "former A branch state differs after reconnect")
        facts[f"former_a_on_{name}"] = {"available": True, **archived}
    facts["former_a_block"] = before_a_block
    facts["selected_tip"] = smoke.profile_at("b", expected)
    facts["selected_tip"]["hash"] = expected
    facts["finalized_hash"] = genesis

    print("Syncing native wallet B at the stable selected tip.", flush=True)
    smoke.wallet("b", ["sync"])
    store = json.loads((smoke.work / "b.seed.store.json").read_text())
    check(store["genesis_hash"] == genesis.removeprefix("0x"), "wallet genesis binding differs")
    check(store["last_synced_block"] == tips["b"]["number"], "wallet did not reach the selected tip")
    notes = [note for note in store["notes"] if note["on_chain"] and not note["spent"]]
    check(len(notes) == tips["b"]["number"] and all(note["value"] > 0 for note in notes),
          "wallet did not discover every positive B coinbase")
    check(not store["rejected"], "wallet rejected a normally mined coinbase")
    facts["wallet"] = {"synced_height": store["last_synced_block"], "coinbase_notes": len(notes),
                       "positive_value": True, "profile_and_state_proof_checks": "native sync passed"}
    check(all(smoke.rpc(name, "chain_getBlockHash") == expected for name in ("a", "b")),
          "a follower changed the selected tip during wallet sync")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-bin", required=True, type=Path)
    parser.add_argument("--wallet-bin", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    check(set(range(8)).issubset(os.sched_getaffinity(0)), "CPU affinity must permit CPUs 0-7")
    os.sched_setaffinity(0, set(range(8)))
    os.nice(max(0, 19 - os.getpriority(os.PRIO_PROCESS, 0)))
    check(all(shutil.which(tool) for tool in ("taskset", "nice")), "taskset and nice are required")
    workspace_inputs = [REPO / "Cargo.toml", REPO / "Cargo.lock"]
    node, node_id = binary_identity(args.node_bin, [REPO / "chain", REPO / "crates", *workspace_inputs])
    wallet, wallet_id = binary_identity(args.wallet_bin, [REPO / "crates", *workspace_inputs])
    root = REPO / "target" / "native-upgrade-smoke"
    root.mkdir(parents=True, exist_ok=True)
    with (root / "smoke.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=root))
        print(f"Smoke artifacts: {work}", flush=True)
        smoke = Smoke(node, wallet, work)
        facts = {"scope": "fresh dev shallow fork, restart, archive retention and native wallet sync",
                 "binaries": {"node": node_id, "wallet": wallet_id}, "passed": False}
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, interrupted)
        try:
            exercise(smoke, facts)
            facts["passed"] = True
        except Exception as error:
            facts["failure"] = str(error)
        finally:
            cleanup = smoke.cleanup()
            if cleanup:
                facts["passed"] = False
                facts["cleanup_errors"] = cleanup
            (work / "facts.json").write_text(json.dumps(facts, indent=2) + "\n")
        print(f"{'PASS' if facts['passed'] else 'FAIL'}: {work / 'facts.json'}", flush=True)
        return 0 if facts["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Smoke refused: {error}", file=sys.stderr)
        sys.exit(1)
