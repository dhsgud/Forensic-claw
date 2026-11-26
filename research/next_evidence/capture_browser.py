"""Capture controlled Windows Chromium evidence from fresh Chromium browser profiles via Playwright CLI."""

import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter_ns
from urllib.parse import urlsplit

from forensic_claw.forensics.browser_history import final_download_url

CHECKS = [
    {"id": "payload", "cost": 1},
    {"id": "full_history", "cost": 4},
    {"id": "entry_hint", "cost": 1},
    {"id": "profile", "cost": 1},
    {"id": "final_origin", "cost": 2},
    {"id": "server_log", "cost": 3},
]
PAYLOAD = b"Controlled Forensic-Claw research fixture.\n"
LAYOUT = (
    ("target", "a", "common"),
    ("target", "a", "mirror"),
    ("target", "b", "common"),
    ("target", "b", "direct"),
    ("other", "a", "common"),
    ("other", "a", "direct"),
    ("other", "b", "mirror"),
    ("other", "b", "direct"),
)


def verdict(profile, origin):
    return "supported" if (profile, origin) == ("target", "a") else "refuted"


def model():
    return {
        "checks": [check.copy() for check in CHECKS],
        "hypotheses": [
            {
                "id": f"{profile}-{origin}-{hint}",
                "verdict": verdict(profile, origin),
                "outcomes": {
                    "payload": "match",
                    "full_history": f"{profile}:{origin}",
                    "entry_hint": hint,
                    "profile": profile,
                    "final_origin": origin,
                    "server_log": origin if hint != "mirror" else "unavailable",
                },
            }
            for profile, origin, hint in LAYOUT
        ],
    }


def capture(rounds, browser, verify_direct=False):
    node_shim = shutil.which("npx.cmd")
    if node_shim is None:
        raise RuntimeError("npx.cmd is required")
    records = {}
    sent = {}
    servers = {}

    def url(name, path):
        return f"http://127.0.0.1:{servers[name].server_port}{path}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path.strip("/").split("/")
            if len(path) == 2 and path[1] in records:
                stage, trial = path
                _, origin, hint = records[trial]
                if stage == "page":
                    body = f'<a href="/start/{trial}">Download fixture</a>'.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                elif stage in {"start", hint}:
                    destination = (
                        url("entry", f"/{hint}/{trial}")
                        if stage == "start"
                        else url(origin, f"/file/{trial}")
                    )
                    self.send_response(302)
                    self.send_header("Location", destination)
                    self.end_headers()
                    return
                elif stage == "file" and self.server is servers[origin]:
                    sent[trial] = origin
                    body = PAYLOAD
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", 'attachment; filename="fixture.txt"')
                else:
                    self.send_error(404)
                    return
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

    def cli(directory, session, *args):
        completed = subprocess.run(
            [
                node_shim,
                "--yes",
                "--package",
                "@playwright/cli@0.1.25",
                "playwright-cli",
                f"-s={session}",
                *map(str, args),
            ],
            cwd=directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
        if completed.returncode or "### Error" in completed.stdout:
            raise RuntimeError(completed.stdout + completed.stderr)
        return completed.stdout

    def extract(directory, profile, trials):
        path = directory / profile / "Default" / "History"
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            for trial in trials:
                download, state, received, total = db.execute(
                    """SELECT d.id, d.state, d.received_bytes, d.total_bytes
                       FROM downloads d JOIN downloads_url_chains u ON u.id = d.id
                       WHERE u.chain_index = 0 AND u.url = ?""",
                    (url("entry", f"/start/{trial}"),),
                ).fetchone()
                chain = [
                    value
                    for (value,) in db.execute(
                        "SELECT url FROM downloads_url_chains WHERE id = ? ORDER BY chain_index",
                        (download,),
                    )
                ]
                if len(chain) != 3 or state != 1 or received != total:
                    raise ValueError(f"incomplete browser record {trial}")
                hint = urlsplit(chain[1]).path.split("/")[1]
                port = urlsplit(chain[-1]).port
                origin = next(key for key in ("a", "b") if servers[key].server_port == port)
                digest = hashlib.sha256((directory / f"{trial}.txt").read_bytes()).hexdigest()
                if sent.get(trial) != origin or received != len(PAYLOAD):
                    raise ValueError(f"origin response and browser record disagree: {trial}")
                direct = {}
                if verify_direct:
                    start = perf_counter_ns()
                    final = final_download_url(path, download)
                    duration = (perf_counter_ns() - start) / 1000
                    if final != chain[-1]:
                        raise ValueError(f"direct SQL and parsed URL disagree: {trial}")
                    direct = {"direct_origin": origin, "direct_lookup_us": round(duration)}
                yield {
                    **direct,
                    "trial": trial,
                    "profile": profile,
                    "origin": origin,
                    "hint": hint,
                    "download_row": download,
                    "state": state,
                    "bytes": received,
                    "sha256": digest,
                    "server_origin": sent[trial],
                }

    output = []
    with ThreadPoolExecutor(3) as workers:
        for key in ("entry", "a", "b"):
            servers[key] = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            workers.submit(servers[key].serve_forever)
        try:
            for batch in range(rounds):
                with TemporaryDirectory(prefix="forensic-browser-") as tmp:
                    directory = Path(tmp)
                    for profile in ("target", "other"):
                        session = f"fc-evidence-{directory.name}-{profile}"
                        trials = []
                        for index, row in enumerate(LAYOUT):
                            if row[0] == profile:
                                trial = f"b{batch}-{index}"
                                records[trial] = row
                                trials.append(trial)
                        if verify_direct and profile == "other":
                            trials.reverse()
                        code = directory / "download.js"
                        commands = []
                        for trial in trials:
                            page_url = json.dumps(url("entry", f"/page/{trial}"))
                            target = json.dumps(str(directory / f"{trial}.txt"))
                            commands += [
                                f"await page.goto({page_url});",
                                "{ const pending = page.waitForEvent('download');",
                                "await page.getByText('Download fixture').click();",
                                f"await (await pending).saveAs({target}); }}",
                            ]
                        code.write_text(
                            "async page => {" + "".join(commands) + "}", encoding="utf-8"
                        )
                        cli(
                            directory,
                            session,
                            "open",
                            "about:blank",
                            f"--browser={browser}",
                            "--persistent",
                            f"--profile={directory / profile}",
                        )
                        try:
                            cli(directory, session, "run-code", "--filename", code)
                        finally:
                            cli(directory, session, "close")
                        output.extend(extract(directory, profile, trials))
        finally:
            for server in servers.values():
                server.shutdown()
                server.server_close()
    return {
        "browser": browser,
        "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "trials": output,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", choices=("msedge", "chrome"), default="msedge")
    parser.add_argument("--rounds", type=int, choices=range(1, 5), default=3)
    parser.add_argument("--verify-direct", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    capture_result = capture(args.rounds, args.browser, args.verify_direct)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(capture_result, output, indent=2)
