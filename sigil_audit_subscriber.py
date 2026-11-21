#!/usr/bin/env python3
"""
SiGiL IPC v1 subscriber for Sigil-audit <- sentinel-x (sigil.sock).
Subscribes to verdict_event, containment_event, and threat_signal frames,
appends normalized JSONL audit records, and reconnects automatically on EOF/error.
Zero external dependencies (Python standard library only).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import socket
import sys
import time
from typing import Iterable, Optional


def default_sigil_sock_path() -> str:
    env_sock = os.environ.get("SIGIL_SOCK", "").strip()
    if env_sock:
        return env_sock
    xdg = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if xdg:
        return os.path.join(xdg, "sigil.sock")
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    return f"/tmp/sigil-{uid}.sock"


def _utc_now_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class SigilAuditSubscriber:
    """Streams SiGiL IPC v1 events from sigil.sock and writes JSONL audit records."""

    def __init__(
        self,
        sock_path: Optional[str] = None,
        out_path: str = "sigil-audit-stream.jsonl",
        source: str = "sigil-audit",
        topics: Optional[Iterable[str]] = None,
        reconnect_delay: float = 1.0,
    ) -> None:
        self.sock_path = sock_path or default_sigil_sock_path()
        self.out_path = out_path
        self.source = source
        self.topics = (
            list(topics)
            if topics is not None
            else [
                "verdict_event",
                "containment_event",
                "threat_signal",
            ]
        )
        self.reconnect_delay = reconnect_delay

    def _build_hello(self) -> bytes:
        msg = {
            "v": 1,
            "id": f"audit-sub-{int(time.time() * 1000)}",
            "ts": _utc_now_iso(),
            "source": self.source,
            "type": "hello",
            "payload": {
                "source": self.source,
                "subscriptions": self.topics,
                "want_snapshot": True,
                "snapshot": True,
            },
        }
        return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")

    def _append_record(self, raw_line: str) -> None:
        try:
            env = json.loads(raw_line)
        except json.JSONDecodeError:
            return
        record = {
            "logged_at": _utc_now_iso(),
            "envelope_v": env.get("v"),
            "envelope_id": env.get("id"),
            "envelope_ts": env.get("ts"),
            "source": env.get("source"),
            "type": env.get("type"),
            "payload": env.get("payload"),
        }
        out_dir = os.path.dirname(os.path.abspath(self.out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(self.out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    def run_forever(self, max_frames: Optional[int] = None) -> None:
        frames_seen = 0
        while True:
            if max_frames is not None and frames_seen >= max_frames:
                return
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2.0)
                    sock.connect(self.sock_path)
                    sock.sendall(self._build_hello())
                    buf = b""
                    while True:
                        if max_frames is not None and frames_seen >= max_frames:
                            return
                        try:
                            chunk = sock.recv(65536)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            self._append_record(line.decode("utf-8", errors="replace"))
                            frames_seen += 1
                            if max_frames is not None and frames_seen >= max_frames:
                                return
            except OSError:
                time.sleep(self.reconnect_delay)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Subscribe Sigil-audit to sigil.sock v1")
    parser.add_argument("--sock", default=None, help="Path to sigil.sock")
    parser.add_argument("--out", default="sigil-audit-stream.jsonl", help="Output JSONL path")
    parser.add_argument("--max-frames", type=int, default=None, help="Exit after N frames (for testing)")
    args = parser.parse_args(argv)
    sub = SigilAuditSubscriber(sock_path=args.sock, out_path=args.out)
    sub.run_forever(max_frames=args.max_frames)
    return 0


if __name__ == "__main__":
    sys.exit(main())
