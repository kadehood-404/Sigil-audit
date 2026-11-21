#!/usr/bin/env python3
import json
import os
import socket
import tempfile
import threading
import unittest

from sigil_audit_subscriber import SigilAuditSubscriber, default_sigil_sock_path


class TestSigilAuditSubscriber(unittest.TestCase):
    def test_default_sock_path_precedence(self):
        orig_sigil = os.environ.get("SIGIL_SOCK")
        orig_xdg = os.environ.get("XDG_RUNTIME_DIR")
        try:
            os.environ["SIGIL_SOCK"] = "/custom/sigil.sock"
            os.environ["XDG_RUNTIME_DIR"] = "/run/user/1000"
            self.assertEqual(default_sigil_sock_path(), "/custom/sigil.sock")

            del os.environ["SIGIL_SOCK"]
            self.assertEqual(default_sigil_sock_path(), "/run/user/1000/sigil.sock")

            del os.environ["XDG_RUNTIME_DIR"]
            self.assertTrue(default_sigil_sock_path().startswith("/tmp/sigil-"))
        finally:
            if orig_sigil is None:
                os.environ.pop("SIGIL_SOCK", None)
            else:
                os.environ["SIGIL_SOCK"] = orig_sigil
            if orig_xdg is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = orig_xdg

    def test_stream_and_reconnect_writes_normalized_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = os.path.join(tmp, "sigil.sock")
            out_path = os.path.join(tmp, "audit.jsonl")
            hellos: list[dict] = []

            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(4)

            def serve_twice():
                try:
                    # Connection 1: read hello, send 1 frame, then close (forces reconnect).
                    c1, _ = srv.accept()
                    with c1:
                        raw = c1.recv(4096).decode("utf-8").strip()
                        hellos.append(json.loads(raw))
                        f1 = {
                            "v": 1,
                            "id": "env-1",
                            "ts": "2026-11-21T12:00:00Z",
                            "source": "sentinel-x",
                            "type": "verdict_event",
                            "payload": {"severity": "high"},
                        }
                        c1.sendall((json.dumps(f1) + "\n").encode("utf-8"))

                    # Connection 2: read hello, send 2nd frame.
                    c2, _ = srv.accept()
                    with c2:
                        raw = c2.recv(4096).decode("utf-8").strip()
                        hellos.append(json.loads(raw))
                        f2 = {
                            "v": 1,
                            "id": "env-2",
                            "ts": "2026-11-21T12:00:01Z",
                            "source": "sentinel-x",
                            "type": "containment_event",
                            "payload": {"effective": "SEVER"},
                        }
                        c2.sendall((json.dumps(f2) + "\n").encode("utf-8"))
                finally:
                    srv.close()

            t = threading.Thread(target=serve_twice, daemon=True)
            t.start()

            sub = SigilAuditSubscriber(
                sock_path=sock_path,
                out_path=out_path,
                reconnect_delay=0.05,
            )
            sub.run_forever(max_frames=2)
            t.join(timeout=3.0)

            self.assertEqual(len(hellos), 2)
            self.assertEqual(hellos[0]["type"], "hello")
            self.assertTrue(hellos[0]["payload"]["want_snapshot"])

            with open(out_path, encoding="utf-8") as fh:
                rows = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["envelope_id"], "env-1")
            self.assertEqual(rows[0]["type"], "verdict_event")
            self.assertEqual(rows[1]["envelope_id"], "env-2")
            self.assertEqual(rows[1]["type"], "containment_event")


if __name__ == "__main__":
    unittest.main()
