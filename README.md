# Sigil-audit

Audit & inspection toolkit for the **SiGiL** (`sigil-framework`) suite:

- **[`Sigil-audit.html`](Sigil-audit.html):** Zero-telemetry, single-file air-gapped browser inspector for LLM prompts, hidden Unicode smuggling, Base64 payloads, and secret/PII leaks.
- **[`sigil_audit_subscriber.py`](sigil_audit_subscriber.py):** Zero-dependency Python stdlib SiGiL IPC v1 subscriber (`sigil.sock`) that streams `verdict_event`, `containment_event`, `threat_signal`, and initial `state_snapshot` frames from `sentinel-x` into normalized JSONL audit logs with automatic reconnect.

---

## Live `sigil.sock` Audit Stream

```bash
# Subscribe to the running sentinel-x daemon (resolves SIGIL_SOCK -> $XDG_RUNTIME_DIR/sigil.sock -> /tmp/sigil-<uid>.sock)
python3 sigil_audit_subscriber.py --out sigil-audit-stream.jsonl

# Explicit socket path + bounded test run
python3 sigil_audit_subscriber.py --sock /tmp/sigil-1000.sock --out /tmp/audit.jsonl --max-frames 3
```

## Tests

```bash
python3 -m unittest discover -v
```
