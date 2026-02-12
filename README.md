# DNS Failover SOCKS5 Proxy (Python)

A desktop GUI app (Tkinter) that runs a local SOCKS5 proxy and resolves DNS with failover across multiple providers:

- Up to 5 classic DNS groups (UDP/53) with enable/disable checkbox.
- 2 extra encrypted DNS endpoints (DoH/DoT) with enable/disable checkbox.
- Automatic switching to next enabled provider on DNS errors.
- Logs show which provider is active and when switching happens.
- Copyable logs from GUI.

## Run

```bash
python3 app.py
```

Then configure your target app to use SOCKS5 proxy at:

- IP: `127.0.0.1`
- Port: `1080`

(Or change bind IP/port in the GUI.)
