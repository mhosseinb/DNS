import asyncio
import ipaddress
import queue
import random
import socket
import ssl
import struct
import threading
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from urllib import request


@dataclass
class DnsProvider:
    name: str
    kind: str  # udp | doh | dot
    endpoints: list[str]
    enabled: bool = True


class DnsFailoverResolver:
    def __init__(self, log_func):
        self.providers: list[DnsProvider] = []
        self._active_index = 0
        self.log = log_func

    def set_providers(self, providers: list[DnsProvider]):
        self.providers = providers
        self._active_index = 0
        enabled_count = len([p for p in providers if p.enabled])
        self.log(f"[Resolver] {enabled_count} DNS provider(s) enabled.")

    def _enabled_indices(self):
        return [i for i, p in enumerate(self.providers) if p.enabled]

    def resolve(self, hostname: str, qtype: int = 1) -> str:
        enabled = self._enabled_indices()
        if not enabled:
            raise RuntimeError("No DNS provider is enabled.")

        start = 0
        if self._active_index in enabled:
            start = enabled.index(self._active_index)

        for offset in range(len(enabled)):
            idx = enabled[(start + offset) % len(enabled)]
            provider = self.providers[idx]
            try:
                ip = self._query_provider(provider, hostname, qtype)
                if idx != self._active_index:
                    self.log(f"[Resolver] Switched active DNS -> {provider.name} ({provider.kind}).")
                self._active_index = idx
                return ip
            except Exception as exc:
                self.log(f"[Resolver] {provider.name} failed: {exc}")

        raise RuntimeError(f"All enabled DNS providers failed for: {hostname}")

    def _query_provider(self, provider: DnsProvider, hostname: str, qtype: int) -> str:
        last_error = None
        for endpoint in provider.endpoints:
            try:
                packet = self._build_dns_query(hostname, qtype)
                if provider.kind == "udp":
                    response = self._query_udp(endpoint, packet)
                elif provider.kind == "doh":
                    response = self._query_doh(endpoint, packet)
                elif provider.kind == "dot":
                    response = self._query_dot(endpoint, packet)
                else:
                    raise ValueError(f"Unknown provider kind: {provider.kind}")
                return self._extract_a_record(response)
            except Exception as exc:
                last_error = exc
        raise RuntimeError(last_error or "unknown error")

    @staticmethod
    def _build_dns_query(hostname: str, qtype: int = 1) -> bytes:
        tid = random.randint(0, 65535)
        flags = 0x0100
        qdcount = 1
        header = struct.pack("!HHHHHH", tid, flags, qdcount, 0, 0, 0)

        qname = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in hostname.split(".")) + b"\x00"
        question = qname + struct.pack("!HH", qtype, 1)
        return header + question

    @staticmethod
    def _skip_name(buf: bytes, offset: int) -> int:
        while True:
            length = buf[offset]
            if length == 0:
                return offset + 1
            if length & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + length

    def _extract_a_record(self, response: bytes) -> str:
        if len(response) < 12:
            raise RuntimeError("Invalid DNS response")
        _tid, flags, qdcount, ancount, _nsc, _arc = struct.unpack("!HHHHHH", response[:12])
        rcode = flags & 0x000F
        if rcode != 0:
            raise RuntimeError(f"DNS error code: {rcode}")

        offset = 12
        for _ in range(qdcount):
            offset = self._skip_name(response, offset)
            offset += 4

        for _ in range(ancount):
            offset = self._skip_name(response, offset)
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", response[offset:offset + 10])
            offset += 10
            rdata = response[offset:offset + rdlen]
            offset += rdlen
            if rtype == 1 and rclass == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)

        raise RuntimeError("No A record found")

    @staticmethod
    def _query_udp(server_ip: str, packet: bytes, timeout: float = 3.0) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server_ip, 53))
            data, _ = sock.recvfrom(4096)
            return data

    @staticmethod
    def _query_doh(url: str, packet: bytes, timeout: float = 4.0) -> bytes:
        req = request.Request(
            url,
            data=packet,
            method="POST",
            headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
        )
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    @staticmethod
    def _query_dot(endpoint: str, packet: bytes, timeout: float = 4.0) -> bytes:
        if ":" in endpoint:
            host, port_s = endpoint.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = endpoint, 853

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(struct.pack("!H", len(packet)) + packet)
                dlen = struct.unpack("!H", tls_sock.recv(2))[0]
                data = b""
                while len(data) < dlen:
                    chunk = tls_sock.recv(dlen - len(data))
                    if not chunk:
                        break
                    data += chunk
                return data


class Socks5ProxyServer:
    def __init__(self, host: str, port: int, resolver: DnsFailoverResolver, log_func):
        self.host = host
        self.port = port
        self.resolver = resolver
        self.log = log_func
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.log(f"[Proxy] Listening on socks5://{self.host}:{self.port}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.log("[Proxy] Stopped.")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            ver_nmethods = await reader.readexactly(2)
            ver, nmethods = ver_nmethods[0], ver_nmethods[1]
            if ver != 5:
                raise RuntimeError("Unsupported SOCKS version")
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")
            await writer.drain()

            req = await reader.readexactly(4)
            ver, cmd, _rsv, atyp = req
            if ver != 5 or cmd != 1:
                raise RuntimeError("Only CONNECT supported")

            if atyp == 1:
                dst_addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                dlen = (await reader.readexactly(1))[0]
                domain = (await reader.readexactly(dlen)).decode("idna")
                dst_addr = self.resolver.resolve(domain)
                self.log(f"[Proxy] {domain} -> {dst_addr}")
            elif atyp == 4:
                dst_addr = str(ipaddress.IPv6Address(await reader.readexactly(16)))
            else:
                raise RuntimeError("Unknown ATYP")

            dst_port = struct.unpack("!H", await reader.readexactly(2))[0]

            remote_reader, remote_writer = await asyncio.open_connection(dst_addr, dst_port)
            bind_host, bind_port = remote_writer.get_extra_info("sockname")[:2]
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(bind_host) + struct.pack("!H", bind_port)
            writer.write(reply)
            await writer.drain()

            await asyncio.gather(
                self._relay(reader, remote_writer),
                self._relay(remote_reader, writer),
            )
        except Exception as exc:
            self.log(f"[Proxy] Client {peer} error: {exc}")
            try:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def _relay(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
        try:
            while True:
                data = await src.read(16384)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        finally:
            dst.close()


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("DNS Failover SOCKS5 Proxy")
        self.root.geometry("980x720")

        self.log_queue = queue.Queue()
        self.loop = None
        self.loop_thread = None
        self.proxy = None
        self.resolver = DnsFailoverResolver(self.log)

        self.provider_vars = []
        self.extra_type_vars = []
        self.extra_url_vars = []

        self._build_ui()
        self._poll_logs()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f6f8fb")
        style.configure("TLabel", background="#f6f8fb", foreground="#233")
        style.configure("TLabelframe", background="#f6f8fb")
        style.configure("TLabelframe.Label", background="#f6f8fb", foreground="#112")

        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        top = ttk.Frame(main)
        top.pack(fill="x")

        ttk.Label(top, text="Bind IP:").pack(side="left")
        self.bind_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.bind_ip, width=16).pack(side="left", padx=6)

        ttk.Label(top, text="Port:").pack(side="left")
        self.bind_port = tk.StringVar(value="1080")
        ttk.Entry(top, textvariable=self.bind_port, width=8).pack(side="left", padx=6)

        self.status_var = tk.StringVar(value="Stopped")
        ttk.Label(top, textvariable=self.status_var, foreground="#006d77").pack(side="left", padx=14)

        self.start_btn = ttk.Button(top, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side="right", padx=4)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_proxy, state="disabled")
        self.stop_btn.pack(side="right", padx=4)

        providers_frame = ttk.Labelframe(main, text="DNS Providers (Enable/Disable)", padding=10)
        providers_frame.pack(fill="x", pady=8)

        defaults = [
            ("shecan", ["178.22.122.100", "185.51.200.2"]),
            ("vanillapp", ["10.139.177.21", "10.139.177.22"]),
            ("hostiran", ["172.29.2.100", "172.29.0.100"]),
            ("begzar", ["185.55.226.26", "185.55.225.25", "185.55.224.24"]),
            ("electro", ["78.157.42.100", "78.157.42.101"]),
        ]

        for i, (name, endpoints) in enumerate(defaults):
            row = ttk.Frame(providers_frame)
            row.pack(fill="x", pady=2)
            enabled_var = tk.BooleanVar(value=True)
            entries = []
            ttk.Checkbutton(row, text=name, variable=enabled_var).pack(side="left", padx=4)
            for ep in endpoints:
                var = tk.StringVar(value=ep)
                ttk.Entry(row, textvariable=var, width=16).pack(side="left", padx=3)
                entries.append(var)
            self.provider_vars.append((name, enabled_var, entries))

        extra_frame = ttk.Labelframe(main, text="Extra Encrypted DNS (DoH/DoT)", padding=10)
        extra_frame.pack(fill="x", pady=8)

        extra_defaults = [
            ("doh", "https://free.shecan.ir/dns-query"),
            ("doh", "https://free.vanillapp.ir/dns-query"),
        ]

        for i in range(2):
            row = ttk.Frame(extra_frame)
            row.pack(fill="x", pady=2)
            enabled = tk.BooleanVar(value=True)
            dns_type = tk.StringVar(value=extra_defaults[i][0])
            url = tk.StringVar(value=extra_defaults[i][1])

            ttk.Checkbutton(row, text=f"Extra {i+1}", variable=enabled).pack(side="left", padx=4)
            ttk.Combobox(row, values=["doh", "dot"], textvariable=dns_type, width=6, state="readonly").pack(side="left", padx=4)
            ttk.Entry(row, textvariable=url).pack(side="left", fill="x", expand=True, padx=4)

            self.extra_type_vars.append((enabled, dns_type))
            self.extra_url_vars.append(url)

        log_frame = ttk.Labelframe(main, text="Logs", padding=10)
        log_frame.pack(fill="both", expand=True, pady=8)

        self.log_text = tk.Text(log_frame, wrap="word", height=20)
        self.log_text.pack(fill="both", expand=True)

        bottom = ttk.Frame(main)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Copy Logs", command=self.copy_logs).pack(side="right", padx=4)
        ttk.Button(bottom, text="Clear", command=lambda: self.log_text.delete("1.0", "end")).pack(side="right", padx=4)

    def build_providers(self):
        providers = []
        for name, enabled_var, entries in self.provider_vars:
            endpoints = [v.get().strip() for v in entries if v.get().strip()]
            providers.append(DnsProvider(name=name, kind="udp", endpoints=endpoints, enabled=enabled_var.get()))

        for i in range(2):
            enabled, dns_type = self.extra_type_vars[i]
            endpoint = self.extra_url_vars[i].get().strip()
            providers.append(
                DnsProvider(name=f"extra-{i+1}", kind=dns_type.get(), endpoints=[endpoint] if endpoint else [], enabled=enabled.get())
            )

        return providers

    def start_proxy(self):
        try:
            host = self.bind_ip.get().strip()
            port = int(self.bind_port.get().strip())
        except ValueError:
            messagebox.showerror("Invalid input", "Port must be a number.")
            return

        providers = self.build_providers()
        self.resolver.set_providers(providers)

        self.loop = asyncio.new_event_loop()
        self.proxy = Socks5ProxyServer(host, port, self.resolver, self.log)

        async def runner():
            await self.proxy.start()

        def thread_target():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(runner())
            self.loop.run_forever()

        self.loop_thread = threading.Thread(target=thread_target, daemon=True)
        self.loop_thread.start()

        self.status_var.set(f"Running at {host}:{port}")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def stop_proxy(self):
        if not self.loop or not self.proxy:
            return

        async def shutdown():
            await self.proxy.stop()

        fut = asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
        fut.result(timeout=5)
        self.loop.call_soon_threadsafe(self.loop.stop)

        self.status_var.set("Stopped")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def log(self, text: str):
        self.log_queue.put(text)

    def _poll_logs(self):
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
        self.root.after(200, self._poll_logs)

    def copy_logs(self):
        data = self.log_text.get("1.0", "end").strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(data)
        self.log("[UI] Logs copied to clipboard.")


def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
