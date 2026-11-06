#!/usr/bin/env python3
"""ZB custom DoH resolver: blocks a fixed denylist, forwards the rest to
mainland-China DoH upstreams (fallback: Cloudflare). Stdlib only."""
import os
import struct
import time
import base64
import threading
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BLOCKED = [
    # time sync (18)
    "time.apple.com", "time-ios.apple.com", "time.android.com",
    "pool.ntp.org", "time.google.com", "time.cloudflare.com",
    "ntp.aliyun.com", "ntp1.aliyun.com", "ntp2.aliyun.com", "ntp3.aliyun.com",
    "ntp4.aliyun.com", "ntp5.aliyun.com", "ntp6.aliyun.com", "ntp7.aliyun.com",
    "time1.aliyun.com", "time2.aliyun.com", "ntp.tencent.com",
    "time.windows.com",
    # meituan reporting / calibration channels (6)
    # NOTE 2026-11-06: p.meituan.com REMOVED from the blocklist.
    # A/B test that night: seller Control D and CONDNS trial both upload fine;
    # NextDNS with the full 25-domain list blocks dispatch but kills photo upload.
    # DoH probes of the NextDNS profile showed p.meituan.com returning 0.0.0.0,
    # and p.meituan.com is the only "p" (picture?) domain in the list, so it is
    # the prime suspect for the upload endpoint. If the phone test shows upload
    # still fails, check /__log during an upload attempt and try the next
    # suspect (httpdns.meituan.com); if dispatch-blocking breaks, re-add it.
    # Original 25-domain list (incl. p.meituan.com) is in git history.
    "dreport.meituan.net", "httpdns.meituan.com",
    "maplocatesdksnapshot.d.meituan.net", "shadowa.meituan.com",
    "qq.meituan.com", "catfront.dianping.com",
]

UPSTREAMS = [u.strip() for u in os.environ.get(
    "UPSTREAMS",
    "https://doh.pub/dns-query,https://dns.alidns.com/dns-query,"
    "https://cloudflare-dns.com/dns-query").split(",") if u.strip()]
LOG_KEY = os.environ.get("LOG_KEY", "zb-rider-log-7f3a")
PORT = int(os.environ.get("PORT", "8080"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "4"))

log_ring = deque(maxlen=1000)
log_lock = threading.Lock()


def parse_question(msg):
    off = 12
    labels = []
    while True:
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        labels.append(msg[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    qtype, _qclass = struct.unpack(">HH", msg[off:off + 4])
    return ".".join(labels).lower(), qtype, off + 4


def is_blocked(name):
    return any(name == d or name.endswith("." + d) for d in BLOCKED)


def blocked_response(msg, qtype, qend):
    qd = struct.unpack(">H", msg[4:6])[0]
    tid = struct.unpack(">H", msg[0:2])[0]
    answers, ancount = b"", 0
    if qtype == 1:  # A -> 0.0.0.0
        answers = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(4)
        ancount = 1
    elif qtype == 28:  # AAAA -> ::
        answers = b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 60, 16) + bytes(16)
        ancount = 1
    hdr = struct.pack(">HHHHHH", tid, 0x8180, qd, ancount, 0, 0)
    return hdr + msg[12:qend] + answers


def servfail_response(msg, qend):
    qd = struct.unpack(">H", msg[4:6])[0]
    tid = struct.unpack(">H", msg[0:2])[0]
    hdr = struct.pack(">HHHHHH", tid, 0x8182, qd, 0, 0, 0)
    return hdr + msg[12:qend]


def forward(msg):
    last_exc = None
    for upstream in UPSTREAMS:
        try:
            req = urllib.request.Request(
                upstream, data=msg,
                headers={"Content-Type": "application/dns-message",
                         "Accept": "application/dns-message"})
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
                return resp.read(), upstream
        except Exception as exc:  # try next upstream
            last_exc = exc
    raise last_exc if last_exc else RuntimeError("no upstream configured")


def add_log(line):
    entry = "%sZ %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), line)
    with log_lock:
        log_ring.append(entry)
    print(entry, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/dns-message"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            return self._send(200, b"ok", "text/plain")
        if self.path.startswith("/__log"):
            params = parse_qs(urlparse(self.path).query)
            if params.get("key", [""])[0] != LOG_KEY:
                return self._send(403, b"forbidden", "text/plain")
            with log_lock:
                body = ("\n".join(log_ring) + "\n").encode()
            return self._send(200, body, "text/plain")
        if self.path.startswith("/dns-query"):
            params = parse_qs(urlparse(self.path).query)
            raw = params.get("dns", [None])[0]
            if raw is None:
                return self._send(400, b"missing dns param", "text/plain")
            try:
                msg = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            except Exception:
                return self._send(400, b"bad base64", "text/plain")
            return self._handle(msg)
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path.startswith("/dns-query"):
            length = int(self.headers.get("Content-Length", 0))
            msg = self.rfile.read(length) if length else b""
            return self._handle(msg)
        return self._send(404, b"not found", "text/plain")

    def _handle(self, msg):
        clean_path = urlparse(self.path).path
        tag = clean_path[len("/dns-query"):].strip("/") or "-"
        try:
            qname, qtype, qend = parse_question(msg)
        except Exception:
            return self._send(400, b"bad dns message", "text/plain")
        if is_blocked(qname):
            add_log("[%s] BLOCK %s type=%s" % (tag, qname, qtype))
            return self._send(200, blocked_response(msg, qtype, qend))
        try:
            resp, upstream = forward(msg)
            add_log("[%s] PASS %s type=%s via %s"
                    % (tag, qname, qtype, upstream.split("/")[2]))
            return self._send(200, resp)
        except Exception as exc:
            add_log("[%s] FAIL %s type=%s err=%s"
                    % (tag, qname, qtype, type(exc).__name__))
            return self._send(200, servfail_response(msg, qend))


if __name__ == "__main__":
    print("listening on port %d, upstreams: %s" % (PORT, UPSTREAMS), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
