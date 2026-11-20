"""mitmproxy helpers: find the binaries, make sure its CA exists, and compute the CA's SPKI hash.

The SPKI hash is what lets ONLY the test Chrome profile trust mitmproxy:
    --ignore-certificate-errors-spki-list=<base64(sha256(SubjectPublicKeyInfo DER))>
Chrome then accepts any certificate chaining to that key, and only when the flag is given (which
also requires --user-data-dir). Nothing is added to the system keychain.
"""
import base64
import hashlib
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

CA_CERT = "mitmproxy-ca-cert.pem"


def confdir() -> Path:
    """mitmproxy's config dir (where its CA lives). Override with $DYN_MITM_CONFDIR."""
    return Path(os.environ.get("DYN_MITM_CONFDIR", "~/.mitmproxy")).expanduser()


def find(tool: str = "mitmdump") -> Path | None:
    p = shutil.which(tool)
    return Path(p) if p else None


def version(mitmdump: Path) -> str:
    out = subprocess.run([str(mitmdump), "--version"], capture_output=True, text=True, timeout=30).stdout
    m = re.search(r"Mitmproxy:\s*([\d.]+)", out)
    return m.group(1) if m else ""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_free(port: int) -> bool:
    """True if nothing is listening on the port. Like a server, ignores connections in TIME_WAIT
    (left for ~1 min after the previous run), which would otherwise block back-to-back runs."""
    with socket.socket() as s:
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def wait_for_port(port: int, timeout: float = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def ensure_ca(mitmdump: Path, conf: Path | None = None) -> tuple[Path, bool]:
    """Return (CA cert path, created_now). mitmproxy creates its CA the first time it starts."""
    conf = conf or confdir()
    cert = conf / CA_CERT
    if cert.exists():
        return cert, False
    port = free_port()
    proc = subprocess.Popen([str(mitmdump), "--listen-host", "127.0.0.1", "-p", str(port),
                             "--set", f"confdir={conf}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 30
        while time.time() < deadline and not cert.exists():
            time.sleep(0.2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    if not cert.exists():
        raise RuntimeError(f"mitmproxy did not create {cert}")
    return cert, True


# --- minimal DER reader: just enough X.509 to find the SubjectPublicKeyInfo ---------------------

def _der(buf: bytes, i: int) -> tuple[int, int, int, int]:
    """(tag, start, content_start, end) of the DER element at offset i."""
    tag, length, j = buf[i], buf[i + 1], i + 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4:
            raise ValueError("bad DER length")
        length, j = int.from_bytes(buf[j:j + n], "big"), j + n
    if j + length > len(buf):
        raise ValueError("truncated DER")
    return tag, i, j, j + length


def _children(buf: bytes, content_start: int, end: int):
    i = content_start
    while i < end:
        el = _der(buf, i)
        yield el
        i = el[3]


def spki_der(cert_der: bytes) -> bytes:
    """Certificate -> tbsCertificate -> [version], serial, sigalg, issuer, validity, subject, SPKI."""
    tag, _, c0, end = _der(cert_der, 0)
    if tag != 0x30:
        raise ValueError("not a DER certificate")
    tag, _, t0, tend = next(_children(cert_der, c0, end))
    if tag != 0x30:
        raise ValueError("no tbsCertificate")
    fields = [el for el in _children(cert_der, t0, tend)]
    if fields and fields[0][0] == 0xA0:          # explicit [0] version
        fields = fields[1:]
    if len(fields) < 6 or fields[5][0] != 0x30:
        raise ValueError("no SubjectPublicKeyInfo")
    _, start, _, stop = fields[5]
    return cert_der[start:stop]


def pem_to_der(pem: str) -> bytes:
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S)
    if not m:
        raise ValueError("no PEM certificate")
    return base64.b64decode("".join(m.group(1).split()))


def spki_hash(cert_pem: Path) -> str:
    """The value for Chrome's --ignore-certificate-errors-spki-list."""
    der = pem_to_der(Path(cert_pem).read_text())
    return base64.b64encode(hashlib.sha256(spki_der(der)).digest()).decode()
