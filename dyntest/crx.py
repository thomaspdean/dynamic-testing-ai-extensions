"""Read a Chrome extension package (.crx) with the standard library only.

CRX3 layout (what the Chrome Web Store serves):
    "Cr24" | uint32 version=3 | uint32 header_size | CrxFileHeader (protobuf) | zip archive
    CrxFileHeader:
        2  sha256_with_rsa    repeated AsymmetricKeyProof { 1 public_key, 2 signature }
        3  sha256_with_ecdsa  repeated AsymmetricKeyProof
        10000 signed_header_data: SignedData { 1 crx_id (16 bytes) }
A store CRX carries more than one key proof (the developer's and the Web Store's). The extension's
key is the one whose SHA-256 starts with crx_id. The extension ID is those 16 bytes written as hex
with the digits 0-f mapped to the letters a-p.

CRX2 (old): "Cr24" | uint32 2 | uint32 key_len | uint32 sig_len | key | sig | zip.

Signatures are not verified: the run pins each file by SHA-256 instead.
"""
import base64
import hashlib
import io
import json
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path


class CrxError(ValueError):
    pass


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if i >= len(buf):
            raise CrxError("truncated protobuf varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise CrxError("protobuf varint too long")


def protobuf_fields(buf: bytes):
    """Yield (field_number, value) pairs. Length-delimited values are bytes, varints are ints."""
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, i = _varint(buf, i)
        elif wire == 2:
            n, i = _varint(buf, i)
            if i + n > len(buf):
                raise CrxError("truncated protobuf field")
            val, i = buf[i:i + n], i + n
        elif wire == 1:
            val, i = buf[i:i + 8], i + 8
        elif wire == 5:
            val, i = buf[i:i + 4], i + 4
        else:
            raise CrxError(f"unsupported protobuf wire type {wire}")
        yield field, val


def id_from_bytes(b: bytes) -> str:
    return "".join("abcdefghijklmnop"[int(c, 16)] for c in b[:16].hex())


def id_from_public_key(der: bytes) -> str:
    """Chrome extension ID = first 16 bytes of SHA-256(public key DER), hex digits mapped to a-p."""
    return id_from_bytes(hashlib.sha256(der).digest())


@dataclass
class Crx:
    ext_id: str
    public_key: bytes      # DER SubjectPublicKeyInfo
    crx_version: int       # 2 or 3
    zip_bytes: bytes
    sha256: str            # of the whole .crx file

    @property
    def manifest_key(self) -> str:
        """Value for manifest.json "key": makes an unpacked copy load with the same ID."""
        return base64.b64encode(self.public_key).decode()

    def zip(self) -> zipfile.ZipFile:
        return zipfile.ZipFile(io.BytesIO(self.zip_bytes))

    def manifest(self) -> dict:
        with self.zip() as z:
            return json.loads(z.read("manifest.json").decode("utf-8-sig"))

    def display_name(self) -> str:
        """manifest name, resolving "__MSG_x__" through _locales/<default_locale>/messages.json."""
        m = self.manifest()
        name = m.get("name", "")
        if not (name.startswith("__MSG_") and name.endswith("__")):
            return name
        key = name[6:-2].lower()
        with self.zip() as z:
            for loc in (m.get("default_locale"), "en", "en_US"):
                try:
                    msgs = json.loads(z.read(f"_locales/{loc}/messages.json").decode("utf-8-sig"))
                except (KeyError, TypeError, ValueError):
                    continue
                for k, v in msgs.items():
                    if k.lower() == key and isinstance(v, dict) and "message" in v:
                        return v["message"]
        return name


def parse_crx(data: bytes) -> Crx:
    if len(data) < 12 or data[:4] != b"Cr24":
        raise CrxError("not a CRX file (missing 'Cr24' magic)")
    (version,) = struct.unpack_from("<I", data, 4)
    if version == 3:
        (hsize,) = struct.unpack_from("<I", data, 8)
        header, zip_start = data[12:12 + hsize], 12 + hsize
        keys, signed = [], None
        for field, val in protobuf_fields(header):
            if field in (2, 3):
                keys += [v for f, v in protobuf_fields(val) if f == 1]
            elif field == 10000:
                signed = val
        if signed is None:
            raise CrxError("CRX3 header has no signed_header_data")
        crx_id = next((v for f, v in protobuf_fields(signed) if f == 1), b"")
        if len(crx_id) != 16:
            raise CrxError("signed_header_data has no 16-byte crx_id")
        matching = [k for k in keys if hashlib.sha256(k).digest()[:16] == crx_id]
        if not matching:
            raise CrxError("no public key in the header matches crx_id")
        key, ext_id = matching[0], id_from_bytes(crx_id)
    elif version == 2:
        klen, slen = struct.unpack_from("<II", data, 8)
        key, zip_start = data[16:16 + klen], 16 + klen + slen
        ext_id = id_from_public_key(key)
    else:
        raise CrxError(f"unsupported CRX version {version}")
    if data[zip_start:zip_start + 4] != b"PK\x03\x04":
        raise CrxError("no zip archive after the CRX header")
    return Crx(ext_id, key, version, data[zip_start:], hashlib.sha256(data).hexdigest())


def read_crx(path: str | Path) -> Crx:
    return parse_crx(Path(path).read_bytes())
