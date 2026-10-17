"""Tests for APK and IPA analysis services.

Covers:
- Binary XML (AXML) parser for AndroidManifest.xml
- APK extraction and metadata parsing
- IPA extraction (Info.plist, Mach-O, entitlements)
- EFA service routing for .apk and .ipa extensions
- New DDV endpoints: /efa/apk-disasm and /efa/ipa-disasm
"""

from __future__ import annotations

import io
import plistlib
import struct
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.services.apk_svc as apk_svc
from app.services.apk_svc import _analyse_so_file, _AXMLParser, _parse_manifest
from app.services.ipa_svc import _extract_entitlements, _parse_macho, _run_ipa_sync

# ── Helpers to build synthetic test data ─────────────────────────────────────


def _make_string_pool(strings: list[str], utf8: bool = True) -> bytes:
    """Build a minimal binary XML string pool chunk."""
    n = len(strings)
    flags = 0x100 if utf8 else 0

    encoded: list[bytes] = []
    for s in strings:
        if utf8:
            sb = s.encode("utf-8")
            char_len = len(s)  # simplified: assume ASCII
            byte_len = len(sb)
            encoded.append(bytes([char_len, byte_len]) + sb + b"\x00")
        else:
            chars = s.encode("utf-16-le")
            char_len = len(s)
            encoded.append(struct.pack("<H", char_len) + chars + b"\x00\x00")

    string_data = b"".join(encoded)
    offsets = []
    off = 0
    for e in encoded:
        offsets.append(off)
        off += len(e)

    # header: type(2)+hdrsize(2)+chunksize(4)+strcount(4)+stylecount(4)+flags(4)+stringsstart(4)+stylesstart(4)
    hdr_size = 0x1C
    strings_start = hdr_size + n * 4  # offsets table is n * 4 bytes
    chunk_size = strings_start + len(string_data)

    header = struct.pack("<HH", 0x0001, hdr_size)
    header += struct.pack("<I", chunk_size)
    header += struct.pack("<I", n)  # string_count
    header += struct.pack("<I", 0)  # style_count
    header += struct.pack("<I", flags)  # flags
    header += struct.pack("<I", strings_start)  # strings_start
    header += struct.pack("<I", 0)  # styles_start

    offsets_data = struct.pack("<" + "I" * n, *offsets)
    return header + offsets_data + string_data


def _make_axml_manifest(
    package: str = "com.test.app",
    version_code: int = 1,
    version_name: str = "1.0.0",
    min_sdk: int = 21,
    target_sdk: int = 33,
    permissions: list[str] | None = None,
    activities: list[str] | None = None,
) -> bytes:
    """Build a minimal valid Android binary XML manifest."""
    permissions = permissions or []
    activities = activities or []

    # Build string pool (all strings used in the XML)
    # Order matters — we'll reference them by index
    strings = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "package",
        "versionCode",
        "versionName",
        "minSdkVersion",
        "targetSdkVersion",
        "manifest",
        "uses-sdk",
        "uses-permission",
        "activity",
        "application",
        "name",
        package,
        version_name,
    ]
    perm_strings = list(permissions)
    act_strings = list(activities)
    strings += perm_strings + act_strings

    def si(s: str) -> int:
        return strings.index(s)

    # String pool chunk
    strpool = _make_string_pool(strings)

    # Resource map — map attribute name strings to resource IDs
    # We put the android: attributes in the right positions.
    # For simplicity use zeros; our parser uses string names, not resource IDs
    resmap_count = len(strings)
    resmap_data = struct.pack("<" + "I" * resmap_count, *([0] * resmap_count))
    resmap_hdr = struct.pack("<HH", 0x0180, 8) + struct.pack("<I", 8 + len(resmap_data))
    resmap = resmap_hdr + resmap_data

    def _attr(name_idx: int, dtype: int, ddata: int, raw_idx: int = 0xFFFFFFFF) -> bytes:
        """Build a 20-byte attribute (no namespace for simplicity)."""
        ns = 0xFFFFFFFF  # no ns
        return struct.pack("<IIIHBBI", ns, name_idx, raw_idx, 8, 0, dtype, ddata)

    def _start_el(name_idx: int, attrs: bytes) -> bytes:
        """Build a START_ELEMENT chunk."""
        attr_count = len(attrs) // 20
        # chunk: type(2)+hdrsize(2)+chunksize(4)+lineno(4)+comment(4)+ns(4)+name(4)+
        #        attrstart(2)+attrsize(2)+attrcount(2)+id(2)+class(2)+style(2)
        hdr_size = 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2  # = 36
        chunk_size = hdr_size + len(attrs)
        header = struct.pack("<HH", 0x0102, hdr_size)
        header += struct.pack("<I", chunk_size)
        header += struct.pack("<I", 1)  # line number
        header += struct.pack("<I", 0xFFFFFFFF)  # comment
        header += struct.pack("<I", 0xFFFFFFFF)  # ns
        header += struct.pack("<I", name_idx)
        header += struct.pack("<H", 20)  # attr_start (from attrExt = 16..36)
        # wait: attrExt starts at offset 16 from chunk start
        # attrStart = offset from attrExt (pos+16) to first attribute
        # attrExt is 20 bytes, so attrStart = 20
        header += struct.pack("<H", 20)  # attr_size
        header += struct.pack("<H", attr_count)  # attr_count
        header += struct.pack("<HHH", 0, 0, 0)  # idIndex, classIndex, styleIndex
        return header + attrs

    def _end_el(name_idx: int) -> bytes:
        """Build an END_ELEMENT chunk."""
        hdr_size = 8 + 4 + 4 + 4 + 4
        header = struct.pack("<HH", 0x0103, hdr_size)
        header += struct.pack("<I", hdr_size)
        header += struct.pack("<I", 1)
        header += struct.pack("<I", 0xFFFFFFFF)
        header += struct.pack("<I", 0xFFFFFFFF)
        header += struct.pack("<I", name_idx)
        return header

    # ── Build XML tree ────────────────────────────────────────────────────────
    TYPE_INT_DEC = 0x10
    TYPE_STRING = 0x03

    # <manifest package="..." versionCode="..." versionName="...">
    manifest_attrs = _attr(si("package"), TYPE_STRING, si(package))
    manifest_attrs += _attr(si("versionCode"), TYPE_INT_DEC, version_code)
    manifest_attrs += _attr(si("versionName"), TYPE_STRING, si(version_name))

    # <uses-sdk minSdkVersion="..." targetSdkVersion="...">
    sdk_attrs = _attr(si("minSdkVersion"), TYPE_INT_DEC, min_sdk)
    sdk_attrs += _attr(si("targetSdkVersion"), TYPE_INT_DEC, target_sdk)

    xml_body = _start_el(si("manifest"), manifest_attrs)
    xml_body += _start_el(si("uses-sdk"), sdk_attrs)
    xml_body += _end_el(si("uses-sdk"))

    for perm in permissions:
        psi = si(perm)
        pattrs = _attr(si("name"), TYPE_STRING, psi)
        xml_body += _start_el(si("uses-permission"), pattrs)
        xml_body += _end_el(si("uses-permission"))

    xml_body += _start_el(si("application"), b"")
    for act in activities:
        asi = si(act)
        aattrs = _attr(si("name"), TYPE_STRING, asi)
        xml_body += _start_el(si("activity"), aattrs)
        xml_body += _end_el(si("activity"))
    xml_body += _end_el(si("application"))

    xml_body += _end_el(si("manifest"))

    xml_body = strpool + resmap + xml_body

    # File header: type=0x0003, hdrsize=8, filesize
    file_size = 8 + len(xml_body)
    file_hdr = struct.pack("<HHI", 0x0003, 8, file_size)
    return file_hdr + xml_body


def _make_minimal_elf(bits: int = 64, machine: int = 0xB7) -> bytes:
    """Build a minimal valid ELF header (no sections)."""
    e_class = 2 if bits == 64 else 1
    header = b"\x7fELF"
    header += bytes([e_class, 1, 1, 0])  # class, data=LE, version, OS/ABI
    header += b"\x00" * 8  # padding
    header += struct.pack("<H", 3)  # e_type = ET_DYN (shared object)
    header += struct.pack("<H", machine)  # e_machine
    header += struct.pack("<I", 1)  # e_version
    if bits == 64:
        header += struct.pack("<QQQ", 0, 0x40, 0)  # entry, phoff, shoff
        header += struct.pack("<I", 0)  # flags
        header += struct.pack("<H", 64)  # ehsize
        header += struct.pack("<HHHHHH", 56, 0, 0, 64, 0, 0)  # ph/sh info
    else:
        header += struct.pack("<III", 0, 0x34, 0)  # entry, phoff, shoff
        header += struct.pack("<I", 0)  # flags
        header += struct.pack("<H", 52)  # ehsize
        header += struct.pack("<HHHHHH", 32, 0, 0, 40, 0, 0)
    return header + b"\x00" * 256


def _make_test_apk(with_manifest: bool = True, with_so: bool = True) -> bytes:
    """Build a minimal synthetic APK (ZIP with manifest + optional .so)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        if with_manifest:
            manifest = _make_axml_manifest(
                package="com.test.app",
                version_code=42,
                version_name="2.3.0",
                min_sdk=24,
                target_sdk=33,
                permissions=["android.permission.INTERNET", "android.permission.CAMERA"],
                activities=["com.test.app.MainActivity"],
            )
            zf.writestr("AndroidManifest.xml", manifest)
        # Minimal DEX header (magic + version + checksum + ...)
        dex_header = b"dex\n035\x00" + b"\x00" * 104
        zf.writestr("classes.dex", dex_header)
        if with_so:
            elf_data = _make_minimal_elf(bits=64, machine=0xB7)  # AArch64
            zf.writestr("lib/arm64-v8a/libnative.so", elf_data)
            zf.writestr("lib/armeabi-v7a/libnative.so", _make_minimal_elf(bits=32, machine=0x28))
        zf.writestr("assets/config.json", b'{"key":"value"}')
        zf.writestr("res/layout/main.xml", b"<LinearLayout/>")
    return buf.getvalue()


def _make_test_ipa(
    bundle_id: str = "com.test.app",
    display_name: str = "TestApp",
    version: str = "1.0",
) -> bytes:
    """Build a minimal synthetic IPA (ZIP with Info.plist + Mach-O binary)."""
    buf = io.BytesIO()
    info = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleDisplayName": display_name,
        "CFBundleName": display_name,
        "CFBundleShortVersionString": version,
        "CFBundleVersion": "100",
        "CFBundleExecutable": "TestApp",
        "MinimumOSVersion": "14.0",
        "DTPlatformName": "iphoneos",
        "NSCameraUsageDescription": "For scanning",
    }
    # Mach-O thin arm64 little-endian 64-bit
    macho = _make_minimal_macho()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("Payload/TestApp.app/Info.plist", plistlib.dumps(info))
        zf.writestr("Payload/TestApp.app/TestApp", macho)
        zf.writestr("Payload/TestApp.app/Frameworks/UIKit.framework/", b"")
        zf.writestr("Payload/TestApp.app/Frameworks/UIKit.framework/UIKit", b"\xcf\xfa\xed\xfe")
    return buf.getvalue()


def _make_minimal_macho() -> bytes:
    """Build a minimal valid Mach-O 64-bit arm64 LE (little-endian) header.

    Apple arm64 binaries have:
      magic = MH_MAGIC_64 = 0xFEEDFACF
    Stored as little-endian bytes: CF FA ED FE.
    When the parser reads those 4 bytes as big-endian it gets 0xCFFAEDFE,
    which maps to ('little', 64) in _MACHO_MAGIC.
    """
    magic = 0xFEEDFACF  # MH_MAGIC_64, will be stored as CF FA ED FE (LE)
    cputype = 0x0100000C  # CPU_TYPE_ARM64
    cpusubtype = 0x00000000
    filetype = 0x00000002  # MH_EXECUTE
    ncmds = 0
    sizeofcmds = 0
    flags = 0x00200085  # PIE + NOUNDEFS + DYLDLINK + TWOLEVEL

    header = struct.pack("<IIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags)
    header += struct.pack("<I", 0)  # reserved (64-bit header)
    return header + b"\x00" * 64


# ── AXML parser tests ─────────────────────────────────────────────────────────


class TestAXMLParser:
    def test_parse_package(self):
        axml = _make_axml_manifest(package="com.evil.malware")
        result = _AXMLParser(axml).parse()
        assert result["package"] == "com.evil.malware"

    def test_parse_version(self):
        axml = _make_axml_manifest(version_code=99, version_name="3.14.0")
        result = _AXMLParser(axml).parse()
        assert result["version_code"] == 99
        assert result["version_name"] == "3.14.0"

    def test_parse_sdk_versions(self):
        axml = _make_axml_manifest(min_sdk=23, target_sdk=34)
        result = _AXMLParser(axml).parse()
        assert result["min_sdk"] == 23
        assert result["target_sdk"] == 34

    def test_parse_permissions(self):
        perms = ["android.permission.INTERNET", "android.permission.CAMERA"]
        axml = _make_axml_manifest(permissions=perms)
        result = _AXMLParser(axml).parse()
        assert set(perms).issubset(set(result["permissions"]))

    def test_parse_activities(self):
        acts = ["com.test.MainActivity"]
        axml = _make_axml_manifest(activities=acts)
        result = _AXMLParser(axml).parse()
        assert "com.test.MainActivity" in result["activities"]

    def test_invalid_data_returns_error(self):
        result = _AXMLParser(b"\x00\x00\x00\x00").parse()
        assert "error" in result

    def test_empty_data_returns_error(self):
        result = _AXMLParser(b"").parse()
        assert "error" in result

    def test_fallback_plaintext_xml(self):
        xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.plain.app"
          android:versionCode="5"
          android:versionName="1.5">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application>
    <activity android:name="com.plain.app.Main"/>
  </application>
</manifest>"""
        result = _parse_manifest(xml)
        assert result["package"] == "com.plain.app"
        assert "android.permission.INTERNET" in result["permissions"]
        assert "com.plain.app.Main" in result["activities"]


# ── APK service tests ─────────────────────────────────────────────────────────


class TestAPKSvc:
    def test_analyse_so_file_elf(self):
        elf = _make_minimal_elf(bits=64, machine=0xB7)
        entry = _analyse_so_file("lib/arm64-v8a/libtest.so", elf)
        assert entry["path"] == "lib/arm64-v8a/libtest.so"
        assert "elf" in entry
        assert entry["elf"]["machine"] == "AArch64"
        assert entry["elf"]["bits"] == 64
        assert "hex_dump" in entry

    def test_analyse_so_file_size_capped(self):
        large = b"\x7fELF" + b"\x00" * (3 * 1024 * 1024)
        entry = _analyse_so_file("lib/test.so", large)
        # hex_dump should be capped at 2MB
        assert entry["hex_size"] <= 2 * 1024 * 1024

    def test_run_apk_sync_basic(self):
        """Minimal APK: manifest parsed, so files listed."""
        from app.services.apk_svc import _run_apk_sync

        apk_data = _make_test_apk(with_manifest=True, with_so=True)
        result = _run_apk_sync(apk_data)

        assert "manifest" in result
        mf = result["manifest"]
        assert mf["package"] == "com.test.app"
        assert mf["version_code"] == 42
        assert mf["version_name"] == "2.3.0"
        assert mf["min_sdk"] == 24
        assert mf["target_sdk"] == 33
        assert "android.permission.INTERNET" in mf["permissions"]
        assert "android.permission.CAMERA" in mf["permissions"]

    def test_run_apk_sync_so_files(self):
        from app.services.apk_svc import _run_apk_sync

        apk_data = _make_test_apk(with_so=True)
        result = _run_apk_sync(apk_data)

        assert len(result["so_files"]) == 2
        paths = {s["path"] for s in result["so_files"]}
        assert "lib/arm64-v8a/libnative.so" in paths
        assert "lib/armeabi-v7a/libnative.so" in paths

    def test_run_apk_sync_dex_listed(self):
        from app.services.apk_svc import _run_apk_sync

        apk_data = _make_test_apk()
        result = _run_apk_sync(apk_data)
        assert "classes.dex" in result["dex_files"]

    def test_run_apk_sync_bad_zip(self):
        from app.services.apk_svc import _run_apk_sync

        result = _run_apk_sync(b"not a zip")
        assert "error" in result

    def test_run_apk_sync_no_jadx(self):
        """Without jadx in PATH, jadx status should be not_available."""
        from app.services.apk_svc import _run_apk_sync

        with patch("shutil.which", return_value=None):
            apk_data = _make_test_apk()
            result = _run_apk_sync(apk_data)
        assert result["jadx"]["status"] == "not_available"

    @pytest.mark.asyncio
    async def test_analyse_async(self):
        """Async wrapper returns same structure."""
        apk_data = _make_test_apk()
        with patch("shutil.which", return_value=None):
            result = await apk_svc.analyse(apk_data)
        assert "manifest" in result
        assert result["manifest"]["package"] == "com.test.app"

    def test_jadx_not_available_returns_flag(self):
        """jadx_available() returns False when jadx is not in PATH."""
        with patch("shutil.which", return_value=None):
            assert apk_svc.jadx_available() is False


# ── IPA service tests ─────────────────────────────────────────────────────────


class TestIPASvc:
    def test_parse_macho_arm64_le(self):
        macho = _make_minimal_macho()
        result = _parse_macho(macho)
        assert result["arch"] == "arm64"
        assert result["bits"] == 64
        assert result["endian"] == "little"
        assert result["filetype"] == "execute"
        assert result["is_pie"] is True

    def test_parse_macho_empty(self):
        result = _parse_macho(b"")
        assert result == {}

    def test_parse_macho_invalid_magic(self):
        result = _parse_macho(b"\x00\x00\x00\x00\x00\x00\x00\x00")
        assert "error" in result

    def test_extract_entitlements_from_plist(self):
        ent_plist = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>application-identifier</key>
  <string>TEAM123.com.test.app</string>
  <key>get-task-allow</key>
  <false/>
</dict>
</plist>"""
        ents = _extract_entitlements(ent_plist)
        assert ents.get("application-identifier") == "TEAM123.com.test.app"
        assert ents.get("get-task-allow") is False

    def test_extract_entitlements_missing(self):
        ents = _extract_entitlements(b"no plist here")
        assert ents == {}

    def test_run_ipa_sync_basic(self):
        ipa_data = _make_test_ipa(bundle_id="com.example.ios", display_name="ExampleApp")
        result = _run_ipa_sync(ipa_data)

        assert result["bundle_id"] == "com.example.ios"
        assert result["display_name"] == "ExampleApp"
        assert result["version"] == "1.0"
        assert result["min_os_version"] == "14.0"
        assert result["platform"] == "iphoneos"

    def test_run_ipa_sync_frameworks(self):
        ipa_data = _make_test_ipa()
        result = _run_ipa_sync(ipa_data)
        # UIKit.framework should be detected
        assert any("UIKit" in fw for fw in result["frameworks"])

    def test_run_ipa_sync_main_binary(self):
        ipa_data = _make_test_ipa()
        result = _run_ipa_sync(ipa_data)

        assert result["main_binary"] is not None
        mb = result["main_binary"]
        assert mb["path"].endswith("/TestApp")
        assert "macho" in mb
        assert "hex_dump" in mb
        # Mach-O architecture
        mc = mb["macho"]
        assert mc.get("arch") == "arm64"

    def test_run_ipa_sync_bad_zip(self):
        result = _run_ipa_sync(b"not a zip")
        assert "error" in result

    def test_run_ipa_sync_info_plist_extras(self):
        ipa_data = _make_test_ipa()
        result = _run_ipa_sync(ipa_data)
        # NSCameraUsageDescription was added to Info.plist
        assert "NSCameraUsageDescription" in result.get("info_plist", {})


# ── EFA service routing tests ─────────────────────────────────────────────────


class TestEFARouting:
    """Test that efa_svc.analyse() correctly routes APK/IPA files."""

    @pytest.mark.asyncio
    async def test_apk_ext_routes_to_apk_svc(self):
        from app.services import efa_svc

        apk_data = _make_test_apk()

        async def _mock_get(url, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = apk_data
            resp.headers = {"content-type": "application/octet-stream"}
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _mock_get

        with patch("shutil.which", return_value=None):
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = await efa_svc.analyse(
                    url="http://example.com/app.apk",
                    path="/app.apk",
                    content_type=None,
                    size=None,
                )
        assert result["file_type"] == "apk"
        assert "apk" in result
        assert result["apk"]["manifest"]["package"] == "com.test.app"

    @pytest.mark.asyncio
    async def test_ipa_ext_routes_to_ipa_svc(self):
        from app.services import efa_svc

        ipa_data = _make_test_ipa()

        async def _mock_get(url, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = ipa_data
            resp.headers = {"content-type": "application/octet-stream"}
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _mock_get

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await efa_svc.analyse(
                url="http://example.com/MyApp.ipa",
                path="/MyApp.ipa",
                content_type=None,
                size=None,
            )
        assert result["file_type"] == "ipa"
        assert "ipa" in result
        assert result["ipa"]["bundle_id"] == "com.test.app"

    @pytest.mark.asyncio
    async def test_zip_not_apk_uses_zip_branch(self):
        """A plain .zip file should not trigger APK analysis."""
        from app.services import efa_svc

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", b"hello")
        zip_data = buf.getvalue()

        async def _mock_get(url, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = zip_data
            resp.headers = {"content-type": "application/zip"}
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _mock_get

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await efa_svc.analyse(
                url="http://example.com/archive.zip",
                path="/archive.zip",
                content_type=None,
                size=None,
            )
        # Should be zip, not apk
        assert result["file_type"] == "zip"


# ── API endpoint tests ─────────────────────────────────────────────────────────

from httpx import ASGITransport, AsyncClient

from app import auth as auth_module
from app.config import settings
from app.main import app as fastapi_app


@pytest.fixture(autouse=True)
def clear_users():
    auth_module._users.clear()
    auth_module._username_index.clear()
    yield
    auth_module._users.clear()
    auth_module._username_index.clear()


@pytest.fixture
async def auth_client():
    async with AsyncClient(transport=ASGITransport(app=fastapi_app), base_url="http://test") as c:
        await c.post(
            "/auth/register",
            json={
                "username": "apktest",
                "password": "pass1234",
                "invite_code": settings.invite_code,
            },
        )
        await c.post("/auth/login", json={"username": "apktest", "password": "pass1234"})
        yield c


@pytest.mark.asyncio
async def test_apk_disasm_endpoint_not_found(auth_client):
    """apk-disasm returns 404 when result doesn't exist."""
    resp = await auth_client.post(
        "/results/nonexistent/efa/apk-disasm",
        params={"path": "/app.apk", "so_path": "lib/arm64-v8a/libnative.so"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_ipa_disasm_endpoint_not_found(auth_client):
    """ipa-disasm returns 404 when result doesn't exist."""
    resp = await auth_client.post(
        "/results/nonexistent/efa/ipa-disasm",
        params={"path": "/app.ipa"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_apk_disasm_endpoint_missing_efa_entry(auth_client):
    """apk-disasm returns 404 when result exists but EFA path not found."""
    from app.main import _stores

    uid = list(auth_module._users.keys())[0]
    _stores[uid] = {"rid1": {"_id": "rid1", "target": "test.com", "efa": []}}

    resp = await auth_client.post(
        "/results/rid1/efa/apk-disasm",
        params={"path": "/missing.apk", "so_path": "lib/test.so"},
    )
    assert resp.status_code == 404
    _stores.pop(uid, None)


@pytest.mark.asyncio
async def test_ipa_disasm_endpoint_no_hex_dump(auth_client):
    """ipa-disasm returns 400 when main_binary has no hex_dump."""
    from app.main import _stores

    uid = list(auth_module._users.keys())[0]
    _stores[uid] = {
        "rid2": {
            "_id": "rid2",
            "target": "test.com",
            "efa": [
                {
                    "path": "/app.ipa",
                    "file_type": "ipa",
                    "ipa": {"main_binary": {"path": "Payload/App.app/App"}},
                }
            ],
        }
    }

    resp = await auth_client.post(
        "/results/rid2/efa/ipa-disasm",
        params={"path": "/app.ipa"},
    )
    assert resp.status_code == 400
    _stores.pop(uid, None)
