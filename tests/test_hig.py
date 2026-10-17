"""Tests for the Host Intelligence Gathering (HIG) service.

All external I/O (the scanner subprocess, tool discovery) is mocked — no real
scans run.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import HIGInfo
from app.services import hig_svc

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="185.220.101.45" addrtype="ipv4"/>
    <hostnames>
      <hostname name="secure-login-microsoft.ru" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.4p1" extrainfo="protocol 2.0">
          <cpe>cpe:/a:openbsd:openssh:8.4p1</cpe>
        </service>
        <script id="ssh-hostkey" output="2048 SHA256:abc (RSA)"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="9">
        <state state="closed" reason="conn-refused"/>
        <service name="discard"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="94"/>
      <osmatch name="Linux 4.x" accuracy="88"/>
    </os>
    <hostscript>
      <script id="traceroute" output="suppressed via Tor"/>
    </hostscript>
  </host>
</nmaprun>"""


# ── _parse_xml ────────────────────────────────────────────────────────────────


def test_parse_xml_extracts_open_ports_only():
    info = hig_svc._parse_xml(_SAMPLE_XML, via_tor=True, all_ports=False)
    assert info.state == "up"
    assert info.ip == "185.220.101.45"
    assert info.hostnames == ["secure-login-microsoft.ru"]
    # The closed port 9 must be filtered out.
    assert [p.port for p in info.ports] == [22, 443]


def test_parse_xml_service_and_scripts():
    info = hig_svc._parse_xml(_SAMPLE_XML, via_tor=True, all_ports=False)
    ssh = next(p for p in info.ports if p.port == 22)
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.4p1"
    assert ssh.cpe == ["cpe:/a:openbsd:openssh:8.4p1"]
    assert ssh.scripts[0].id == "ssh-hostkey"


def test_parse_xml_os_and_host_scripts():
    info = hig_svc._parse_xml(_SAMPLE_XML, via_tor=True, all_ports=False)
    assert info.os_matches[0] == {"name": "Linux 5.x", "accuracy": "94"}
    assert info.scripts[0].id == "traceroute"
    assert info.via_tor is True


def test_parse_xml_host_down():
    xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    info = hig_svc._parse_xml(xml, via_tor=False, all_ports=True)
    assert info.state == "down"
    assert info.all_ports is True


# ── _build_argv ───────────────────────────────────────────────────────────────


def test_build_argv_tor_uses_connect_scan_and_torsocks():
    argv = hig_svc._build_argv("1.2.3.4", via_tor=True, all_ports=False)
    assert argv[0] == "torsocks"
    assert "-sT" in argv and "-Pn" in argv and "-n" in argv
    assert "-p-" not in argv
    assert argv[-1] == "1.2.3.4"


def test_build_argv_all_ports_adds_full_range():
    argv = hig_svc._build_argv("1.2.3.4", via_tor=True, all_ports=True)
    assert "-p-" in argv


def test_build_argv_uses_reason_by_default():
    argv = hig_svc._build_argv("1.2.3.4", via_tor=False, all_ports=False)
    assert "--reason" in argv


def test_parse_xml_keeps_port_reason():
    xml = (
        '<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/>'
        '<service name="https"/></port></ports></host></nmaprun>'
    )
    info = hig_svc._parse_xml(xml, via_tor=False, all_ports=False)
    assert info.ports[0].port == 443
    assert info.ports[0].reason == "syn-ack"


def test_build_argv_direct_no_torsocks():
    argv = hig_svc._build_argv("1.2.3.4", via_tor=False, all_ports=False)
    assert argv[0] == "nmap"
    assert "torsocks" not in argv
    # Must use a TCP connect scan (no raw sockets in the container), not -A.
    assert "-sT" in argv
    assert "-A" not in argv


def test_build_argv_tor_and_direct_differ_only_by_torsocks():
    tor = hig_svc._build_argv("1.2.3.4", via_tor=True, all_ports=False)
    direct = hig_svc._build_argv("1.2.3.4", via_tor=False, all_ports=False)
    assert tor[0] == "torsocks"
    assert tor[1:] == direct


# ── scan (graceful failure paths) ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_returns_error_when_scanner_missing():
    with patch.object(hig_svc.shutil, "which", return_value=None):
        info = await hig_svc.scan("8.8.8.8", via_tor=True)
    assert isinstance(info, HIGInfo)
    assert info.error == "Scanner not available on host"


@pytest.mark.asyncio
async def test_scan_returns_error_when_tor_missing():
    def which(name):
        return "/usr/bin/nmap" if name == "nmap" else None

    with patch.object(hig_svc.shutil, "which", side_effect=which):
        info = await hig_svc.scan("8.8.8.8", via_tor=True)
    assert info.error == "Tor routing unavailable on host"


@pytest.mark.asyncio
async def test_scan_parses_subprocess_output():
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(_SAMPLE_XML.encode(), b""))
    with (
        patch.object(hig_svc.shutil, "which", return_value="/usr/bin/x"),
        patch.object(hig_svc.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)),
    ):
        info = await hig_svc.scan("185.220.101.45", via_tor=True, all_ports=True)
    assert info.ip == "185.220.101.45"
    assert [p.port for p in info.ports] == [22, 443]
    assert info.all_ports is True
    assert info.error is None


@pytest.mark.asyncio
async def test_scan_empty_output_reports_error():
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b"some stderr noise"))
    with (
        patch.object(hig_svc.shutil, "which", return_value="/usr/bin/x"),
        patch.object(hig_svc.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)),
    ):
        info = await hig_svc.scan("8.8.8.8", via_tor=True)
    assert "some stderr noise" in info.error
