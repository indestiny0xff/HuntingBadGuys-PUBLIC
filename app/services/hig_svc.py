"""
Host Intelligence Gathering (HIG).

Runs an aggressive service/OS probe against a single IP and routes the traffic
through Tor (via torsocks) so the origin host is not exposed. The underlying
tool is an implementation detail — nothing here is surfaced to the UI by name;
callers only ever see the parsed :class:`HIGInfo`.

Tor note: Tor's default circuit rotation (``MaxCircuitDirtiness`` 10 min) already
gives a fresh exit IP well within a day, and each scan opens new streams, so no
torrc change is required to satisfy "rotate at least once per day".
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from ..models import HIGInfo, HIGPort, HIGScript

log = logging.getLogger(__name__)

_BIN = "nmap"
_TORSOCKS = "torsocks"

# Per-host budget handed to the scanner, plus a small outer margin for the
# subprocess wrapper. The full (-p-) sweep over Tor is much slower, so it gets a
# far larger budget.
_HOST_TIMEOUT_DEFAULT = 300  # seconds
_HOST_TIMEOUT_ALL_PORTS = 1500  # seconds
_OUTER_MARGIN = 60


def _build_argv(ip: str, *, via_tor: bool, all_ports: bool) -> list[str]:
    host_timeout = _HOST_TIMEOUT_ALL_PORTS if all_ports else _HOST_TIMEOUT_DEFAULT
    # The container has no CAP_NET_RAW, so raw-packet scan types fail with
    # "Couldn't open a raw socket". And over Tor only TCP connect scans traverse
    # the SOCKS proxy. So BOTH paths use a TCP connect scan with version +
    # default-script detection (skip ping, no DNS); -A's OS detection /
    # traceroute are dropped (they need raw sockets and can't work here anyway).
    # The only difference between the paths is whether we wrap in torsocks.
    # --reason records why each port is reported in its state (e.g. syn-ack),
    # which helps separate real services from proxy/CDN artefacts.
    base = [
        _BIN,
        "-sT",
        "-Pn",
        "-n",
        "-sV",
        "-sC",
        "-T4",
        "--reason",
        "--host-timeout",
        f"{host_timeout}s",
        "-oX",
        "-",
    ]
    args = ([_TORSOCKS] + base) if via_tor else base
    if all_ports:
        args.append("-p-")
    args.append(ip)
    return args


def _text(el: ET.Element | None) -> str | None:
    if el is None:
        return None
    return (el.get("output") or "").strip() or None


def _parse_scripts(parent: ET.Element) -> list[HIGScript]:
    out: list[HIGScript] = []
    for s in parent.findall("script"):
        sid = s.get("id")
        output = (s.get("output") or "").strip()
        if sid and output:
            out.append(HIGScript(id=sid, output=output))
    return out


def _parse_xml(xml: str, *, via_tor: bool, all_ports: bool) -> HIGInfo:
    info = HIGInfo(
        via_tor=via_tor, all_ports=all_ports, scanned_at=datetime.now(timezone.utc).isoformat()
    )
    root = ET.fromstring(xml)
    host = root.find("host")
    if host is None:
        info.state = "down"
        return info

    status = host.find("status")
    if status is not None:
        info.state = status.get("state")

    for addr in host.findall("address"):
        if addr.get("addrtype", "").startswith("ipv") and not info.ip:
            info.ip = addr.get("addr")

    hostnames_el = host.find("hostnames")
    if hostnames_el is not None:
        info.hostnames = [h.get("name") for h in hostnames_el.findall("hostname") if h.get("name")]

    ports_el = host.find("ports")
    if ports_el is not None:
        for p in ports_el.findall("port"):
            try:
                portid = int(p.get("portid", ""))
            except ValueError:
                continue
            state_el = p.find("state")
            state = state_el.get("state") if state_el is not None else None
            reason = state_el.get("reason") if state_el is not None else None
            # Only surface ports that are actually reachable.
            if state not in ("open", "open|filtered"):
                continue
            svc = p.find("service")
            cpe = [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text]
            info.ports.append(
                HIGPort(
                    port=portid,
                    protocol=p.get("protocol", "tcp"),
                    state=state,
                    reason=reason,
                    service=svc.get("name") if svc is not None else None,
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                    extra_info=svc.get("extrainfo") if svc is not None else None,
                    cpe=cpe,
                    scripts=_parse_scripts(p),
                )
            )
    info.ports.sort(key=lambda x: x.port)

    os_el = host.find("os")
    if os_el is not None:
        for m in os_el.findall("osmatch"):
            name = m.get("name")
            if name:
                info.os_matches.append({"name": name, "accuracy": m.get("accuracy")})

    hostscript = host.find("hostscript")
    if hostscript is not None:
        info.scripts = _parse_scripts(hostscript)

    return info


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the scanner and anything it spawned (process group), best effort."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


async def scan(ip: str, *, via_tor: bool = True, all_ports: bool = False) -> HIGInfo:
    """
    Probe `ip` and return a populated :class:`HIGInfo`. Always returns an object
    (never raises): transport / tooling problems are reported via `.error` so the
    UI can show the section with a diagnostic instead of vanishing.
    """
    if shutil.which(_BIN) is None:
        return HIGInfo(
            ip=ip, via_tor=via_tor, all_ports=all_ports, error="Scanner not available on host"
        )
    if via_tor and shutil.which(_TORSOCKS) is None:
        return HIGInfo(
            ip=ip, via_tor=via_tor, all_ports=all_ports, error="Tor routing unavailable on host"
        )

    argv = _build_argv(ip, via_tor=via_tor, all_ports=all_ports)
    host_timeout = _HOST_TIMEOUT_ALL_PORTS if all_ports else _HOST_TIMEOUT_DEFAULT
    log.info("HIG scan ip=%s all_ports=%s via_tor=%s", ip, all_ports, via_tor)
    # Two independent guards: `timeout` kills the scanner from outside the
    # event loop (cancelling asyncio's communicate() can hang when a child
    # keeps the pipes open), and the asyncio guard kills the whole process
    # group if even that fails. nmap's own --host-timeout is the third layer.
    if shutil.which("timeout"):
        argv = ["timeout", "-k", "10", str(host_timeout + 30), *argv]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=host_timeout + _OUTER_MARGIN
            )
        except TimeoutError:
            _kill_group(proc)
            return HIGInfo(ip=ip, via_tor=via_tor, all_ports=all_ports, error="Scan timed out")
    except Exception as exc:
        log.warning("HIG scan failed to launch for %s: %s", ip, exc)
        return HIGInfo(ip=ip, via_tor=via_tor, all_ports=all_ports, error=str(exc))

    xml = (stdout or b"").decode("utf-8", "replace").strip()
    if not xml:
        err = (stderr or b"").decode("utf-8", "replace").strip()[:300] or "No scan output"
        return HIGInfo(ip=ip, via_tor=via_tor, all_ports=all_ports, error=err)

    try:
        info = _parse_xml(xml, via_tor=via_tor, all_ports=all_ports)
        if not info.ip:
            info.ip = ip
        return info
    except ET.ParseError as exc:
        log.warning("HIG parse failed for %s: %s", ip, exc)
        return HIGInfo(
            ip=ip, via_tor=via_tor, all_ports=all_ports, error="Could not parse scan output"
        )
