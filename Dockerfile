# syntax=docker/dockerfile:1.7
# Hunting Bad Guys - production image.
#
# Tool versions are declared once as build arguments. `python scripts/update_deps.py`
# bumps them (and the Python lock file) to the latest releases.
ARG PLAYWRIGHT_VERSION=1.62.0

FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble AS base

ARG RADARE2_VERSION=6.2.4
ARG JADX_VERSION=1.5.6
ARG DIE_VERSION=3.21
ARG TEMURIN_VERSION=17.0.20.1+1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:/opt/jadx/bin:/opt/java/bin:$PATH" \
    HUNTER_DATA_DIR=/data

# ── System packages: Tor (onion targets), nmap + torsocks (host probes) ────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends tor torsocks nmap curl unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# ── radare2 + r2ghidra (disassembly / decompilation) ─────────────────────────
# Ubuntu 24.04 ships an old radare2 without r_core.pc, so the official .deb is
# used and the Ghidra decompiler plugin is compiled against it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake g++ make patch pkg-config git && \
    curl -fsSL "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb" -o /tmp/r2.deb && \
    curl -fsSL "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-dev_${RADARE2_VERSION}_amd64.deb" -o /tmp/r2dev.deb && \
    apt-get install -y /tmp/r2.deb /tmp/r2dev.deb && rm /tmp/r2.deb /tmp/r2dev.deb && \
    r2pm -U && r2pm -ci r2ghidra && r2pm -ci r2ghidra-sleigh && \
    apt-get purge -y cmake g++ make patch pkg-config git && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /root/.local/share/radare2/r2pm/git

# ── Detect-It-Easy (packer / compiler identification) ────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libqt5script5 libqt5scripttools5 libqt5svg5 libqt5opengl5 libqt5sql5 \
        libqt5network5 libqt5dbus5 libqt5widgets5 libqt5gui5 libqt5core5a && \
    curl -fsSL "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb" -o /tmp/die.deb && \
    (dpkg -i /tmp/die.deb || apt-get install -y -f) && rm /tmp/die.deb && \
    rm -rf /var/lib/apt/lists/*

# ── JADX (Android decompiler) on a Temurin JRE ────────────────────────────────
RUN TEMURIN_TAG="jdk-$(echo "${TEMURIN_VERSION}" | sed 's/+/%2B/')" && \
    TEMURIN_FILE="OpenJDK17U-jre_x64_linux_hotspot_$(echo "${TEMURIN_VERSION}" | tr '+' '_').tar.gz" && \
    curl -fsSL "https://github.com/adoptium/temurin17-binaries/releases/download/${TEMURIN_TAG}/${TEMURIN_FILE}" -o /tmp/jre.tar.gz && \
    mkdir -p /opt/java && tar xzf /tmp/jre.tar.gz -C /opt/java --strip-components=1 && rm /tmp/jre.tar.gz && \
    curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && chmod +x /opt/jadx/bin/jadx && rm /tmp/jadx.zip

# ── Python dependencies (locked) ─────────────────────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:0.10.0 /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

# ── Application ──────────────────────────────────────────────────────────────
COPY app/ ./app/
COPY static/ ./static/
COPY data/schema.sql ./data/schema.sql
COPY scripts/ingest_feeds.py ./scripts/ingest_feeds.py
COPY docker/entrypoint.sh /entrypoint.sh
COPY CHANGELOG.md README.md ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev && \
    chmod +x /entrypoint.sh

# ── Non-root runtime user ────────────────────────────────────────────────────
# Chromium runs with --no-sandbox inside the container, so the process itself
# must not be root. The Playwright base image ships an unprivileged `pwuser`
# that already owns the browsers; radare2 plugins installed under /root are
# copied into its home.
RUN mkdir -p /data /app/tmp /home/pwuser/.local/share && \
    if [ -d /root/.local/share/radare2 ]; then \
        cp -r /root/.local/share/radare2 /home/pwuser/.local/share/radare2; \
    fi && \
    chown -R pwuser:pwuser /data /app/tmp /home/pwuser
ENV HOME=/home/pwuser
USER pwuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
