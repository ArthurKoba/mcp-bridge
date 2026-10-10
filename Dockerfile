FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS dependencies

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONPATH=/app/services

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gosu netcat-openbsd util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project




FROM node:22-bookworm-slim AS chrome-devtools-mcp
RUN npm install --global --prefix /opt/chrome-devtools-mcp chrome-devtools-mcp@1.10.1

FROM dependencies AS runtime-base

ARG BUILD_SHA=unknown
ARG BUILD_TIME=unknown

ENV FASTMCP_HOME=/authorization \
    HOME=/home/bridge \
    BUILD_SHA=${BUILD_SHA} \
    BUILD_TIME=${BUILD_TIME}

COPY docker-entrypoint.sh /usr/local/bin/bridge-entrypoint
RUN chmod 0755 /usr/local/bin/bridge-entrypoint \
    && mkdir -p /authorization /admin-api /home/bridge \
    && chown -R 1000:1000 /authorization /admin-api /home/bridge

COPY services/common ./services/common

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["nc", "-z", "-w", "1", "127.0.0.1", "8000"]

ENTRYPOINT ["/usr/local/bin/bridge-entrypoint"]
CMD ["/app/.venv/bin/python", "-m", "common.asgi"]


FROM runtime-base AS authorization
COPY services/authorization ./services/authorization
# The historical global Authorization DB provisioner was retired with
# briareus_dev. Owner-local migrations belong ONLY to the reviewed Backend
# owner-specific startup image; never resurrect a missing global init script.
ENV ASGI_APP=authorization.runtime:app


FROM runtime-base AS gateway
COPY services/bridge ./services/bridge
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
ENV ASGI_APP=bridge.server:app


FROM runtime-base AS admin-api
COPY services/admin-api/src ./services/admin-api/src
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/files ./services/modules/files
ENV ASGI_APP=runtime:app \
    PYTHONPATH=/app/services:/app/services/admin-api/src \
    ASGI_FORWARDED_ALLOW_IPS=* \
    FILE_WORKSPACE_ROOT=/workspace


FROM runtime-base AS github
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/github ./services/modules/github
ENV ASGI_APP=modules.github.runtime:app


FROM runtime-base AS gitlab
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/gitlab ./services/modules/gitlab
ENV ASGI_APP=modules.gitlab.runtime:app


FROM runtime-base AS files
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/files ./services/modules/files
ENV ASGI_APP=modules.files.runtime:app \
    FILE_WORKSPACE_ROOT=/workspace


FROM runtime-base AS web
COPY --from=chrome-devtools-mcp /usr/local/bin/node /usr/local/bin/node
COPY --from=chrome-devtools-mcp /opt/chrome-devtools-mcp /opt/chrome-devtools-mcp
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        chromium chromium-l10n fonts-liberation fonts-noto-color-emoji locales tzdata xvfb \
        libegl1 libgbm1 libgl1-mesa-dri libglx-mesa0 libva2 mesa-vulkan-drivers vainfo intel-media-va-driver \
    && sed -i 's/^# *\\(ru_RU.UTF-8 UTF-8\\)/\\1/' /etc/locale.gen \
    && sed -i 's/^# *\\(en_US.UTF-8 UTF-8\\)/\\1/' /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/* \
    && uv sync --frozen --no-dev --group web --no-install-project
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/files ./services/modules/files
COPY services/modules/web ./services/modules/web
ENV ASGI_APP=modules.web.runtime:app \
    FILE_WORKSPACE_ROOT=/workspace \
    BROWSER_PROFILE_PATH=/browser/profile \
    BROWSER_EXECUTABLE_PATH=/usr/bin/chromium \
    BROWSER_DEVTOOLS_MCP_SCRIPT_PATH=/opt/chrome-devtools-mcp/lib/node_modules/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js \
    CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS=1 \
    CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1 \
    CHROME_DEVTOOLS_MCP_NO_CONFIG_DISCOVERY=1 \
    XDG_CONFIG_HOME=/browser/config \
    XDG_CACHE_HOME=/browser/cache \
    BREAKPAD_DUMP_LOCATION=/browser/crash


FROM runtime-base AS terminal
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential sed git git-lfs gh openssh-client wget ripgrep findutils patch diffutils rsync jq \
        tar zip unzip gzip bzip2 xz-utils make gcc g++ binutils cmake ninja-build pkg-config \
        ccache autoconf automake libtool \
        python3-venv bc bison flex gawk gettext cpio file perl which libncurses-dev \
        procps psmisc lsof strace gdb iproute2 socat netcat-openbsd \
        picocom python3-serial \
    && rm -rf /var/lib/apt/lists/*
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/terminal ./services/modules/terminal
ENV ASGI_APP=modules.terminal.runtime:app \
    HOME=/home/agent \
    TERMINAL_WORKSPACE_ROOT=/workspace \
    TERMINAL_HOME=/home/agent


FROM runtime-base AS analysis
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/files ./services/modules/files
COPY services/modules/analysis ./services/modules/analysis
ENV ASGI_APP=modules.analysis.runtime:app \
    FILE_WORKSPACE_ROOT=/workspace


FROM runtime-base AS ghidra
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/ghidra ./services/modules/ghidra
ENV ASGI_APP=modules.ghidra.runtime:app


FROM runtime-base AS observability
COPY services/modules/__init__.py ./services/modules/__init__.py
COPY services/modules/project_runtime ./services/modules/project_runtime
COPY services/modules/signoz ./services/modules/signoz
COPY services/modules/coolify ./services/modules/coolify
COPY services/modules/observability ./services/modules/observability
ENV ASGI_APP=modules.observability.runtime:app


FROM gateway AS final
