FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv,sharing=shared uv sync --frozen --no-dev --no-install-project
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential sed git git-lfs gh openssh-client wget ripgrep findutils patch diffutils rsync jq \
        tar zip unzip gzip bzip2 xz-utils make gcc g++ binutils cmake ninja-build pkg-config \
        ccache autoconf automake libtool python3-venv bc bison flex gawk gettext cpio file perl which libncurses-dev \
        procps psmisc lsof strace gdb iproute2 socat netcat-openbsd picocom python3-serial \
    && rm -rf /var/lib/apt/lists/*
ENV ASGI_APP=modules.terminal.runtime:app \
    HOME=/home/agent
RUN useradd -u 1000 -m -d /home/agent agent \
    && mkdir -p /workspace \
    && chown -R 1000:1000 /workspace /home/agent
# Direct uv image build: dependency layer cached above; local Briareus distribution is
# installed non-editably from the reviewed git tree, not an external wheelhouse.
COPY README.md LICENSE .python-version ./
COPY services/ ./services/
COPY scripts/ ./scripts/
RUN --mount=type=cache,target=/root/.cache/uv,sharing=shared uv sync --frozen --no-dev --no-editable
USER 1000:1000
EXPOSE 8000
CMD ["/app/.venv/bin/python", "-m", "common.asgi"]
