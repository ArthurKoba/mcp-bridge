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
RUN uv sync --frozen --no-dev --no-install-project
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
# PACKAGING-V1: dependency layer only; Briareus installed ONLY from reviewed immutable wheel.
COPY deploy/install_wheel_release.py /app/install_wheel_release.py
COPY deploy/terminal/wheel-pin.json /app/wheel-pin.json
# BUILD BLOCKED on actual immutable wheel artifact delivery into this context.
# No source overlay / ad hoc wheel build / network download / version fallback.
COPY deploy/wheel_artifacts/ /app/wheel_artifacts/
RUN python /app/install_wheel_release.py --pin /app/wheel-pin.json --wheel-directory /app/wheel_artifacts --python /app/.venv/bin/python \
    && rm -rf /app/wheel_artifacts /app/install_wheel_release.py
USER 1000:1000
EXPOSE 8000
CMD ["/app/.venv/bin/python", "-m", "common.asgi"]
