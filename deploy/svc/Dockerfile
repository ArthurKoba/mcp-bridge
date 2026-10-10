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
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -u 1000 -m -d /home/svc svc
# Direct uv image build: dependency layer cached above; local Briareus distribution is
# installed non-editably from the reviewed git tree, not an external wheelhouse.
COPY README.md LICENSE .python-version ./
COPY services/ ./services/
COPY scripts/ ./scripts/
RUN uv sync --frozen --no-dev --no-editable
USER 1000:1000
EXPOSE 8000
CMD ["/bin/sh", "-ec", "echo BRIAREUS_SVC_UNIFIED_RUNTIME_PENDING >&2; exit 78"]
