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
RUN useradd -u 1000 -m -d /home/briareus briareus
# Direct uv image build: dependency layer cached above; local Briareus distribution is
# installed non-editably from the reviewed git tree, not an external wheelhouse.
COPY README.md LICENSE .python-version ./
COPY services/ ./services/
COPY scripts/ ./scripts/
RUN --mount=type=cache,target=/root/.cache/uv,sharing=shared uv sync --frozen --no-dev --no-editable --reinstall-package briareus
USER 1000:1000
EXPOSE 8000
# Each service starts its OWN Alembic coordinator. Missing DB/grants fail closed.
CMD ["/app/.venv/bin/python", "-m", "uvicorn", "projects.control_runtime:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
