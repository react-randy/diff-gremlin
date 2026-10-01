# Official multiarch image indexes verified on 2026-10-01. See docs/toolchain.md.
FROM node:22.23.1-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS node-tools
WORKDIR /opt/gremlin/node
COPY toolchain/node/package*.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

FROM eclipse-temurin:25.0.4.1_1-jdk-noble@sha256:f6366ccac38ceae180280ad7012d18a15e8031548a430dc2bae06631d9e88ed0 AS jdk
FROM ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc AS uv

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS system
COPY toolchain/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git libstdc++6 zlib1g passwd \
    && rm -rf /var/lib/apt/lists/*

FROM system AS package
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY toolchain/python/ /requirements/
RUN uv venv /build-env \
    && uv pip install --python /build-env/bin/python --require-hashes --only-binary :all: -r /requirements/build-requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN uv build --wheel --no-build-isolation --python /build-env/bin/python --out-dir /wheels
RUN uv venv /opt/gremlin/python \
    && uv pip install --python /opt/gremlin/python/bin/python --require-hashes --only-binary :all: -r /requirements/full-requirements.txt \
    && uv pip install --python /opt/gremlin/python/bin/python --no-deps /wheels/*.whl
COPY scripts/download_asset.py /download_asset.py
COPY scripts/provision_gitleaks.py /provision_gitleaks.py
RUN python -I /provision_gitleaks.py /opt/gremlin/bin
COPY scripts/provision_shfmt.py /provision_shfmt.py
RUN python -I /provision_shfmt.py /opt/gremlin/bin

FROM system AS runtime
LABEL org.opencontainers.image.title="Diff Gremlin" \
      org.opencontainers.image.description="Static risk checks with findings, coverage, and receipts" \
      org.opencontainers.image.source="https://github.com/react-randy/diff-gremlin" \
      org.opencontainers.image.licenses="MIT"
COPY --from=package /opt/gremlin/ /opt/gremlin/
COPY --from=node-tools /opt/gremlin/node/ /opt/gremlin/node/
COPY --from=node-tools /usr/local/bin/node /opt/gremlin/node-bin/node
COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
ENV PATH="/opt/gremlin/python/bin:/opt/gremlin/node-bin:/opt/java/openjdk/bin:/usr/local/bin:/usr/bin:/bin" \
    DIFF_GREMLIN_TOOL_PATH="/opt/gremlin/node/node_modules/.bin:/opt/gremlin/node-bin:/opt/java/openjdk/bin:/opt/gremlin/bin" \
    HOME="/tmp" \
    PYTHONDONTWRITEBYTECODE="1"
RUN /usr/sbin/groupadd --gid 10001 gremlin \
    && /usr/sbin/useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin gremlin \
    && mkdir /workspace
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/opt/gremlin/python/bin/diff-gremlin"]
CMD ["--help"]
