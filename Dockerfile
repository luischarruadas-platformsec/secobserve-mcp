# Every input is pinned: both images by digest, and the dependencies by the hashes in uv.lock. A tag or a version
# range resolved at build time would put code in the image that nobody looked at. Bump a digest together with its tag.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50 AS builder

# uv is here only to turn uv.lock into a requirements file pip can verify hash by hash.
COPY --from=ghcr.io/astral-sh/uv:0.11.18@sha256:78bc42400d77b0678ba95765305c826652ed5431f399257271dda681d0318f03 /uv /usr/local/bin/uv

WORKDIR /build

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file requirements.txt \
    && python -m pip wheel --no-cache-dir --require-hashes --wheel-dir /wheels --requirement requirements.txt \
    && python -m pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50

RUN groupadd --system secobserve \
    && useradd --system --gid secobserve --create-home secobserve

COPY --from=builder /wheels /wheels
# --no-index: everything comes from the wheels built above, so a missing one fails the build instead of being fetched.
RUN python -m pip install --no-cache-dir --no-index /wheels/* \
    && rm -rf /wheels

# The MCP Registry reads this label off the published image and refuses the release unless it equals the
# server name in server.json. It is the only ownership proof it applies to an OCI package.
LABEL io.modelcontextprotocol.server.name="io.github.nh4ttruong/secobserve-mcp"

USER secobserve
# SECOBSERVE_EXPORT_DIR defaults to a directory under the working directory, and at / that is unwritable.
WORKDIR /home/secobserve

EXPOSE 8931

ENTRYPOINT ["secobserve-mcp"]
CMD ["--transport", "http", "--host", "0.0.0.0"]
