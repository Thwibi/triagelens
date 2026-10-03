# TriageLens production image.
#
# Stage 1 builds the frontend with Node; stage 2 installs the Python app from a
# hashed lockfile and serves everything from one process on port 8787.

# ---------------------------------------------------------------- frontend ---
FROM node:lts AS frontend

WORKDIR /build
# Copy manifests first so the dependency layer caches independently of sources.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# The build writes into the backend package's static directory.
COPY backend/ /build/backend/
RUN npm run build


# ----------------------------------------------------------------- backend ---
FROM python:3.12-slim AS runtime

ARG WITH_PDF=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TRIAGELENS_DATA_DIR=/data \
    TRIAGELENS_SERVER__PORT=8787

# WeasyPrint needs pango and cairo; libxml2/lxml needs libxslt. curl is only for
# the healthcheck below. Debian ships these as lib*-prefixed packages: "pango" and
# "cairo" are not package names and apt fails to locate them.
#
# WITH_PDF=1 installs the system libraries only. WeasyPrint itself is not a Phase 0
# dependency, so /api/health still reports pdf_available=false and the report
# endpoint answers 422 PDF_UNAVAILABLE until it is added. Reporting arrives in a
# later phase (spec 11).
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        libxml2 libxslt1.1 curl \
    && if [ "${WITH_PDF}" = "1" ]; then \
         apt-get install --yes --no-install-recommends \
            libpango-1.0-0 libcairo2 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0; \
       fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The lockfile is the authority on what may be installed: --require-hashes refuses
# anything whose bytes do not match, and --only-binary keeps pip from reaching for
# an sdist that the lockfile does not pin.
COPY backend/pyproject.toml backend/requirements.lock ./
RUN python -m pip install --upgrade pip \
    && python -m pip install --require-hashes --only-binary=:all: --no-deps \
        -r requirements.lock

COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/data ./data
COPY backend/rules ./rules
COPY backend/README.md ./
# The built frontend replaces any placeholder and ships as the SPA.
COPY --from=frontend /build/backend/app/static ./app/static

# Run unprivileged: the API only ever writes under the data directory.
RUN useradd --create-home --uid 10001 triagelens \
    && mkdir -p /data \
    && chown -R triagelens:triagelens /data /app
USER triagelens

EXPOSE 8787
VOLUME ["/data"]

# The image binds 0.0.0.0 so a published port can reach it; a process listening
# only on the container's loopback is invisible to `docker -p`. The app refuses
# any non-loopback bind without an auth token, and no default is baked in here on
# purpose: a token shipped in the image would be public knowledge. Supply one:
#
#   docker run -p 127.0.0.1:8787:8787 -e TRIAGELENS_SERVER__AUTH_TOKEN=... triagelens:local
#
# Omitting it makes the container exit with the configuration error rather than
# serving the API unprotected.
ENV TRIAGELENS_SERVER__HOST=0.0.0.0

# Shell form so the token expands from the container environment at run time.
# /api/health sits behind the same bearer auth as every other route, so an
# unauthenticated probe returns 401 and --fail would mark a working container
# unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent \
        -H "Authorization: Bearer ${TRIAGELENS_SERVER__AUTH_TOKEN}" \
        http://127.0.0.1:8787/api/health || exit 1

# ENTRYPOINT, not CMD: `python -m app.main` has to resolve, so form matters when
# extra arguments are appended.
ENTRYPOINT ["python", "-m", "app.main"]