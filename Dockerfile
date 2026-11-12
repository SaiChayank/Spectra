# Build the wheel first:  scripts/build_release.sh   (the image installs that wheel; nothing else from the repo)
# Base pinned by digest (python:3.13-slim, pulled 2026-11-07); bump deliberately.
FROM python:3.13-slim@sha256:09a17cad02668ae61ece136b4fd36ac3849e14f670ebedb637ea3e15580525bc

ARG WHEEL=backend/dist/spectra-1.0.0-py3-none-any.whl
# EXTRAS="[live]" adds scapy (GPL-2.0-only) for live NIC capture: only the compose `capture` service builds that variant (ADR-011).
ARG EXTRAS=""
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    HOME=/home/spectra SPECTRA_DATA_DIR=/data SPECTRA_MODEL_PATH=/data/models/model.joblib

# Pull in Debian security fixes newer than the pinned base (zlib1g CVE-2026-76844 / -85091, trivy 2026-11-08); drop once the base catches up.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home --home-dir /home/spectra --uid 10001 spectra \
 && mkdir -p /data/models && chown -R spectra:spectra /data
COPY ${WHEEL} backend/requirements.lock /tmp/
# Constrain to the audited lockfile versions (hash lines stripped: the lock also lists dev tools we do not install).
# setuptools/wheel/pip are not needed at runtime; their vendored copies of msgpack/urllib3 carried HIGH CVEs (trivy, 2026-11-07).
RUN grep -E '^[A-Za-z0-9_.-]+==' /tmp/requirements.lock | sed 's/ *\\$//' > /tmp/constraints.txt \
 && W=$(ls /tmp/*.whl) && pip install -c /tmp/constraints.txt "spectra${EXTRAS} @ file://${W}" \
 && pip uninstall -y setuptools wheel && python -m pip --version >/dev/null && python -m pip uninstall -y pip \
 && rm -f /tmp/*.whl /tmp/requirements.lock /tmp/constraints.txt

USER 10001
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=4).status==200 else 1)"
ENTRYPOINT ["spectra"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
