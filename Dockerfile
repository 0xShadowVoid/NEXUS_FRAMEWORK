FROM python:3.11-slim

WORKDIR /nexus

# Install from packaging metadata so the image ships runtime dependencies only
# (the "dev" extra — pytest/coverage/httpx2 — is intentionally excluded). The
# whole source tree is copied first because `pip install .` builds a wheel from
# it; external security tools are installed by the operator, not bundled here.
COPY . .
RUN pip install --no-cache-dir . \
 && rm -rf build nexus_framework.egg-info

# Config + results + logs are expected to be bind-mounted (see docker-compose.yml).
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "nexus.py"]
