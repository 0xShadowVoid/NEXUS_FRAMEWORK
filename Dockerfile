FROM python:3.11-slim

WORKDIR /nexus

# Runtime dependencies only; external security tools are installed by the operator.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Config + results + logs are expected to be bind-mounted (see docker-compose.yml).
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "nexus.py"]
