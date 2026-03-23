FROM python:3.13-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1001 app && useradd -u 1001 -g app -s /bin/bash -m app

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY schema.sql model.conf ./

RUN pip install --no-cache-dir "."

# Bundle auth policy for initial bootstrap (injected at build time)
ARG AUTH_YAML_CONTENT=""
RUN if [ -n "$AUTH_YAML_CONTENT" ]; then printf '%s' "$AUTH_YAML_CONTENT" > /app/acl.yaml; fi

RUN mkdir -p /data && chown -R app:app /app /data

USER app

ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DB_PATH=/data/auth.db \
    ACL_YAML_PATH=/app/acl.yaml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["cassandra-auth"]
