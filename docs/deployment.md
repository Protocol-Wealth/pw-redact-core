# Deployment Guide

pw-redact runs as a stateless Docker container. It has no database, no external
dependencies at runtime, and no persistent state — making it trivial to deploy
on any container platform.

## Requirements

- **RAM:** 2GB minimum (spaCy `en_core_web_lg` loads at ~560MB)
- **CPU:** 2 shared vCPUs recommended
- **Disk:** ~1GB for Docker image (Python + spaCy model)
- **Port:** 8080 (internal, configure your platform's HTTPS termination)

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PW_REDACT_API_KEY` | Yes | — | Bearer token for API authentication. At least 32 characters; the server refuses to start, and refuses every request with 503, when it is unset, shorter, or a placeholder from these docs |
| `ENVIRONMENT` | No | `development` | `production` enables JSON logging |
| `LOG_LEVEL` | No | `info` | Logging level (debug, info, warning, error) |
| `SPACY_MODEL` | No | `en_core_web_lg` | spaCy model name (`en_core_web_md` for lighter deployments) |
| `MAX_REQUEST_SIZE_MB` | No | `1` | Maximum request body size in MB |
| `RATE_LIMIT_RPM` | No | `60` | Rate limit: requests per minute |
| `RATE_LIMIT_BURST` | No | `10` | Rate limit: max burst size |

## Docker

```bash
# Build
docker build -t pw-redact .

# Run
docker run -p 8080:8080 \
  -e PW_REDACT_API_KEY="$PW_REDACT_API_KEY" \
  -e ENVIRONMENT=production \
  pw-redact

# Verify
curl http://localhost:8080/v1/health
```

## Fly.io

```bash
# Copy template
cp fly.toml.example fly.toml
# Edit fly.toml: set app name and region

# Create app
fly apps create your-app-name --org your-org

# Set secrets
fly secrets set PW_REDACT_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
fly secrets set ENVIRONMENT=production

# Deploy
fly deploy

# Verify
curl https://your-app-name.fly.dev/v1/health
```

### Fly.io Configuration Notes

- Use `auto_stop_machines = "suspend"` to scale to zero when idle
- Use `min_machines_running = 0` if you don't need always-on
- Cold start from suspend is ~8-10 seconds (spaCy model load)
- For always-on with HA, set `min_machines_running = 2`

## Railway

```bash
# Link repo
railway link

# Set env vars
railway variables set PW_REDACT_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
railway variables set ENVIRONMENT=production

# Deploy
railway up
```

## AWS ECS / Google Cloud Run

Use the provided Dockerfile. Key settings:
- Container port: 8080
- Health check: `GET /v1/health`
- Memory: 2048 MB minimum
- CPU: 1024 units (1 vCPU) minimum

## Monitoring

### Health Check

```
GET /v1/health
```

Returns:
```json
{"status": "healthy", "version": "0.1.0", "models_loaded": true}
```

Use this for your platform's health check configuration (recommended interval: 30s).

### Response Headers

Every response includes:
- `X-Request-ID` — Unique request identifier for log correlation
- `X-Processing-Time-Ms` — Server-side processing duration

### Key Metrics to Monitor

- **Latency:** `X-Processing-Time-Ms` > 3000ms may indicate memory pressure
- **Error rate:** 413 (payload too large), 429 (rate limited), 5xx (server error)
- **Memory:** RSS > 1.8GB on a 2GB instance is a warning sign
- **Cold starts:** Track time from machine resume to first successful health check

## API Key Rotation

Generate a new key and update the secret without downtime:

```bash
# Fly.io
fly secrets set PW_REDACT_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
# Machines restart automatically with new secret

# Docker
docker run -e PW_REDACT_API_KEY="$NEW_PW_REDACT_API_KEY" ...
```

Update the key in all consumers simultaneously,
or implement a brief dual-key period by deploying a custom auth middleware.

## Scaling

pw-redact is stateless and horizontally scalable:
- **Fly.io:** Increase `min_machines_running` or let auto-scaling handle it
- **ECS:** Increase desired task count
- **Cloud Run:** Set min/max instances

Each instance handles ~10 concurrent requests with 2 uvicorn workers.
For higher throughput, scale instances rather than increasing workers per instance
(spaCy's memory footprint is per-worker).

## Lighter Deployments

If 2GB RAM is too much for your use case:

1. Switch to `en_core_web_md` (~40MB vs ~560MB):
   ```bash
   fly secrets set SPACY_MODEL=en_core_web_md
   ```
   Trade-off: Slightly less accurate name detection. Regex patterns are unaffected.

2. Reduce to 1GB RAM with `en_core_web_md`

3. For regex-only mode (no NLP), you can import `PWRedactor` and override the
   analyzer initialization — but this is not yet a supported configuration.
