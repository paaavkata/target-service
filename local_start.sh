#!/bin/bash
# local_start.sh — target-service local development runner.
# Do NOT commit real credentials. Use a gitignored .secrets file:
#   export $(grep -v '^#' .secrets | xargs)

set -e

export ENV=local
export APP_PORT=8080
export HOST=127.0.0.1
export LOG_LEVEL=debug
export LOG_FORMAT=json
export APP_ID=scantinel

# Database — update user/password/host for your local PG instance.
export DB_URI='postgresql://target-service-user:changeme@127.0.0.1:5432/scantinel?sslmode=disable'

# Kafka
export KAFKA_BOOTSTRAP_SERVER=localhost:9092
export KAFKA_CLIENT_ID=target-service

# Generate Swagger docs.
swag init -g main.go \
  -d cmd/target-service,internal/handler,internal/model \
  -o cmd/target-service/docs

# Run the service.
go run cmd/target-service/main.go
