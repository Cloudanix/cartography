#!/bin/bash
set -e

# Unit Tests
echo "Running Unit Tests"
ALL_PROXY="" all_proxy="" .venv/bin/pytest tests/unit
echo "Unit Tests Passed"

# Integration Tests (requires Docker)
echo "Running Integration Tests"
CONTAINER=neo4j-test

docker rm -f "$CONTAINER" 2>/dev/null || true

docker run -d \
  --name "$CONTAINER" \
  -p 7687:7687 \
  -e NEO4J_AUTH=none \
  -e NEO4J_PLUGINS='["apoc"]' \
  neo4j:2026-community

echo "Waiting for Neo4j to start..."
until docker exec "$CONTAINER" cypher-shell -u neo4j -p '' 'RETURN 1' &>/dev/null; do
  sleep 3
done
echo "Neo4j ready."

NEO4J_URL=bolt://localhost:7687 ALL_PROXY="" all_proxy="" .venv/bin/pytest tests/integration
echo "Integration Tests Passed"

docker rm -f "$CONTAINER"
echo "Container Removed"
