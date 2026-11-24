#!/usr/bin/env bash
echo "Stopping Redis Cluster containers..."
docker rm -f redis-7000 redis-7001 redis-7002 2>/dev/null || true
