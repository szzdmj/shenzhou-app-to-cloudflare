#!/usr/bin/env bash
set -e

IMAGE_NAME="ghcr.io/szzdmj/shenzhou-app:latest"

echo "🔄 Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" -f static-build.Dockerfile .

echo "🚀 Pushing to GitHub Container Registry"
docker push "$IMAGE_NAME"

echo "🧼 Stopping old container if exists..."
docker stop running_shenzhou 2>/dev/null || true
docker rm running_shenzhou 2>/dev/null || true

echo "🟢 Starting a new container..."
docker run -d --name running_shenzhou -p 80:80 -p 443:443 "$IMAGE_NAME"
