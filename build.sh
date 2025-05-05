#!/bin/bash

docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -t xhunt3rx/altcha-lite:latest \
    --push \
    .
