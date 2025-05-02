#!/bin/bash

echo "This is a temporary solution that bears inconsistent results, in the future switch to on machine building or some other solution."

docker build --progress=plain -f Dockerfile.amd64-linux-static -t amd64-linux-static-builder --output type=local,dest=./cross_build . && echo "amd64-linux-static finished" &

# docker build --progress=plain -f Dockerfile.amd64-linux -t amd64-linux-builder --output type=local,dest=./cross_build . && echo "amd64-linux finished" &
# docker build -f Dockerfile.arm64-linux -t arm64-linux-builder --output type=local,dest=./cross_build . && echo "arm64-linux finished" &
wait
