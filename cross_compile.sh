#!/bin/bash

echo "This is a temporary solution that bears inconsistent results, in the future switch to on machine building or some other solution."

docker build --progress=quiet -f Dockerfile.amd64-linux-static -t amd64-linux-static-builder --output type=local,dest=./cross_build . &

docker build --progress=quiet -f Dockerfile.amd64-linux -t amd64-linux-builder --output type=local,dest=./cross_build . &
docker build --progress=quiet -f Dockerfile.arm64-linux -t arm64-linux-builder --output type=local,dest=./cross_build . $
wait
