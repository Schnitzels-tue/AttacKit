#!/bin/bash

# Function to check if a process has completed and its exit status
check_status() {
    pid=$1
    process_name=$2
    log_file=$3

    if kill -0 $pid 2>/dev/null; then
        echo "$process_name: compiling"
    else
        wait $pid    # Wait for the process to finish and capture the exit code
        exit_code=$? # Capture the exit status of the process

        if [ $exit_code -eq 0 ]; then
            echo "$process_name: ✅ Completed"
        else
            echo "$process_name: ❌ Failed (Exit Code: $exit_code)"
            echo "----- $process_name Build Logs -----"
            cat "$log_file" # Display the log file of the failed build
            echo "--------------------------"
        fi
    fi
}

echo "This is a temporary solution that bears inconsistent results, in the future switch to on-machine building or some other solution."

mkdir cross_build

# Start the Docker build processes in the background and redirect logs
docker build --progress=quiet -f Dockerfile.amd64-linux-static -t amd64-linux-static-builder --output type=local,dest=./cross_build . >cross_build/amd64-linux-static-build.log 2>&1 &
pid1=$!
docker build --progress=quiet -f Dockerfile.amd64-linux -t amd64-linux-builder --output type=local,dest=./cross_build . >cross_build/amd64-linux-build.log 2>&1 &
pid2=$!
docker build --progress=quiet -f Dockerfile.arm64-linux -t arm64-linux-builder --output type=local,dest=./cross_build . >cross_build/arm64-linux-build.log 2>&1 &
pid3=$!

# Loop to check status
while kill -0 $pid1 2>/dev/null || kill -0 $pid2 2>/dev/null || kill -0 $pid3 2>/dev/null; do
    clear
    # Check the status of each build process
    check_status $pid1 "amd64-linux-static" "cross_build/amd64-linux-static-build.log"
    check_status $pid2 "amd64-linux" "cross_build/amd64-linux-build.log"
    check_status $pid3 "arm64-linux" "cross_build/arm64-linux-build.log"

    sleep 1 # Adjust sleep time as needed
done

# Final status check after all builds are complete
clear
check_status $pid1 "amd64-linux-static" "cross_build/amd64-linux-static-build.log"
check_status $pid2 "amd64-linux" "cross_build/amd64-linux-build.log"
check_status $pid3 "arm64-linux" "cross_build/arm64-linux-build.log"

echo "cleaning up..."
rm cross_build/*.log
