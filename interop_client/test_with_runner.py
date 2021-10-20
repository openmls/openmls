#!/usr/bin/python3

import subprocess
import os
import atexit

import socket

owd = os.getcwd()


# This function perform some cleanup. In particular, it removes the cloned
# mls-implementations repo and kills the interop_client.
def cleanup():
    os.chdir(owd)
    subprocess.run(['killall', 'interop_client'])
    subprocess.run(['rm', '-rf', 'mls-implementations'])


# Register that function to be run at exit.
atexit.register(cleanup)

# Compile and run the interop client, but suppress output. For now, we're only
# interested in the output of the test runner.
interop_client_p = subprocess.Popen(
    ['cargo', 'run', '--release'], stdout=subprocess.DEVNULL)

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

# Wait for the process to either terminate or start listening at a port.
while sock.connect_ex(('::1', 50051)) != 0:
    # If the compilation process or the interop client itself terminates for
    # some reason, we want to exit with code 1.
    if interop_client_p.poll() is not None:
        print("compilation failed or client has exited prematurely, aborting")
        exit(1)

# Clone the mls-implementations repo to build the test runner.
subprocess.run(
    ['git', 'clone', 'https://github.com/mlswg/mls-implementations.git'])

# Copy the config.json to the place where the test runner expects it.
subprocess.run(
    ['cp', 'config.json', 'mls-implementations/interop/test-runner'])

# Change into the test runner dir.
os.chdir("./mls-implementations/interop/test-runner")

# Increase the timeout set by the runner
subprocess.run(['sed', '-i', 's/time.Second/time.Second * 10/g', 'main.go'])

# Get the required go modules
subprocess.run(['go', 'get'])
# Build the test runner
subprocess.run(['go', 'build'])

# Run the test runner
test_runner_output = subprocess.check_output(['./test-runner'])

# Check if it has output any errors and return a corresponding error code.
if "error" in str(test_runner_output):
    exit(1)
else:
    print(str(test_runner_output))
    exit(0)
