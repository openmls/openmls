#!/usr/bin/python3

import subprocess
import os
import atexit

import socket

owd = os.getcwd()

# For now, this is linux/unix only, assuming that binaries are in /usr/bin

# This function perform some cleanup. In particular, it removes the cloned
# mls-implementations repo and kills the interop_client.
def cleanup():
    os.chdir(owd)
    subprocess.run(['/usr/bin/killall', 'interop_client'])
    subprocess.run(['/usr/bin/rm','-rf', 'mls-implementations'])

# Register that function to be run at exit.
atexit.register(cleanup)

# Compile and run the interop client
interop_client_p = subprocess.Popen(['/usr/bin/cargo', 'run', '--release'])

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

# Wait for the process to either terminate or start listening at a port.
while sock.connect_ex(('::1',50051)) != 0 & (interop_client_p.poll() is None): ()

# If it terminated, something went wrong and we want to exit with code 1.
if interop_client_p.poll() is not None:
    print("client not running, aborting")
    exit(1)

# Clone the mls-implementations repo to build the test runner.
subprocess.run(['/usr/bin/git', 'clone', 'https://github.com/mlswg/mls-implementations.git'])

# Copy the config.json to the place where the test runner expects it.
subprocess.run(['/usr/bin/cp', 'config.json', 'mls-implementations/interop/test-runner'])

# Change into the test runner dir.
os.chdir("./mls-implementations/interop/test-runner")
# Get the required go modules
subprocess.run(['/usr/bin/go', 'get'])
# Build the test runner
subprocess.run(['/usr/bin/go', 'build'])

# Run the test runner
test_runner_output = subprocess.check_output(['./test-runner'])

# Check if it has output any errors and return a corresponding error code.
if "error" in str(test_runner_output):
    exit(1)
else:
    print(str(test_runner_output))
    exit(0)
