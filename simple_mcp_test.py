#!/usr/bin/env python3
"""
Simple MCP test script using proper protocol.
"""

import json
import subprocess
import threading
import time
import sys

def read_output(process, output_list):
    """Read output from process in a separate thread."""
    try:
        while process.poll() is None:
            line = process.stdout.readline()
            if line:
                output_list.append(line.strip())
    except:
        pass

def test_mcp():
    """Test MCP server with proper protocol."""
    process = subprocess.Popen([
        'docker', 'run', '--pull', 'always', '-i', '--rm',
        '-e', 'H3_API_KEY=MToxNmNkNGI5NS0zMmEzLTQ5MjgtYmQwOC1jZTUxMGQ1YzJiYmU6RzlEdmhGOTlFQ052RTgvdXVLbStZcWRETTdLd3cvbzM4NldubUQ1bFF2Ymk3LzY2',
        'horizon3ai/h3-mcp-server:latest'
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=0)

    output_lines = []
    error_lines = []

    # Start output reader threads
    output_thread = threading.Thread(target=read_output, args=(process, output_lines))
    output_thread.daemon = True
    output_thread.start()

    def read_stderr():
        try:
            while process.poll() is None:
                line = process.stderr.readline()
                if line:
                    error_lines.append(line.strip())
        except:
            pass

    error_thread = threading.Thread(target=read_stderr)
    error_thread.daemon = True
    error_thread.start()

    # Wait for server to start
    time.sleep(3)

    print("Server startup messages:")
    for line in error_lines[-10:]:  # Show last 10 error lines (server startup info)
        print(f"  {line}")

    # Send initialize request
    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }

    print(f"\nSending: {json.dumps(init_request)}")
    process.stdin.write(json.dumps(init_request) + "\n")
    process.stdin.flush()

    # Wait for response
    time.sleep(2)

    print(f"\nReceived {len(output_lines)} output lines:")
    for line in output_lines:
        print(f"  {line}")

    # Send tools/list request
    if output_lines:  # If we got a response to initialize
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }

        print(f"\nSending: {json.dumps(tools_request)}")
        process.stdin.write(json.dumps(tools_request) + "\n")
        process.stdin.flush()

        time.sleep(2)

        print(f"\nAfter tools request, total output lines: {len(output_lines)}")
        for line in output_lines[-5:]:  # Show last 5 lines
            print(f"  {line}")

    process.terminate()
    process.wait()

if __name__ == "__main__":
    test_mcp()