#!/usr/bin/env python3
"""
Test script to understand the NodeZero MCP server protocol.
"""

import json
import subprocess
import sys

def test_mcp_server():
    """Test basic MCP server functionality."""
    try:
        process = subprocess.Popen([
            'docker', 'run', '--pull', 'always', '-i', '--rm',
            '-e', 'H3_API_KEY=MToxNmNkNGI5NS0zMmEzLTQ5MjgtYmQwOC1jZTUxMGQ1YzJiYmU6RzlEdmhGOTlFQ052RTgvdXVLbStZcWRETTdLd3cvbzM4NldubUQ1bFF2Ymk3LzY2',
            'horizon3ai/h3-mcp-server:latest'
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Test 1: Initialize request
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {
                        "listChanged": True
                    },
                    "sampling": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }

        print("Sending initialize request...")
        process.stdin.write(json.dumps(init_request) + "\n")
        process.stdin.flush()

        # Read response
        response = process.stdout.readline()
        if response:
            print(f"Initialize response: {response.strip()}")
            init_response = json.loads(response.strip())
        else:
            print("No initialize response received")
            return

        # Test 2: Get tools list
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }

        print("\nSending tools/list request...")
        process.stdin.write(json.dumps(tools_request) + "\n")
        process.stdin.flush()

        response = process.stdout.readline()
        if response:
            print(f"Tools response: {response.strip()}")
            tools_response = json.loads(response.strip())

            if "result" in tools_response and "tools" in tools_response["result"]:
                tools = tools_response["result"]["tools"]
                print(f"\nAvailable tools ({len(tools)}):")
                for tool in tools:
                    print(f"  - {tool.get('name', 'unknown')}: {tool.get('description', 'No description')}")
        else:
            print("No tools response received")

        process.terminate()
        process.wait()

    except Exception as e:
        print(f"Error: {e}")
        if process:
            process.terminate()

if __name__ == "__main__":
    test_mcp_server()