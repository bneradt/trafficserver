#!/usr/bin/env python3
"""A server that sends chunked responses with delays between chunks.

This is used to test that transform plugins correctly receive all chunks
of a chunked response when they arrive in separate TCP segments.
"""

#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse
import socket
import sys
import time


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    :returns: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="Address to listen on.")
    parser.add_argument("port", type=int, help="The port to listen on.")
    parser.add_argument("--chunk-delay", type=float, default=0.1, help="Delay in seconds between sending chunks.")
    return parser.parse_args()


def get_listening_socket(address: str, port: int) -> socket.socket:
    """Create a listening socket.

    :param address: The address to listen on.
    :param port: The port to listen on.
    :returns: A listening socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Disable Nagle's algorithm to ensure chunks are sent immediately.
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.bind((address, port))
    sock.listen(1)
    return sock


def accept_connection(sock: socket.socket) -> socket.socket:
    """Accept a connection.

    :param sock: The socket to accept a connection on.
    :returns: The accepted socket.
    """
    client_sock, addr = sock.accept()
    # Disable Nagle's algorithm on the client socket as well.
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return client_sock


def receive_request(sock: socket.socket) -> bytes:
    """Receive a complete HTTP request.

    :param sock: The socket to read from.
    :returns: The received request bytes.
    """
    request = b""
    while b"\r\n\r\n" not in request:
        data = sock.recv(4096)
        if not data:
            break
        request += data
        print(f"Received request data: {data}")
    return request


def send_chunked_response(sock: socket.socket, chunk_delay: float) -> None:
    """Send a chunked HTTP response with delays between chunks.

    The response body consists of multiple chunks sent with delays between
    them to ensure they arrive as separate TCP segments.

    :param sock: The socket to send the response on.
    :param chunk_delay: Delay in seconds between sending chunks.
    """
    # Define the chunks we'll send. Each chunk has content that we can verify
    # on the client side.
    chunks = [
        b"CHUNK_ONE_DATA_",
        b"CHUNK_TWO_DATA_",
        b"CHUNK_THREE_END",
    ]

    # Send the response headers.
    headers = (b"HTTP/1.1 200 OK\r\n"
               b"Transfer-Encoding: chunked\r\n"
               b"Content-Type: text/plain\r\n"
               b"\r\n")
    print(f"Sending headers: {headers}")
    sock.sendall(headers)

    # Send each chunk with a delay between them.
    for i, chunk_data in enumerate(chunks):
        # Wait before sending to ensure chunks arrive separately.
        time.sleep(chunk_delay)

        # Format the chunk: size in hex, CRLF, data, CRLF.
        chunk_size = len(chunk_data)
        formatted_chunk = f"{chunk_size:x}\r\n".encode() + chunk_data + b"\r\n"
        print(f"Sending chunk {i + 1}/{len(chunks)}: {formatted_chunk}")
        sock.sendall(formatted_chunk)

    # Wait before sending the final chunk.
    time.sleep(chunk_delay)

    # Send the final zero-length chunk to end the response.
    final_chunk = b"0\r\n\r\n"
    print(f"Sending final chunk: {final_chunk}")
    sock.sendall(final_chunk)
    print("Response complete.")


def handle_connection(sock: socket.socket, chunk_delay: float) -> bool:
    """Handle a single client connection.

    :param sock: The client socket.
    :param chunk_delay: Delay in seconds between sending chunks.
    :returns: True if the request was handled successfully.
    """
    request = receive_request(sock)
    if not request:
        print("No request received.")
        return False

    print(f"Received complete request:\n{request.decode('utf-8', errors='replace')}")

    send_chunked_response(sock, chunk_delay)
    return True


def run_server(address: str, port: int, chunk_delay: float) -> int:
    """Run the server.

    :param address: The address to listen on.
    :param port: The port to listen on.
    :param chunk_delay: Delay in seconds between sending chunks.
    :returns: 0 on success, 1 on failure.
    """
    try:
        with get_listening_socket(address, port) as listening_sock:
            print(f"Listening on {address}:{port}")

            # Handle connections until we successfully serve one request.
            while True:
                print("Waiting for a connection...")
                with accept_connection(listening_sock) as client_sock:
                    # Set a timeout to avoid hanging forever.
                    client_sock.settimeout(10.0)
                    try:
                        if handle_connection(client_sock, chunk_delay):
                            print("Successfully handled request.")
                            return 0
                    except socket.timeout:
                        print("Connection timed out, trying again...")
                    except Exception as e:
                        print(f"Error handling connection: {e}")
    except KeyboardInterrupt:
        print("Interrupted.")
    except Exception as e:
        print(f"Server error: {e}")
        return 1

    return 0


def main() -> int:
    """Entry point."""
    args = parse_args()
    return run_server(args.address, args.port, args.chunk_delay)


if __name__ == "__main__":
    sys.exit(main())
