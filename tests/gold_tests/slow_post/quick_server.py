#!/usr/bin/env python3
"""A server that replies without waiting for the entire request."""

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
import ssl
import sys
import time


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "address",
        help="Address to listen on")
    parser.add_argument(
        "port",
        type=int,
        default=8080,
        help="The port to listen on")
    parser.add_argument(
        "cert",
        help="The certificate to use")
    parser.add_argument(
        "private_key",
        help="The key to use")

    return parser.parse_args()


def wait_for_headers_complete(sock: socket.socket) -> bytes:
    """Wait for the headers to be complete.

    :param sock: The socket to read from.
    :returns: The bytes read off the socket.
    """
    headers = b""
    while True:
        data = sock.recv(1024)
        print(f'Received:\n{data}')
        headers += data
        if b"\r\n\r\n" in data:
            break
    return headers


def calculate_num_outstanding_bytes(read_bytes: bytes) -> int:
    """Determine how many more bytes to read.

    This parses the Content-Length header to determine how many more bytes to
    read.

    :param read_bytes: The bytes read so far.
    :returns: The number of bytes to read, or -1 if it is chunked encoded.
    """
    headers = read_bytes.decode("utf-8").split("\r\n")
    content_length_value = None
    for header in headers:
        if header.lower().startswith("content-length:"):
            content_length_value = int(header.split(":")[1])
        elif header.lower().startswith("transfer-encoding: chunked"):
            return -1
    if content_length_value is None:
        raise ValueError("No Content-Length header found.")

    end_of_headers = read_bytes.find(b"\r\n\r\n")
    if end_of_headers == -1:
        raise ValueError("No end of headers found.")

    end_of_headers += 4
    return content_length_value - (len(read_bytes) - end_of_headers)


def send_response(sock: socket.socket) -> None:
    """Send an HTTP response.

    :param sock: The socket to write to.
    """
    response = (
        r"HTTP/1.1 200 OK\r\n"
        r"Content-Length: 0\r\n"
        r"\r\n"
    )
    print(f'Sending:\n{response}')
    sock.sendall(response.encode("utf-8"))


def drain_socket(
        sock: socket.socket,
        previously_read_data: bytes,
        num_bytes_to_drain: int) -> None:
    """Read the rest of the request.

    :param sock: The socket to drain.
    :param num_bytes_to_drain: The number of bytes to drain.
    """

    read_data = previously_read_data
    num_bytes_drained = 0
    while True:
        if num_bytes_to_drain > 0:
            if num_bytes_drained >= num_bytes_to_drain:
                break
        elif b'0\r\n\r\n' == read_data[-5:]:
            print("Found end of chunked data.")
            break

        data = sock.recv(1024)
        print(f'Received:\n{data}')
        if not data:
            print("Socket closed.")
            break
        num_bytes_drained += len(data)
        read_data += data


def main() -> int:
    """Run the server."""
    args = parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.private_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((args.address, args.port))
        sock.listen(5)
        print(f"Listening on {args.address}:{args.port}")
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, _ = ssock.accept()
            read_bytes = wait_for_headers_complete(conn)
            send_response(conn)

            num_bytes_to_drain = calculate_num_outstanding_bytes(read_bytes)
            print(f'Read {len(read_bytes)} bytes. '
                  f'Draining {num_bytes_to_drain} bytes.')
            #drain_socket(conn, read_bytes, num_bytes_to_drain)

    return 0


if __name__ == "__main__":
    sys.exit(main())
