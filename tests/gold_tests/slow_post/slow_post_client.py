#!/usr/bin/env python3

"""Implement a client that sends request bodies slowly.

The number of requests and the timing of sending the body is configurable.
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

from typing import Generator
import time
import threading
import requests
import argparse


def gen(slow_time: int) -> Generator:
    """Generate a string that takes slow_time seconds to generate."""
    for _ in range(slow_time):
        yield b'a'
        time.sleep(1)


def slow_post(port: int, slow_time: int) -> None:
    """Slowly send a request to the specified port.

    This sends a request to the local listening port that takes slow_time
    seconds to send the body.

    :param port: The localhost port to send the request to.
    :param slow_time: The number of seconds to take to send the body.
    """
    requests.post(f'http://127.0.0.1:{port}/', data=gen(slow_time))


def makerequest(port: int, connection_limit: int) -> None:
    """Concurrently send requests on the specified port.

    :param port: The localhost port to send the request to.
    :param connection_limit: The number of concurrent requests to send.
    """
    client_timeout = 3
    for _ in range(connection_limit):
        t = threading.Thread(
            target=slow_post,
            daemon=True,
            args=(port, client_timeout + 10))
        t.start()
    time.sleep(1)
    r = requests.get(f'http://127.0.0.1:{port}/')
    print(r.status_code)


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", "-p",
                        type=int,
                        help="Port to use")
    parser.add_argument("--connectionlimit", "-c",
                        type=int,
                        help="connection limit")
    return parser.parse_args()


def main() -> None:
    """Run the client."""
    args = parse_args()
    makerequest(args.port, args.connectionlimit)


if __name__ == '__main__':
    main()
