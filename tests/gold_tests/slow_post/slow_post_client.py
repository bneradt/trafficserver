#!/usr/bin/env python3
"""Implements a client which slowly POSTs a request."""

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

import argparse
import requests
import sys
import threading
import time


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "port",
        type=int,
        help="The port to which to connect.")
    parser.add_argument(
        "-t", "--send_time",
        type=int,
        default=3,
        help="The number of seconds to send the POST.")

    return parser.parse_args()


def gen(slow_time: int) -> Generator:
    """Slowly generate the content for the body of a request.

    :param slow_time: The number of seconds to take to generate the content.
    """
    for _ in range(slow_time):
        yield b'a'
        time.sleep(1)


def slow_post(port: int, slow_time: int) -> None:
    """Slowly POST a request.

    :param port: The port to which to connect.
    :param slow_time: The number of seconds to take to generate the content.
    """
    r = requests.post(f'http://127.0.0.1:{port}/', data=gen(slow_time))
    print(r.status_code)


def main():
    """Run the client."""
    args = parse_args()
    slow_post(args.port, args.send_time)
    return 0


if __name__ == '__main__':
    sys.exit(main())
