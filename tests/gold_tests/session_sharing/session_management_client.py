'''
'''
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

import requests
import argparse
import logging


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-p",
                        type=int,
                        help="Port to use")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    # Make three requests across two sessions.
    firstConnection = requests.Session()
    firstConnection.get(
        'http://127.0.0.1:{0}/one'.format(args.port),
        headers={'Connection': "keep-alive",
                 'Content-Length': '0'})

    secondConnection = requests.Session()
    secondConnection.get(
        'http://127.0.0.1:{0}/two'.format(args.port),
        headers={'Connection': "close",
                 'Content-Length': '0'})

    firstConnection.get(
        'http://127.0.0.1:{0}/three'.format(args.port),
        headers={'Connection': "close",
                 'Content-Length': '0'})


if __name__ == '__main__':
    main()
