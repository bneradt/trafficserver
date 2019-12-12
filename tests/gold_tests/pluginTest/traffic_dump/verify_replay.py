"""
Verify that a given JSON replay file fulfills basic expectations.
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
import json
import jsonschema
import sys


def validate_json(schema_json, replay_json):
    """
    Validate the replay file against the provided schema.
    """
    try:
        jsonschema.validate(instance=replay_json, schema=schema_json)
    except jsonschema.ValidationError:
        print("The replay file does not validate against the schema.")
        return False
    else:
        return True


def verify_there_was_a_transaction(replay_json):
    """
    Verify that the replay file has a sensible looking transaction.
    """
    try:
        transactions = replay_json['sessions'][0]['transactions']
    except KeyError:
        print("The replay file did not have transactions in it.")
        return False

    if len(transactions) < 1:
        print("There are no transactions in the replay file.")
        return False
    transaction = transactions[0]
    if not ('client-request' in transaction and 'server-response' in transaction):
        print("There was not request and response in the transaction of the replay file.")
        return False

    return True


def verify_client_request_body_bytes(replay_json, expected_body_bytes):
    """
    Verify that the replay file has the specified body bytes in it.
    """
    try:
        received_body_bytes = replay_json['sessions'][0]['transactions'][0]['client-request']['content']['data']
    except KeyError:
        print("The replay file did not have a body element in the first transaction.")
        return False

    if received_body_bytes != expected_body_bytes:
        print("Expected body bytes of '{0}' but got '{1}'".format(expected_body_bytes, received_body_bytes))
        return False

    # If the client request had that many bytes, verify that the proxy-request
    # does too. This is not guaranteed to always be true, but for our autest it
    # currently holds and this check is worthwhile.
    try:
        proxy_request_body_size = replay_json['sessions'][0]['transactions'][0]['proxy-request']['content']['size']
    except KeyError:
        print("The replay file did not have a proxgy-rerquest content size element in the first transaction.")
        return False

    if int(proxy_request_body_size) != len(expected_body_bytes):
        print("Expected the proxy-request content size to be '{0}' but got '{1}'".format(
            len(expected_body_bytes), proxy_request_body_size))
        return False

    return True


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("schema_file",
                        type=argparse.FileType('r'),
                        help="The schema in which to validate the replay file.")
    parser.add_argument("replay_file",
                        type=argparse.FileType('r'),
                        help="The replay file to validate.")
    parser.add_argument("--request_body",
                        type=str,
                        help="Verify that the client request has the specified body bytes.")
    return parser.parse_args()


def main():
    args = parse_args()

    schema_json = json.load(args.schema_file)
    replay_json = json.load(args.replay_file)

    if not validate_json(schema_json, replay_json):
        return 1

    # Verifying that there is a transaction in the replay file may seem
    # unnecessary since the replay file validated against the schema. But a JSON
    # file that doesn't have conflicting entry names will pass the schema. For
    # instance, this passes against our replay schema:
    #
    # {"name": "Bob", "languages": ["English", "French"]}
    #
    # Thus we do the following sanity check to make sure that the replay file
    # appears to have some transaction in it.
    if not verify_there_was_a_transaction(replay_json):
        return 1

    if args.request_body and not verify_client_request_body_bytes(replay_json, args.request_body):
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
