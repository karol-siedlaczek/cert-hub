#!/usr/bin/env python3

import base64
import hmac
import hashlib
import argparse

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-k", "--hmac-key", required=True, help="TODO")
    parser.add_argument("-n", "--token-name", required=True, help="TODO")
    parser.add_argument("-v", "--token-value", required=True, help="TODO")

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    key = base64.b64decode(args.hmac_key)
    token = f"{args.token_name}.{args.token_value}".encode()
    print(hmac.new(key, token, hashlib.sha256).hexdigest())
    
    
