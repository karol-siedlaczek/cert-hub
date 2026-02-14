#!/usr/bin/env python3

import base64
import hmac
import hashlib
import argparse

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-H", "--hmac-key-b64", required=True, help="TODO")
    parser.add_argument("-k", "--token-key", required=True, help="TODO")
    parser.add_argument("-v", "--token-value", required=True, help="TODO")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    key = base64.b64decode(args.hmac_key_b64)
    token = str(args.token_value).encode()
    hmac_key = hmac.new(key, token, hashlib.sha256)
    print(f"TOKEN_{str(args.token_key).upper()}_HMAC={hmac_key.hexdigest()}")
    
    
