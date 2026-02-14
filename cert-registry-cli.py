#!/usr/bin/env python3

import argparse
import requests
from functools import partial
from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum

class Action(Enum):
    VERSION = "version"
    HEALTH = "health"
    CERT = "cert"
    TOKEN = "token"
    SCOPE = "scope"
    

class CertAction(Enum):
    ISSUE = "issue"
    RENEW = "renew"
    LIST = "list"
    

class TokenAction(Enum):
    GEN_HMAC = 'generate-hmac'
    

class ScopeAction(Enum):
    LOOKUP = "lookup"


@dataclass(frozen=True)
class Client():
    base_url: str
    session: requests.Session
    timeout: int
    
    @classmethod
    def init(
        cls, 
        base_url: str, 
        token: Optional[str] = None,
        *,
        timeout: int
    ) -> None:
        base_url = base_url.rstrip("/")
        session = requests.Session()
        
        if token:
            session.headers.update({"Authorization": f"Bearer {token}"})
        
        session.headers.update({"Accept": "application/json"})
        
        return cls(base_url, session, timeout)
        
    
    def request(
        self, 
        method: str, 
        path: str, 
        *, 
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = f"{self.base_url}/{path}"
        
        response = self.session.request(
            method=method.upper(),
            url=url,
            params=params,
            json=json_body,
            timeout=self.timeout
        )
        
        return response
    
    
def print_response(response: requests.Response, format: str) -> None:
    try:
        payload = response.json()
    except ValueError:
        print(response.text)
        return
    
    print(format)
    print(payload)
    
    # todo - by specific formats
            

# Commands

def get_version(client: Client, args: argparse.Namespace) -> int:
    response = client.request("GET", "api/version")
    print_response(response, args.format)
    return 0 if response.ok else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cert-registry",
        description="CLI for cert registry application", 
        add_help=False
    )
    
    parser.add_argument("-u", "--url")
    parser.add_argument("-t", "--token")
    parser.add_argument("-f", "--format", choices=["table", "json", "yaml"], default="table")
    parser.add_argument("--timeout", type=int, default=360)
    
    sub = parser.add_subparsers(dest="action", required=True)
    
    p_version = sub.add_parser("version")
    p_version.set_defaults(func="version")
    
    # p_health = sub.add_parser("health")
    # p_health.add_argument("--cert", action="append", default=[])
    # p_health.add_argument("--exclude-ok", action="store_true")
    # p_health.set_defaults(func="health")
    
    # p_cert = sub.add_parser("cert")
    # cert_sub = p_cert.add_subparsers(dest="cert_action", required=True)
    
    # p_cert_issue = cert_sub.add_parser("issue")
    # p_cert_issue.add_argument("--cert", action="append", default=[])
    # p_cert_issue.set_defaults(func="issue")
    
    # p_cert_renew = cert_sub.add_parser("renew")
    # p_cert_renew.add_argument("--cert", action="append", default=[])
    # p_cert_renew.set_defaults(func="renew")
    
    # p_cert_list = cert_sub.add_parser("list")
    # p_cert_list.add_argument("--cert", action="append", default=[])
    # p_cert_list.set_defaults(func="list")
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(args)
    client = Client.init(args.url, args.token, timeout=args.timeout)
    
    handlers = {
        "version": partial(get_version, client)
    }
    raise SystemExit(handlers[args.func](args))
    