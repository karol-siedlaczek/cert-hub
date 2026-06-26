from flask import Flask

from cert_hub.api.helpers import filter_certs_by_type
from cert_hub.domain.cert.cert_type import CertType

app = Flask(__name__)


class _FakeCert:
    def __init__(self, cert_id: str, cert_type: CertType):
        self.id = cert_id
        self.type = cert_type


def _certs():
    return [_FakeCert("le", CertType.LETSENCRYPT), _FakeCert("st", CertType.STATIC)]


def test_filter_absent_type_returns_all():
    with app.test_request_context("/api/certs"):
        assert {c.id for c in filter_certs_by_type(_certs())} == {"le", "st"}


def test_filter_type_all_returns_all():
    # Regression: CertType was once a plain Enum, so "all" (str from the query) never
    # equalled CertType.ALL and the filter returned []. ?type=all must return everything.
    with app.test_request_context("/api/certs?type=all"):
        assert {c.id for c in filter_certs_by_type(_certs())} == {"le", "st"}


def test_filter_type_letsencrypt():
    with app.test_request_context("/api/certs?type=letsencrypt"):
        assert [c.id for c in filter_certs_by_type(_certs())] == ["le"]


def test_filter_type_static():
    with app.test_request_context("/api/certs?type=static"):
        assert [c.id for c in filter_certs_by_type(_certs())] == ["st"]
