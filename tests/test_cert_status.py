from cert_hub.domain.cert.cert_status import CertStatus


def test_new_static_statuses_exist_with_matching_values():
    for name in ("CERT_MISSING", "KEY_MISSING", "CHAIN_MISSING", "INVALID_CERT_FILE", "NOT_SUPPORTED"):
        member = CertStatus[name]
        assert member.value == name
