from cert_hub.api.helpers import render_metrics


def test_render_metrics_emits_families_and_values():
    records = [
        {"id": "a", "type": "letsencrypt", "status": "OK", "expiry_ts": 1800000000, "days_to_expire": 40},
        {"id": "b", "type": "static", "status": "CERT_MISSING", "expiry_ts": None, "days_to_expire": None},
    ]
    out = render_metrics(records, {"version": "1.2.3", "git_sha": "abc123"})

    assert 'certhub_build_info{version="1.2.3",git_sha="abc123"} 1' in out
    assert 'certhub_cert_expiry_timestamp_seconds{id="a",type="letsencrypt"} 1800000000' in out
    assert 'certhub_cert_days_to_expire{id="a",type="letsencrypt"} 40' in out
    assert 'certhub_cert_status{id="a",type="letsencrypt",status="OK"} 1' in out
    assert 'certhub_cert_status{id="b",type="static",status="CERT_MISSING"} 1' in out
    # b has no expiry/days metrics
    assert 'certhub_cert_expiry_timestamp_seconds{id="b"' not in out
    assert 'certhub_cert_days_to_expire{id="b"' not in out
    assert "# TYPE certhub_cert_status gauge" in out
    assert out.endswith("\n")


def test_render_metrics_escapes_label_values():
    records = [{"id": 'a"x', "type": "static", "status": "OK", "expiry_ts": None, "days_to_expire": None}]
    out = render_metrics(records, {"version": "v", "git_sha": "s"})
    assert 'id="a\\"x"' in out
