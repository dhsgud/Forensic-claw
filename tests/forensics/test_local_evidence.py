from hypothesis import given
from hypothesis import strategies as st

from forensic_claw.forensics.trust import is_local_endpoint


@given(
    st.sampled_from(
        ["http://127.0.0.1:8080/v1", "http://localhost:8000/v1", "http://[::1]:1234/v1"]
    )
)
def test_evidence_endpoint_accepts_loopback_addresses(url):
    assert is_local_endpoint(url)


@given(
    st.sampled_from(
        [
            "https://example.org/v1",
            "http://localhost.example.org",
            "http://192.168.1.1/v1",
            "file:///tmp/api",
            "http://localhost@evil.example",
        ]
    )
)
def test_evidence_endpoint_rejects_non_loopback_destinations(url):
    assert not is_local_endpoint(url)
