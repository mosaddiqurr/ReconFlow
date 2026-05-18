from reconflow.core.validator import detect_target_type, validate_target
from reconflow.models.target import Target


def test_valid_domain_target() -> None:
    target = Target.from_value("example.com")

    assert target.value == "example.com"
    assert target.kind == "domain"
    assert detect_target_type("example.com") == "domain"
    assert validate_target("example.com") is True


def test_valid_ip_target() -> None:
    target = Target.from_value("192.0.2.10")

    assert target.kind == "ip"
    assert detect_target_type("192.0.2.10") == "ip"
    assert validate_target("192.0.2.10") is True


def test_valid_url_target() -> None:
    target = Target.from_value("https://example.com/login")

    assert target.kind == "url"
    assert detect_target_type("https://example.com/login") == "url"
    assert validate_target("https://example.com/login") is True


def test_invalid_target() -> None:
    target = Target.from_value("not a target")

    assert target.kind == "invalid"
    assert detect_target_type("not a target") == "invalid"
    assert validate_target("not a target") is False
