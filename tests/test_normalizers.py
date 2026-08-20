from __future__ import annotations

from aitlds_detection.normalizers import normalize_apache, normalize_auth


def test_apache_combined_log_normalization() -> None:
    raw = (
        '192.168.10.238 - - [04/Mar/2020:19:32:50 +0000] '
        '"GET /static/evil.php?cmd=id HTTP/1.1" 200 131 "-" "curl/7.58.0"'
    )
    event = normalize_apache(raw, "access.log", 42)
    assert event["normalizer"]["success"] is True
    assert event["@timestamp"] == "2020-03-04T19:32:50+00:00"
    assert event["source"]["ip"] == "192.168.10.238"
    assert event["http"]["request"]["method"] == "GET"
    assert event["url"]["path"] == "/static/evil.php"
    assert event["url"]["query"] == "cmd=id"
    assert event["log"]["line_no"] == 42


def test_apache_escaped_quote_is_not_dropped() -> None:
    raw = (
        '192.168.10.238 - - [04/Mar/2020:19:18:35 +0000] '
        '"GET /x.php?q=\\\"<script>alert(1)</script> HTTP/1.1" '
        '400 0 "-" "-"'
    )
    event = normalize_apache(raw, "access.log", 1)
    assert event["normalizer"]["success"] is True
    assert event["http"]["response"]["status_code"] == 400


def test_apache_timeout_request_is_valid_empty_request() -> None:
    raw = '192.168.10.4 - - [29/Feb/2020:11:31:27 +0000] "-" 408 0 "-" "-"'
    event = normalize_apache(raw, "access.log", 1)
    assert event["normalizer"]["success"] is True
    assert event["http"]["request"]["method"] is None


def test_auth_failure_normalization() -> None:
    raw = (
        "Mar  4 19:25:47 mail auth: pam_unix(dovecot:auth): "
        "authentication failure; logname= uid=0 euid=0 tty=dovecot "
        "ruser=daryl rhost=127.0.0.1  user=daryl"
    )
    event = normalize_auth(raw, "auth.log", 735)
    assert event["normalizer"]["success"] is True
    assert event["event"]["action"] == "authentication_failure"
    assert event["event"]["outcome"] == "failure"
    assert event["auth"]["service"] == "dovecot"
    assert event["user"]["name"] == "daryl"
    assert event["source"]["ip"] == "127.0.0.1"

