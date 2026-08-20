"""Deterministic normalizers for the AIT-LDS v1.0 log sources used in the PoC."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


APACHE_PATTERN = re.compile(
    r'^(?P<src_ip>\S+) (?P<ident>\S+) (?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] "(?P<request>(?:\\.|[^"])*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referrer>(?:\\.|[^"])*)" '
    r'"(?P<user_agent>(?:\\.|[^"])*)"$'
)
AUTH_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<clock>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<program>[^:]+): (?P<message>.*)$"
)
PAM_PATTERN = re.compile(r"pam_unix\((?P<service>[^:)]+)(?::[^)]*)?\)")


def _event_id(source_file: str, line_no: int, raw_line: str) -> str:
    payload = f"{source_file}\0{line_no}\0{raw_line}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _base_event(source_file: str, line_no: int, raw_line: str) -> dict:
    return {
        "event_id": _event_id(source_file, line_no, raw_line),
        "@timestamp": None,
        "host": {"name": None},
        "log": {
            "source": None,
            "file": source_file,
            "line_no": line_no,
        },
        "event": {"category": None, "action": None, "outcome": None},
        "source": {"ip": None},
        "user": {"name": None, "id": None},
        "process": {
            "pid": None,
            "ppid": None,
            "executable": None,
            "command_line": None,
        },
        "http": {
            "request": {"method": None},
            "response": {"status_code": None, "body_bytes": None},
        },
        "url": {"original": None, "path": None, "query": None},
        "user_agent": {"original": None},
        "auth": {"service": None, "ruser": None, "rhost": None},
        "logsource": {},
        "normalizer": {
            "name": None,
            "version": "0.1.0",
            "success": False,
            "errors": [],
        },
        "raw_line": raw_line,
    }


def normalize_apache(
    raw_line: str, source_file: str, line_no: int, *, year: int = 2020
) -> dict:
    del year
    event = _base_event(source_file, line_no, raw_line)
    event["log"]["source"] = "apache_access"
    event["event"]["category"] = "web"
    event["logsource"] = {
        "category": "webserver",
        "product": "apache",
        "service": "access",
    }
    event["normalizer"]["name"] = "aitlds-apache-access"
    match = APACHE_PATTERN.match(raw_line)
    if not match:
        event["normalizer"]["errors"].append("apache_combined_pattern_mismatch")
        return event

    values = match.groupdict()
    try:
        parsed_time = datetime.strptime(
            values["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
        )
        event["@timestamp"] = parsed_time.astimezone(timezone.utc).isoformat()
    except ValueError:
        event["normalizer"]["errors"].append("invalid_timestamp")

    request_parts = values["request"].split(" ", 2)
    if len(request_parts) == 3:
        method, target, protocol = request_parts
        event["http"]["request"]["method"] = method
        event["url"]["original"] = target
        parsed_url = urlsplit(target)
        event["url"]["path"] = parsed_url.path
        event["url"]["query"] = parsed_url.query or None
        event["http"]["version"] = protocol
    elif values["request"] != "-":
        event["normalizer"]["errors"].append("invalid_request_line")

    event["source"]["ip"] = values["src_ip"]
    event["user"]["name"] = None if values["user"] == "-" else values["user"]
    event["http"]["response"]["status_code"] = int(values["status"])
    event["http"]["response"]["body_bytes"] = (
        None if values["bytes"] == "-" else int(values["bytes"])
    )
    event["http"]["referrer"] = (
        None if values["referrer"] == "-" else values["referrer"]
    )
    event["user_agent"]["original"] = values["user_agent"]
    event["normalizer"]["success"] = not event["normalizer"]["errors"]
    return event


def normalize_auth(
    raw_line: str, source_file: str, line_no: int, *, year: int = 2020
) -> dict:
    event = _base_event(source_file, line_no, raw_line)
    event["log"]["source"] = "auth"
    event["event"]["category"] = "authentication"
    event["logsource"] = {
        "category": "authentication",
        "product": "linux",
        "service": "auth",
    }
    event["normalizer"]["name"] = "aitlds-linux-auth"
    match = AUTH_PATTERN.match(raw_line)
    if not match:
        event["normalizer"]["errors"].append("syslog_pattern_mismatch")
        return event

    values = match.groupdict()
    try:
        parsed_time = datetime.strptime(
            f"{year} {values['month']} {values['day']} {values['clock']}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        event["@timestamp"] = parsed_time.isoformat()
    except ValueError:
        event["normalizer"]["errors"].append("invalid_timestamp")

    message = values["message"]
    event["host"]["name"] = values["host"]
    event["process"]["name"] = values["program"]
    event["message"] = message
    pam_match = PAM_PATTERN.search(message)
    if pam_match:
        event["auth"]["service"] = pam_match.group("service")

    if "authentication failure" in message:
        event["event"]["action"] = "authentication_failure"
        event["event"]["outcome"] = "failure"
    elif "session opened" in message:
        event["event"]["action"] = "session_opened"
        event["event"]["outcome"] = "success"
    elif "session closed" in message:
        event["event"]["action"] = "session_closed"
        event["event"]["outcome"] = "success"
    else:
        event["event"]["action"] = "authentication_message"

    user_match = re.search(r"\buser=(?P<user>[^\s]+)", message)
    if not user_match:
        user_match = re.search(r"\bfor user (?P<user>[^\s]+)", message)
    if user_match:
        event["user"]["name"] = user_match.group("user")
    ruser_match = re.search(r"\bruser=(?P<ruser>[^\s]*)", message)
    rhost_match = re.search(r"\brhost=(?P<rhost>[^\s]*)", message)
    if ruser_match:
        event["auth"]["ruser"] = ruser_match.group("ruser") or None
    if rhost_match:
        event["auth"]["rhost"] = rhost_match.group("rhost") or None
        event["source"]["ip"] = rhost_match.group("rhost") or None

    pid_match = re.search(r"\[(?P<pid>\d+)\]", values["program"])
    if pid_match:
        event["process"]["pid"] = int(pid_match.group("pid"))
    event["normalizer"]["success"] = not event["normalizer"]["errors"]
    return event


NORMALIZERS = {"apache": normalize_apache, "auth": normalize_auth}


def relative_source_name(path: Path) -> str:
    return path.as_posix()
