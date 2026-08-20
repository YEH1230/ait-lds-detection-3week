from __future__ import annotations

from pathlib import Path

from aitlds_detection.labels import iter_labeled_events
from aitlds_detection.normalizers import normalize_apache, normalize_auth
from aitlds_detection.rule_engine import evaluate_rules, load_rules


RULES = Path(__file__).resolve().parents[1] / "rules"


def test_actual_apache_attack_and_normal_fixtures(tmp_path: Path) -> None:
    logs = [
        '192.168.10.190 - - [29/Feb/2020:00:00:02 +0000] "GET /login.php HTTP/1.1" 200 2532 "-" "Mozilla/5.0 Firefox/73.0"',
        '192.168.10.238 - - [04/Mar/2020:19:18:33 +0000] "HEAD / HTTP/1.1" 400 0 "-" "-"',
        '192.168.10.238 - - [04/Mar/2020:19:25:46 +0000] "GET /login.php HTTP/1.0" 200 6335 "-" "Mozilla/5.0 (Hydra)"',
        '192.168.10.238 - - [04/Mar/2020:19:32:44 +0000] "GET /login.php HTTP/1.1" 200 6316 "-" "python-requests/2.18.4"',
        '192.168.10.238 - - [04/Mar/2020:19:32:50 +0000] "GET /static/evil.php?cmd=id HTTP/1.1" 200 131 "-" "curl/7.58.0"',
    ]
    labels = ["0,0", "nikto,nikto", "hydra,hydra", "upload,upload", "mail-curl,mail-curl"]
    log_path = tmp_path / "access.log"
    label_path = tmp_path / "labels.log"
    log_path.write_text("\n".join(logs) + "\n", encoding="utf-8")
    label_path.write_text("\n".join(labels) + "\n", encoding="utf-8")
    rules = load_rules(RULES)

    predictions = []
    for event in iter_labeled_events(
        log_path, label_path, normalize_apache, label_policy="event"
    ):
        predictions.append(bool(evaluate_rules(event, rules)))
    assert predictions == [False, True, True, True, True]


def test_auth_event_rule_has_expected_false_positive_tradeoff(tmp_path: Path) -> None:
    failure = (
        "Mar  4 19:25:47 mail auth: pam_unix(dovecot:auth): "
        "authentication failure; logname= uid=0 euid=0 tty=dovecot "
        "ruser=daryl rhost=127.0.0.1  user=daryl"
    )
    normal = (
        "Feb 29 00:09:01 mail-0 CRON[32002]: "
        "pam_unix(cron:session): session opened for user root by (uid=0)"
    )
    log_path = tmp_path / "auth.log"
    label_path = tmp_path / "labels.log"
    log_path.write_text(f"{normal}\n{failure}\n{failure}\n", encoding="utf-8")
    label_path.write_text("0,0\nhydra,hydra\n0,0\n", encoding="utf-8")
    rules = load_rules(RULES)
    predictions = [
        bool(evaluate_rules(event, rules))
        for event in iter_labeled_events(
            log_path, label_path, normalize_auth, label_policy="event"
        )
    ]
    assert predictions == [False, True, True]
