
from datetime import datetime, timedelta
from pathlib import Path

import main


def make_log_lines(ip, count, interval=5):
    start = datetime(2026, 10, 24, 12, 0, 0)

    return [
        (
            f"{(start + timedelta(seconds=i * interval)):%Y-%m-%d %H:%M:%S} "
            f"LOGIN_FAILED user=admin ip={ip}\n"
        )
        for i in range(count)
    ]


def test_real_analysis_creates_medium_alert(tmp_path, monkeypatch):
    log_file = tmp_path / "sample_auth.log"
    report_dir = tmp_path / "reports"

    log_file.write_text(
        "".join(make_log_lines("192.0.2.10", 3)),
        encoding="utf-8",
    )

    monkeypatch.setattr(main, "LOG_FILE", log_file)
    monkeypatch.setattr(main, "REPORT_DIR", report_dir)

    main.analyze_logs()

    report = report_dir / "security_report.txt"
    assert report.exists()
    assert "[MEDIUM] IP: 192.0.2.10" in report.read_text(
        encoding="utf-8"
    )


def test_real_analysis_creates_high_alert(tmp_path, monkeypatch):
    log_file = tmp_path / "sample_auth.log"
    report_dir = tmp_path / "reports"

    log_file.write_text(
        "".join(make_log_lines("192.0.2.20", 6)),
        encoding="utf-8",
    )

    monkeypatch.setattr(main, "LOG_FILE", log_file)
    monkeypatch.setattr(main, "REPORT_DIR", report_dir)

    main.analyze_logs()

    report = (report_dir / "security_report.txt").read_text(
        encoding="utf-8"
    )

    assert "[MEDIUM] IP: 192.0.2.20" in report
    assert "[HIGH] IP: 192.0.2.20" in report


def test_attempts_outside_window_create_no_alert(tmp_path, monkeypatch):
    log_file = tmp_path / "sample_auth.log"
    report_dir = tmp_path / "reports"

    log_file.write_text(
        "".join(make_log_lines("192.0.2.30", 3, interval=70)),
        encoding="utf-8",
    )

    monkeypatch.setattr(main, "LOG_FILE", log_file)
    monkeypatch.setattr(main, "REPORT_DIR", report_dir)

    main.analyze_logs()

    report = (report_dir / "security_report.txt").read_text(
        encoding="utf-8"
    )

    assert "No time-based alerts detected." in report


def test_missing_log_file(tmp_path, monkeypatch, capsys):
    missing_log = tmp_path / "missing.log"

    monkeypatch.setattr(main, "LOG_FILE", missing_log)
    monkeypatch.setattr(main, "REPORT_DIR", tmp_path / "reports")

    main.analyze_logs()

    output = capsys.readouterr().out
    assert "Error: log file not found:" in output
