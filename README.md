
# Mini SOC - Security Monitoring Lab

## Overview

Mini SOC is a Python-based security monitoring project
that analyzes authentication logs and detects repeated
failed login attempts within a configurable time window.

## Features

- Authentication log analysis
- Failed login counting by IP address
- Time-window-based detection
- MEDIUM and HIGH alert severity levels
- Automatic text report generation
- Automated tests using pytest
- Missing log file handling

## Technologies

- Python
- pytest
- Linux
- Git and GitHub

## Detection Rules

| Condition | Severity |
|---|---|
| 3 failed attempts within 60 seconds | MEDIUM |
| 6 failed attempts within 60 seconds | HIGH |

## Project Structure

```text
mini-soc-lab/
├── data/
├── reports/
├── tests/
├── main.py
├── README.md
└── .gitignore
```

## Installation

Clone the repository and enter the project directory.

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install pytest:

```bash
python -m pip install pytest
```

## Usage

Run the log analyzer:

```bash
python main.py
```

Run the automated tests:

```bash
python -m pytest -v
```

## Disclaimer

This project uses sample authentication logs for educational
and defensive security monitoring purposes. Alerts indicate
suspicious patterns and do not independently prove an attack.
