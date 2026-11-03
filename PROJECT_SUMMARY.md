# SentinelOps — Project Summary

**Purpose.** SentinelOps is a local web app for host threat triage. It collects live process, memory, network, and optional log evidence, then helps administrators and analysts prioritize and investigate suspicious activity. “Live memory” means runtime process memory usage and context; it does not acquire or analyze RAM dump images.

**How it works.** A Flask/Python backend gathers host telemetry with `psutil` and, on Windows, can read Event Logs through `pywin32`. A transparent rule-based engine (`detection_engine.py`) checks process commands, process ancestry, network context, recent CPU/memory baselines, and log events. It correlates evidence, assigns a 0–100 priority score and severity, explains each signal, and suggests a review action. Scores indicate review priority, not probability or proof of compromise.

**Main capabilities.** Role-based administrator and analyst sign-in; live, on-demand threat hunts; process and connection views; optional Windows Event Log or log-file scans; rule library; correlated alerts with evidence; analyst investigations (Open, Investigating, Resolved, False Positive) with notes; administrator user and case oversight; individual alert/threat reports; combined CSV export and report history.

**Roles.** Analysts run hunts and manage assigned investigations. Administrators manage accounts, review stored alerts and investigations, and oversee report history. Users are stored with password hashes. New databases require `SENTINELOPS_BOOTSTRAP_PASSWORD` to create the initial `admin@localhost` account; set `SECRET_KEY` for a persistent Flask session secret.

**Technology and data.** Python 3, Flask, SQLite, psutil, optional Windows pywin32, and a plain HTML/CSS/JavaScript interface. `threat_hunter.db` is created beside `app.py` and stores users, alerts/evidence, process baselines, investigations, and reports. The app is designed for local host monitoring and demonstrations; Windows log access and protected process details may require elevated privileges.

**Run locally (PowerShell).** From `C:\MajorProject`, activate the existing venv if available, install dependencies with `pip install -r requirements.txt`, set `SENTINELOPS_BOOTSTRAP_PASSWORD` (first database initialization) and `SECRET_KEY`, then run `python app.py`. Open `http://127.0.0.1:5000`.

**Core files.** `app.py` — Flask routes, telemetry, SQLite, log collection, exports; `detection_engine.py` — rules, correlation, risk scoring, explanations; `templates/index.html`, `static/styles.css`, `static/app.js` — UI; `requirements.txt` — dependencies; `startup.txt` — local startup notes; `README.md` — detailed usage and scope. Project report, diagrams, and demo artifacts are provided in the accompanying PDF/DOCX/PNG files.

**Project flow.** Sign in → run a hunt or scan logs → review prioritized alerts and evidence → open/update an investigation → export reports. No automatic continuous scan is implied; hunts are analyst-triggered.
