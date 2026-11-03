# SentinelOps - Live Memory & Log Threat Hunter

SentinelOps is a complete local web project for host threat triage. It implements the flow in the supplied DFD: authenticated administrator and analyst access, user management, a threat-hunt run, correlated alerts, investigation tracking, and report export. It uses a Python Flask backend, a plain HTML/CSS/JavaScript frontend, psutil-based runtime telemetry, optional Windows Event Log collection, and a correlation-focused detection engine.

## DFD workflow implemented

1. **Administrator** signs in, creates users, and reviews the dashboard, alerts, reports, and investigation status.
2. **Security analyst** signs in, runs a live threat hunt, views alerts, and opens or updates investigations.
3. The system collects host process, memory, network, and optional log evidence, then correlates it into prioritized alerts.
4. Exporting the current alert set downloads a CSV and stores a report record in the application database.

On first launch, the app copies `threat_hunter_demo.db` to a local `threat_hunter.db` so the sample alerts and investigations appear in the running project. The app then uses the local copy; the committed demo database stays unchanged.

## Clear Definition of Live Memory

In this project, **Live Memory** means monitoring a running system's active process memory usage and related runtime process context:

- process resident memory usage
- process name, PID, user, executable path, and command line
- remote network connections tied to processes
- log activity that can support or contradict process findings

It does **not** mean offline memory dump forensics, RAM image acquisition, or Volatility-style forensic reconstruction.

## Main Contribution: Detection and Correlation Engine

The main contribution is not the process table. The main contribution is the detection engine in `detection_engine.py`.

The engine:

- extracts indicators from processes, command lines, memory usage, network context, recent baselines, and logs
- maps indicators to tactics such as Execution, Persistence, Credential Access, Defense Evasion, and Impact
- correlates multiple indicators from the same process or across sources
- calculates a transparent rule-based risk score from independent evidence points
- assigns severity levels
- explains why an alert was generated
- recommends an investigation action

## Difference from Task Manager and Event Viewer

Task Manager shows running processes. Event Viewer shows logs. Both require the analyst to manually inspect, connect, and prioritize evidence.

This system adds practical value by automatically:

- analyzing suspicious process and log behavior
- prioritizing high-risk activity
- correlating process, memory, network, and log indicators
- explaining alert reasons
- exporting investigation-ready reports

## Website Sections

- **Security overview**: host health, detection totals, and risk distribution.
- **Threat hunts**: live process, memory, network, parent/child process tree, recent baseline, and optional log analysis.
- **Alerts**: correlated signals with their evidence and recommended action.
- **Investigations**: analyst-owned alert cases with Open, Investigating, Resolved, and False Positive states. A False Positive requires a documented reason.
- **Reports**: CSV exports and a stored report history.
- **User management**: administrator-only account creation.

## Run

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Optional for databases without the bundled demo administrator.
$env:SENTINELOPS_BOOTSTRAP_PASSWORD = "Use-a-strong-password"
$env:SECRET_KEY = "a-long-random-secret-value"
python app.py
```

Open `http://127.0.0.1:5000`.

### First sign-in

A fresh download includes a demo administrator in the synthetic database. Sign in with `admin@localhost` and password `SentinelDemo!2026`. This account is for local demonstration only; change its password before using the app in any shared or deployed environment. `SENTINELOPS_BOOTSTRAP_PASSWORD` is used only if the database has no users. Existing `threat_hunter.db` files are preserved and migrated.

Run PowerShell as Administrator for better visibility into Security logs, protected process details, and network ownership.

## Project Files

```text
app.py                 Flask routes, host telemetry, log collection, export API
detection_engine.py    Indicator rules, correlation, risk scoring, explanations
templates/index.html   Complete website and dashboard markup
static/styles.css      Responsive frontend design
static/app.js          Live polling, rendering, log scan, report export
threat_hunter.db       Local runtime database (ignored by Git; may contain private data)\nthreat_hunter_demo.db  GitHub-safe SQLite sample with schema and synthetic records
requirements.txt       Python dependencies
```

## GitHub-safe demo database

`threat_hunter_demo.db` is a separate SQLite database containing the same application schema and synthetic example records. On a fresh checkout, the app copies it to `threat_hunter.db` and runs against that local copy. It contains one demo administrator with a hashed demo-only password and no real user accounts. Alert evidence, process names, users, addresses, and timestamps are fictional; the sample IP and `.test` domains are reserved for documentation/examples.

Keep your local `threat_hunter.db` out of source control. It may contain real host telemetry and account data, and `.gitignore` excludes it. Existing local databases are preserved. The app never writes to the committed demo database during normal startup or use.
