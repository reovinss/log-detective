# Log Detective

Basic information security pet project for analyzing nginx access logs.

The app parses log lines, highlights suspicious activity, gives a simple risk score, and explains what to check next.

## Features

- Paste logs or upload `.log` / `.txt` files.
- Detect sensitive path probes like `/.env`, `/admin`, `/wp-login.php`.
- Detect common SQL injection, XSS, and path traversal patterns.
- Detect known scanner user agents such as `sqlmap`, `nikto`, and `nmap`.
- Detect repeated `404`, `401`, and `403` responses from one IP.
- Show risk score, alerts, top IPs, status codes, and top paths.

## Run

Clone the repository and open its folder:

```bash
git clone https://github.com/reovinss/log-detective.git
cd log-detective
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## Good next tasks

- Add support for Apache combined logs.
- Add CSV/JSON report export.
- Add a timeline view.
- Add tests for parser and detection rules.
- Store previous analyses in SQLite.
