# BTCS2101 Student–Faculty Portal

A local Flask + SQLite mini-project with separate student, faculty and admin access.

## Quick start (Windows)
1. Install Python 3.10 or newer from python.org and enable **Add Python to PATH**.
2. Extract this ZIP into a normal writable folder.
3. Double-click `run.bat`. Keep the terminal window open.
4. Open http://127.0.0.1:5000 in your browser.

## Accounts and local setup

For a fresh installation, set an administrator username and password in environment variables before the first run. Do not commit credentials or a database file. Example in Windows PowerShell:

```powershell
$env:PULSE_ADMIN_USERNAME = "your-admin-username"
$env:PULSE_ADMIN_PASSWORD = "choose-a-strong-password"
$env:SECRET_KEY = [guid]::NewGuid().ToString()
python app.py
```

Student and faculty accounts should be created through the registration pages or provisioned securely by the administrator. This repository does not include demo passwords.

## Features
- Separate student, faculty and admin login pages.
- Student signup accepts enrollment IDs with `/`, e.g. `ADTU/1/2025-29/BTCS/073`.
- Faculty self-registration requires admin approval.
- Notices, assignments, assignment completion tracking, searchable dashboard and study-material uploads/downloads.
- Admin overview, faculty approvals, account activation/deactivation, password-reset request handling, manual password reset, CSV exports and activity log.
- Password hashes stored with Werkzeug; uploaded files use safe generated storage names.

## Notes
- Database `pulse.db` is created on first launch in this folder. It is ignored by Git and should not be committed.
- Upload limit is 16 MB. Uploaded files are stored in `static/uploads`.
- This is an educational local demo, not a production deployment. For production, configure a strong `SECRET_KEY`, CSRF protection, rate limiting, secure reset links, backups and HTTPS.
