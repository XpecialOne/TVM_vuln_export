# Tenable Vulnerability Export to Excel (Excludes Informational) - VM Module only (Next version will include WAS)

Production-ready Python project that uses the official Vulnerability Export API to fetch all vulnerabilities except informational and writes them to `vulnerabilities.xlsx`.

## Features
- Auth via `.env` (python-dotenv)
- Uses POST /vulns/export -> poll -> download chunk(s)
- Filters severities to low, medium, high, critical (excludes informational)
- Normalizes nested records to a flat Excel sheet
- Optional: limit by recent time window via SINCE_DAYS (see below)

## Quick Start
1. Clone/unzip this project.
2. Create a virtual environment (recommended):
   ```bash
   python -m venv .venv && source .venv/bin/activate  # macOS/Linux
   # or on Windows:
   # py -m venv .venv && .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure your secrets:
   - Copy `.env.example` to `.env` and fill your keys.
   ```bash
   cp .env.example .env
   ```
5. Run the exporter:
   ```bash
   python export_vulns_to_excel.py
   ```
6. The output file `vulnerabilities.xlsx` will be created in the project root.

## Configuration
- `.env` must define:
  - `TENABLE_ACCESS_KEY`
  - `TENABLE_SECRET_KEY`
- Optional `.env` variables:
  - `SINCE_DAYS` — e.g., `30` to export findings seen in the last 30 days only.

## Notes
- The script targets https://cloud.tenable.com and uses the documented X-ApiKeys header.
