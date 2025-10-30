#!/usr/bin/env python3
# Tenable Vulnerability Export to Excel
# - Excludes Informational severity
# - Supports .env via python-dotenv
# - Optional SINCE_DAYS to restrict by recency

import os
import sys
import time
import json
import gzip
import io
import itertools
from typing import Dict, Iterable, List, Optional

import requests
import pandas as pd
from dotenv import load_dotenv

# Load .env
load_dotenv()

API_BASE = "https://cloud.tenable.com"
EXPORT_ENDPOINT = f"{API_BASE}/vulns/export"
STATUS_ENDPOINT = f"{EXPORT_ENDPOINT}" + "/{uuid}/status"
CHUNK_ENDPOINT  = f"{EXPORT_ENDPOINT}" + "/{uuid}/chunks/{chunk_id}"

# Tunables
POLL_INTERVAL_SECS = int(os.getenv("POLL_INTERVAL_SECS", "5"))
REQUEST_TIMEOUT    = int(os.getenv("REQUEST_TIMEOUT", "60"))
CHUNK_SLEEP_SECS   = float(os.getenv("CHUNK_SLEEP_SECS", "0.2"))
OUTPUT_XLSX        = os.getenv("OUTPUT_XLSX", "vulnerabilities.xlsx")
SHEET_NAME         = os.getenv("SHEET_NAME", "Vulns")

def get_since_unix_from_env() -> Optional[int]:
    days_str = os.getenv('SINCE_DAYS')
    if not days_str:
        return None
    try:
        days = int(days_str)
    except ValueError:
        print(f"WARNING: Invalid SINCE_DAYS='{days_str}', ignoring.")
        return None
    import time as _time
    return int(_time.time() - days * 86400)

def get_headers() -> Dict[str, str]:
    akey = os.getenv('TENABLE_ACCESS_KEY')
    skey = os.getenv('TENABLE_SECRET_KEY')
    if not akey or not skey:
        sys.exit('ERROR: TENABLE_ACCESS_KEY or TENABLE_SECRET_KEY is not set in .env')
    return {
        'X-ApiKeys': f'accessKey={akey}; secretKey={skey}',
        'Accept': 'application/json',
        'User-Agent': 'tenable-vuln-export-to-excel/1.1'
    }

def start_export() -> str:
    filters = { 'severity': ['low', 'medium', 'high', 'critical'] }
    since_unix = get_since_unix_from_env()
    if since_unix is not None:
        filters['since'] = int(since_unix)
    body = { 'filters': filters }
    r = requests.post(EXPORT_ENDPOINT, headers=get_headers(), json=body, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    export_uuid = data.get('export_uuid') or data.get('uuid')
    if not export_uuid:
        sys.exit(f'ERROR: Unexpected response when starting export: {data}')
    return export_uuid

def poll_status(export_uuid: str) -> List[int]:
    while True:
        r = requests.get(STATUS_ENDPOINT.format(uuid=export_uuid), headers=get_headers(), timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        status = r.json()
        job_status = str(status.get('status', '')).upper()
        if job_status == 'FINISHED':
            if 'chunks' in status and isinstance(status['chunks'], dict):
                return [int(cid) for cid, st in status['chunks'].items() if str(st).upper() == 'COMPLETED']
            if 'chunks_available' in status and isinstance(status['chunks_available'], list):
                return status['chunks_available']
            return []
        if job_status in {'CANCELLED', 'ERROR'}:
            sys.exit(f"Export ended with status '{job_status}': {json.dumps(status, indent=2)}")
        time.sleep(POLL_INTERVAL_SECS)

def parse_chunk_bytes(blob: bytes) -> Iterable[Dict]:
    try:
        txt = blob.decode('utf-8').strip()
        if txt.startswith('['):
            for row in json.loads(txt):
                yield row
            return
        for line in txt.splitlines():
            if line.strip():
                yield json.loads(line)
        return
    except Exception:
        pass
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as gz:
            decoded = gz.read().decode('utf-8').strip()
            if decoded.startswith('['):
                for row in json.loads(decoded):
                    yield row
            else:
                for line in decoded.splitlines():
                    if line.strip():
                        yield json.loads(line)
    except Exception as e:
        raise RuntimeError(f'Failed to parse export chunk: {e}')

def download_chunk(export_uuid: str, chunk_id: int) -> List[Dict]:
    url = CHUNK_ENDPOINT.format(uuid=export_uuid, chunk_id=chunk_id)
    r = requests.get(url, headers=get_headers(), timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return list(parse_chunk_bytes(r.content))

def normalize_rows(rows: Iterable[Dict]) -> pd.DataFrame:
    rows = list(rows)
    if not rows:
        return pd.DataFrame()
    df = pd.json_normalize(rows, sep='.')
    preferred = [
        'asset.uuid', 'asset.hostname', 'asset.fqdn', 'asset.ipv4', 'asset.ipv6',
        'plugin.id', 'plugin.name', 'plugin.family', 'plugin.severity',
        'vuln.state', 'vuln.first_found', 'vuln.last_found', 'vuln.last_fixed',
        'port.port', 'port.protocol'
    ]
    cols = [c for c in preferred if c in df.columns] + [c for c in df.columns if c not in preferred]
    return df[cols]

def main():
    print('Starting Tenable vulnerability export (excluding informational)...')
    export_uuid = start_export()
    print(f'Export UUID: {export_uuid}')
    chunks = poll_status(export_uuid)
    if not chunks:
        sys.exit('No chunks available from export (empty result set).')
    print(f'Downloading {len(chunks)} chunk(s): {chunks}')
    all_rows = []
    for cid in sorted(chunks):
        rows = download_chunk(export_uuid, cid)
        all_rows.extend(rows)
        print(f'  - chunk {cid}: {len(rows)} records')
        time.sleep(CHUNK_SLEEP_SECS)
    if not all_rows:
        sys.exit('Export returned no vulnerabilities (after filtering out informational).')
    df = normalize_rows(all_rows)
    with pd.ExcelWriter(OUTPUT_XLSX, engine='openpyxl') as xw:
        df.to_excel(xw, index=False, sheet_name=SHEET_NAME)
    print(f'Wrote {len(df):,} rows -> {OUTPUT_XLSX}')

if __name__ == '__main__':
    main()
