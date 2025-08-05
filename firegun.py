#!/usr/bin/env python3
"""
FireGun CLI – Firebase pentest & vuln scanner

Usage:
  firegun scan [options] TARGETS...
  firegun dump-rtdb [options] TARGET
  firegun fs-scan [options] PROJECTS...
  firegun admin-dump-fs [options] PROJECT
  firegun fuzz-rules [options] RULES_FILE PROJECT SCRIPT_FILE
  firegun script [options] SCRIPT_FILE TARGET
  firegun signup [options] EMAIL [PASSWORD]
  firegun signin [options] EMAIL [PASSWORD]
  firegun storage-scan [options] URLS...

Dependencies (requirements.txt):
  httpx
  firebase-admin
  google-cloud-firestore
  google-auth
"""

import argparse
import asyncio
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import httpx
import firebase_admin
from firebase_admin import credentials, db
from google.cloud import firestore as fs_admin

# --- Constants ---
BANNER = r"""
______ _           _____
|  ___(_)         |  __ \
| |_   _ _ __ ___ | |  \/_   _ _ __
|  _| | | '__/ _ \| | __| | | | '_ \
| |   | | | |  __/\ |_\ \ |_| | | | |
\_|   |_|_|  \___|\____/\__,_|_| |_|
               by Marko Zivan (kurozy)
"""

# API endpoints
IDENTITY_TOOLKIT_BASE_URL = "https://identitytoolkit.googleapis.com/v1/accounts"
IT_SIGNUP_URL = f"{IDENTITY_TOOLKIT_BASE_URL}:signUp"
IT_SIGNIN_URL = f"{IDENTITY_TOOLKIT_BASE_URL}:signInWithPassword"
FIRESTORE_BASE_URL = "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"

# --- Banner helper ---
def print_banner() -> None:
    """Prints the banner."""
    print(BANNER)


# --- General & Security Helpers ---

def _load_auth_from_config(config_path: Optional[Path]) -> Optional[str]:
    """Loads idToken or auth token from a JSON config file."""
    if not config_path:
        return None
    try:
        cfg = json.loads(config_path.read_text())
        return cfg.get("idToken") or cfg.get("auth")
    except (FileNotFoundError, json.JSONDecodeError, AttributeError) as e:
        print(f"[-] Could not load or parse config file '{config_path}': {e}", file=sys.stderr)
        sys.exit(1)

def _resolve_targets(raw_targets: List[str]) -> List[str]:
    """Resolves a list of targets, expanding file paths into lines."""
    resolved = []
    for t in raw_targets:
        p = Path(t)
        if p.is_file():
            try:
                resolved.extend(line.strip() for line in p.read_text().splitlines() if line.strip())
            except FileNotFoundError:
                print(f"[-] Target file not found: {p}", file=sys.stderr)
        else:
            resolved.append(t)
    return resolved

def build_rtdb_url(raw: str, auth_token: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> str:
    """Constructs a valid RTDB URL with an optional auth token and extra params."""
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    path = parsed.path or ""
    if not path.endswith(".json"):
        path = path.rstrip("/") + "/.json"

    qs = dict(parse_qsl(parsed.query))
    if auth_token:
        qs.setdefault("auth", auth_token)
    if params:
        qs.update(params)

    new_query = urlencode(qs)
    return urlunparse((parsed.scheme, parsed.netloc, path, "", new_query, ""))


# --- Network & Error Handling ---

async def http_request_with_backoff(
    request_func: Callable[..., httpx.Response],
    max_retries: int = 5,
    initial_delay: float = 1.0
) -> httpx.Response:
    """
    Performs an HTTP request with exponential backoff for rate limiting and server errors.
    """
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            resp = await request_func()
            # Retry on 429 (Too Many Requests) or 5xx server errors.
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < max_retries - 1:
                    print(f"[!] Received HTTP {resp.status_code}. Retrying in {delay:.2f}s...", file=sys.stderr)
                    await asyncio.sleep(delay)
                    delay *= 2  # Exponential backoff
                    continue
            return resp
        except httpx.RequestError as e:
            if attempt < max_retries - 1:
                print(f"[-] Request error: {e}. Retrying in {delay:.2f}s...", file=sys.stderr)
                await asyncio.sleep(delay)
                delay *= 2
            else:
                raise  # Re-raise the exception after the last attempt
    # This part should ideally not be reached, but as a fallback:
    raise ConnectionError("Failed to complete request after multiple retries.")


# --- Identity Toolkit Helpers ---

async def _identity_toolkit_request(url: str, api_key: str, email: str, password: str) -> Optional[str]:
    """Helper to perform requests against the Identity Toolkit API."""
    params = {"key": api_key}
    payload = {"email": email, "password": password, "returnSecureToken": True}
    try:
        async with httpx.AsyncClient() as client:
            request_func = lambda: client.post(url, params=params, json=payload, timeout=20)
            r = await http_request_with_backoff(request_func)
            r.raise_for_status()
            data = r.json()
            print(f"[+] Success. UID={data['localId']}")
            return data["idToken"]
    except httpx.HTTPStatusError as e:
        error_info = e.response.json().get("error", {})
        message = error_info.get("message", e.response.text)
        print(f"[-] Request failed: {e.response.status_code} - {message}", file=sys.stderr)
    except httpx.RequestError as e:
        print(f"[-] Request failed: {e}", file=sys.stderr)
    return None

async def signup(api_key: str, email: str, password: str) -> None:
    """Signs up a new user using Firebase Authentication."""
    print(f"[*] Signing up user {email}...")
    await _identity_toolkit_request(IT_SIGNUP_URL, api_key, email, password)

async def signin(api_key: str, email: str, password: str) -> Optional[str]:
    """Signs in a user and returns their ID token."""
    print(f"[*] Signing in user {email}...")
    return await _identity_toolkit_request(IT_SIGNIN_URL, api_key, email, password)


# --- RTDB Scan & Exploit ---

async def exploit_rtdb(client: httpx.AsyncClient, root_url: str):
    """Attempts to write a non-destructive public warning to the vulnerable RTDB."""
    print(f"[!] Attempting to non-destructively exploit {root_url}")
    msg = (
        "Your Firebase Realtime Database is publicly writable. This is a security risk. "
        "Secure your database by updating your rules: https://firebase.google.com/docs/database/security"
    )
    payload = {"firegun_vulnerability_warning": msg}
    request_func = lambda: client.patch(root_url, json=payload, timeout=10)
    r = await http_request_with_backoff(request_func)
    if r.status_code == 200:
        print(f"[+] Exploit successful (HTTP {r.status_code}): Wrote a warning message.")
    else:
        print(f"[-] Exploit failed (HTTP {r.status_code}): {r.text}")

async def scan_rtdb(client: httpx.AsyncClient, raw: str, sem: asyncio.Semaphore,
                    exploit: bool, auth_token: Optional[str] = None, readout: bool = False):
    """Scans a single RTDB for vulnerabilities with improved reliability."""
    can_read, can_write = False, False
    probe_url = build_rtdb_url(raw.rstrip("/") + "/__firegun_probe__", auth_token)

    try:
        async with sem:
            # IMPROVEMENT: Use `shallow=true` for a fast, reliable read check.
            shallow_url = build_rtdb_url(raw, auth_token, params={"shallow": "true"})
            read_check_func = lambda: client.get(shallow_url)
            resp = await http_request_with_backoff(read_check_func)

            if resp.status_code == 200 and "error" not in resp.text:
                can_read = True

            # Write probe logic
            try:
                write_check_func = lambda: client.put(probe_url, json={"probe": "firegun"})
                w_resp = await http_request_with_backoff(write_check_func)
                if w_resp.status_code == 200:
                    can_write = True
            finally:
                # IMPROVEMENT: Ensure cleanup is always attempted.
                if can_write:
                    await client.delete(probe_url)

        parts = []
        if can_read: parts.append("READ ACCESS")
        if can_write: parts.append("TAKEOVER (WRITE)")
        status = ", ".join(parts) if parts else f"SECURE (Initial check: HTTP {resp.status_code})"
        print(f"{build_rtdb_url(raw)} [{'VULNERABLE' if parts else 'SECURE'} : {status}]")

        if readout and can_read:
            # Perform full readout only if requested and readable.
            full_url = build_rtdb_url(raw, auth_token)
            readout_func = lambda: client.get(full_url)
            readout_resp = await http_request_with_backoff(readout_func)
            if readout_resp.status_code == 200:
                print("\n-- Begin readout --")
                print(json.dumps(readout_resp.json(), indent=2))
                print("-- End readout --\n")

        if exploit and can_write:
            await exploit_rtdb(client, build_rtdb_url(raw, auth_token))

    except httpx.RequestError as e:
        print(f"[-] Critical error scanning {raw}: {e}", file=sys.stderr)


# --- Firestore Client Scan & Exploit ---

async def enumerate_firestore_collections(client: httpx.AsyncClient, base_url: str, api_key: str, headers: Dict[str, str]):
    """Enumerates top-level collections and a few documents from each."""
    print("  [+] Enumerating collections...")
    try:
        list_collections_url = f"{base_url}:listCollectionIds?key={api_key}"
        
        request_func = lambda: client.post(list_collections_url, headers=headers, json={"pageSize": 50})
        resp = await http_request_with_backoff(request_func)

        if resp.status_code == 200:
            collections = resp.json().get("collectionIds", [])
            print(f"    [+] Found collections ({len(collections)}): {collections}")

            for c in collections[:5]:  # Limit for brevity
                docs_url = f"{base_url}/{c}?pageSize=5&key={api_key}"
                docs_func = lambda: client.get(docs_url, headers=headers)
                docs_resp = await http_request_with_backoff(docs_func)
                if docs_resp.status_code == 200:
                    docs = docs_resp.json().get("documents", [])
                    doc_names = [d['name'].rsplit('/', 1)[-1] for d in docs]
                    print(f"      - {c} sample docs: {doc_names}")

    except (httpx.RequestError, json.JSONDecodeError) as e:
        print(f"  [-] Failed to enumerate collections: {e}", file=sys.stderr)

async def scan_firestore(client: httpx.AsyncClient, project: str, api_key: str,
                         id_token: Optional[str], sem: asyncio.Semaphore, exploit: bool):
    """Scans a single Firestore project for vulnerabilities."""
    base_url = FIRESTORE_BASE_URL.format(project=project)
    headers = {}
    if id_token:
        headers["Authorization"] = f"Bearer {id_token}"

    can_read, can_write = False, False
    last_resp = None
    probe_doc_url = f"{base_url}/__firegun_probe__?key={api_key}"

    try:
        async with sem:
            # 1. Read check
            list_url = f"{base_url}?pageSize=1&key={api_key}"
            read_func = lambda: client.get(list_url, headers=headers)
            read_resp = await http_request_with_backoff(read_func)
            last_resp = read_resp
            if read_resp.status_code == 200:
                can_read = True

            # 2. Write check
            if exploit:
                try:
                    probe_payload = {"fields": {"probe": {"stringValue": "firegun"}}}
                    write_func = lambda: client.patch(probe_doc_url, headers=headers, json=probe_payload)
                    write_resp = await http_request_with_backoff(write_func)
                    last_resp = write_resp
                    if write_resp.status_code in (200, 201):
                        can_write = True
                finally:
                    if can_write:
                        await client.delete(probe_doc_url, headers=headers)
        
        parts = []
        if can_read: parts.append("READ ACCESS")
        if can_write: parts.append("TAKEOVER (WRITE)")
        status = ", ".join(parts) if parts else f"SECURE (Initial check: HTTP {last_resp.status_code if last_resp else 'N/A'})"
        print(f"Firestore {project} [{'VULNERABLE' if parts else 'SECURE'} : {status}]")

        if can_read:
            await enumerate_firestore_collections(client, base_url, api_key, headers)

    except httpx.RequestError as e:
        print(f"[-] Critical error scanning Firestore {project}: {e}", file=sys.stderr)


# --- Firebase Storage Scan ---

async def scan_storage(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore, exploit: bool):
    """Scans a single Firebase Storage URL for vulnerabilities."""
    can_read, can_write = False, False
    resp = None
    probe_url = url.split("?")[0].replace("/o/", "/o/firegun_probe.txt")
    
    try:
        async with sem:
            # 1. Read check
            read_url = url.split("?")[0] + "?alt=media"
            read_func = lambda: client.get(read_url)
            resp = await http_request_with_backoff(read_func)
            if resp.status_code == 200:
                can_read = True

            # 2. Write check
            if exploit:
                try:
                    write_func = lambda: client.put(probe_url, content=b"firegun_probe")
                    w_resp = await http_request_with_backoff(write_func)
                    if w_resp.status_code in (200, 201):
                        can_write = True
                finally:
                    if can_write:
                        await client.delete(probe_url)

    except httpx.RequestError as e:
        print(f"[-] Critical error scanning {url}: {e}", file=sys.stderr)

    parts = []
    if can_read: parts.append("READ")
    if can_write: parts.append("WRITE")
    status = "/".join(parts) if parts else f"SECURE (Initial check: HTTP {resp.status_code if resp else 'N/A'})"
    print(f"{url} [{'VULNERABLE' if parts else 'SECURE'} : {status}]")


# --- Firestore Admin SDK Dump ---
def dump_fs_admin(sa_json: Path, project: str, output: Path):
    """Dumps Firestore data using Admin SDK, bypassing security rules."""
    print("[*] Initializing Admin SDK for Firestore dump...")
    try:
        from google.oauth2 import service_account
        creds = service_account.Credentials.from_service_account_file(str(sa_json))
        client = fs_admin.Client(project=project, credentials=creds)
        
        result = {}

        def recurse(col, path):
            for doc in col.stream():
                key = "/".join(path + [doc.id])
                result[key] = doc.to_dict()
                for sub_col in doc.reference.collections():
                    recurse(sub_col, path + [doc.id, sub_col.id])

        for col in client.collections():
            recurse(col, [col.id])
            
        output.write_text(json.dumps(result, indent=2, default=str))
        print(f"[+] Firestore admin dump written to {output}")

    except Exception as e:
        print(f"[-] Firestore admin dump failed: {e}", file=sys.stderr)
        sys.exit(1)

# --- Node.js Script Runners ---
def check_node_installed():
    """Checks if Node.js is installed and in the PATH."""
    try:
        subprocess.run(["node", "-v"], capture_output=True, check=True, text=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[-] Node.js not found. Please install it to use this feature.", file=sys.stderr)
        return False

def run_node_script(cmd: List[str]):
    """Runs a Node.js script."""
    if not check_node_installed():
        return
    try:
        print(f"[*] Running Node.js script: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Script execution failed with exit code {e.returncode}", file=sys.stderr)
    except FileNotFoundError:
        print("[-] 'node' command not found.", file=sys.stderr)

# --- Async Runners ---
async def run_scan(rtdb_targets: List[str], storage_targets: List[str], concurrency: int, exploit: bool, auth_token: Optional[str], readout: bool):
    async with httpx.AsyncClient(timeout=30) as client:
        sem = asyncio.Semaphore(concurrency)
        tasks = []
        if rtdb_targets:
            tasks.extend([scan_rtdb(client, t, sem, exploit, auth_token, readout) for t in rtdb_targets])
        if storage_targets:
            tasks.extend([scan_storage(client, u, sem, exploit) for u in storage_targets])
        
        if tasks:
            await asyncio.gather(*tasks)

async def run_dump_rtdb(target: str, auth_token: Optional[str], output: Optional[Path]):
    async with httpx.AsyncClient(timeout=60) as client:
        request_func = lambda: client.get(build_rtdb_url(target, auth_token, params={"format": "export"}))
        resp = await http_request_with_backoff(request_func)
        resp.raise_for_status()
        data = resp.json()
        if output:
            output.write_text(json.dumps(data, indent=2))
            print(f"[+] RTDB dump written to {output}")
        else:
            print(json.dumps(data, indent=2))

async def run_fs_scan(projects: List[str], api_key: str, id_token: Optional[str], concurrency: int, exploit: bool):
    async with httpx.AsyncClient(timeout=30) as client:
        sem = asyncio.Semaphore(concurrency)
        tasks = [scan_firestore(client, pj, api_key, id_token, sem, exploit) for pj in projects]
        await asyncio.gather(*tasks)

async def run_scan_storage(urls: List[str], concurrency: int, exploit: bool):
    async with httpx.AsyncClient(timeout=15) as client:
        sem = asyncio.Semaphore(concurrency)
        await asyncio.gather(*(scan_storage(client, u, sem, exploit) for u in urls))

# --- CLI Command Handlers (Hardened) ---
def handle_scan(args: argparse.Namespace) -> None:
    auth_token = _load_auth_from_config(args.config)
    targets = _resolve_targets(args.targets)
    
    rtdb_targets = [t for t in targets if "firebasestorage.googleapis.com" not in t]
    storage_targets = [t for t in targets if "firebasestorage.googleapis.com" in t]

    if not targets:
        print("[-] No valid targets found.")
        return

    print(f"[*] Starting scan on {len(rtdb_targets)} RTDB and {len(storage_targets)} Storage targets...")
    asyncio.run(run_scan(rtdb_targets, storage_targets, args.concurrency, args.exploit, auth_token, args.readout))

def handle_dump_rtdb(args: argparse.Namespace) -> None:
    auth_token = _load_auth_from_config(args.config)
    targets = _resolve_targets([args.target])
    if not targets:
        print(f"[-] Could not resolve target: {args.target}", file=sys.stderr)
        sys.exit(1)
    try:
        asyncio.run(run_dump_rtdb(targets[0], auth_token, args.output))
    except (httpx.RequestError, json.JSONDecodeError, ConnectionError) as e:
        print(f"[-] Failed to dump RTDB: {e}", file=sys.stderr)

def handle_fs_scan(args: argparse.Namespace) -> None:
    api_key = args.api_key or os.getenv("FIREBASE_API_KEY")
    if not api_key:
        print("[-] Error: API Key is required. Use --api-key or set FIREBASE_API_KEY.", file=sys.stderr)
        sys.exit(1)

    id_token = args.id_token or os.getenv("FIREBASE_ID_TOKEN") or _load_auth_from_config(args.config)
    projects = _resolve_targets(args.projects)
    
    print(f"[*] Scanning {len(projects)} Firestore project(s)...")
    asyncio.run(run_fs_scan(projects, api_key, id_token, args.concurrency, args.exploit))

def handle_storage_scan(args: argparse.Namespace) -> None:
    urls = _resolve_targets(args.urls)
    if not urls:
        print("[-] No valid storage URLs found.")
        return
        
    print(f"[*] Scanning {len(urls)} Storage URL(s)...")
    asyncio.run(run_scan_storage(urls, args.concurrency, args.exploit))

def handle_auth(args: argparse.Namespace) -> None:
    """Handles both signup and signin to reduce code duplication."""
    api_key = args.api_key or os.getenv("FIREBASE_API_KEY")
    if not api_key:
        print("[-] Error: API Key is required. Use --api-key or set FIREBASE_API_KEY.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        try:
            password = getpass.getpass(f"Enter password for {args.email}: ")
        except (EOFError, KeyboardInterrupt):
            print("\n[-] Aborted.", file=sys.stderr)
            sys.exit(1)
    
    if args.cmd == "signup":
        asyncio.run(signup(api_key, args.email, password))
    elif args.cmd == "signin":
        token = asyncio.run(signin(api_key, email=args.email, password=password))
        if token:
            print("\n[SUCCESS] Authentication successful.")
            print(f"idToken: {token}")

def handle_admin_dump_fs(args: argparse.Namespace) -> None:
    sa_path_str = args.service_account or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not sa_path_str:
        print("[-] Error: Service account path is required. Use --service-account or set GOOGLE_APPLICATION_CREDENTIALS.", file=sys.stderr)
        sys.exit(1)
    
    dump_fs_admin(Path(sa_path_str), args.project, args.output)

def handle_fuzz_rules(args: argparse.Namespace) -> None:
    api_key = args.api_key or os.getenv("FIREBASE_API_KEY")
    if not api_key:
        print("[-] Error: API Key is required. Use --api-key or set FIREBASE_API_KEY.", file=sys.stderr)
        sys.exit(1)
    
    id_token = args.id_token or os.getenv("FIREBASE_ID_TOKEN")
    cmd = ["node", str(args.script), "--project", args.project,
           "--apiKey", api_key, "--rules", str(args.rules)]
    if id_token:
        cmd += ["--token", id_token]
    run_node_script(cmd)

def handle_run_script(args: argparse.Namespace) -> None:
    token = args.token or os.getenv("FIREBASE_ID_TOKEN")
    cmd = ["node", str(args.path), args.target]
    if token:
        cmd.append(token)
    run_node_script(cmd)

# --- CLI Setup ---
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="firegun",
        description="FireGun CLI – Firebase pentest & vuln scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True, help="Available commands")
    
    # --- General Scan Parser ---
    scan_parser = subparsers.add_parser("scan", help="Scan RTDB or Storage URLs for open permissions")
    scan_parser.add_argument("targets", nargs="+", help="One or more hosts, URLs, or files containing targets")
    scan_parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent scans (default: 10)")
    scan_parser.add_argument("--exploit", action="store_true", help="Attempt to write a non-destructive warning to vulnerable targets")
    scan_parser.add_argument("--readout", action="store_true", help="Print readable data from vulnerable RTDBs")
    scan_parser.add_argument("--config", type=Path, help="JSON config file with idToken or auth token")
    scan_parser.set_defaults(func=handle_scan)

    # --- RTDB Dump Parser ---
    dump_parser = subparsers.add_parser("dump-rtdb", help="Deep dump an entire RTDB to a JSON file")
    dump_parser.add_argument("target", help="A single host, URL, or file containing one")
    dump_parser.add_argument("--output", type=Path, help="Output file path for the dump (prints to console if omitted)")
    dump_parser.add_argument("--config", type=Path, help="JSON config file with idToken or auth token")
    dump_parser.set_defaults(func=handle_dump_rtdb)

    # --- Firestore Scan Parser ---
    fs_scan_parser = subparsers.add_parser("fs-scan", help="Test client-side Firestore access")
    fs_scan_parser.add_argument("projects", nargs="+", help="One or more Firebase project IDs (or file containing them)")
    fs_scan_parser.add_argument("--api-key", help="Firebase project API key (or use FIREBASE_API_KEY env var)")
    fs_scan_parser.add_argument("--id-token", help="Auth token for scans (or use FIREBASE_ID_TOKEN env var). Note: Tokens expire after 1 hour.")
    fs_scan_parser.add_argument("--config", type=Path, help="JSON config file with idToken (lower priority than --id-token/env var)")
    fs_scan_parser.add_argument("-c", "--concurrency", type=int, default=5)
    fs_scan_parser.add_argument("--exploit", action="store_true", help="Attempt to write to vulnerable collections")
    fs_scan_parser.set_defaults(func=handle_fs_scan)

    # --- Storage Scan Parser ---
    st_parser = subparsers.add_parser("storage-scan", help="Firebase Storage file read/write test")
    st_parser.add_argument("urls", nargs="+", help="Full HTTPS URLs to files or files containing URLs")
    st_parser.add_argument("-c", "--concurrency", type=int, default=5)
    st_parser.add_argument("--exploit", action="store_true", help="Try a dummy upload to probe WRITE access")
    st_parser.set_defaults(func=handle_storage_scan)

    # --- Firestore Admin Dump Parser ---
    ad_parser = subparsers.add_parser("admin-dump-fs", help="Dump Firestore using Admin SDK (bypasses rules)")
    ad_parser.add_argument("--service-account", help="Path to service account JSON file (or use GOOGLE_APPLICATION_CREDENTIALS env var)")
    ad_parser.add_argument("project", help="Firebase project ID")
    ad_parser.add_argument("--output", type=Path, required=True, help="Output file for the dump")
    ad_parser.set_defaults(func=handle_admin_dump_fs)

    # --- Firestore Rules Fuzzer Parser ---
    fr_parser = subparsers.add_parser("fuzz-rules", help="Fuzz Firestore rules with a JS script")
    fr_parser.add_argument("rules", type=Path, help="Path to firestore.rules file")
    fr_parser.add_argument("project", help="Firebase project ID")
    fr_parser.add_argument("--api-key", help="Firebase project API key (or use FIREBASE_API_KEY env var)")
    fr_parser.add_argument("--id-token", help="Optional auth token (or use FIREBASE_ID_TOKEN env var)")
    fr_parser.add_argument("script", type=Path, help="Path to the fuzzer JS script")
    fr_parser.set_defaults(func=handle_fuzz_rules)

    # --- Custom Script Runner Parser ---
    sc_parser = subparsers.add_parser("script", help="Run a custom JS pentesting script")
    sc_parser.add_argument("path", type=Path, help="Path to the JS script")
    sc_parser.add_argument("target", help="Target URL or identifier for the script")
    sc_parser.add_argument("--token", help="Optional auth token for the script (or use FIREBASE_ID_TOKEN env var)")
    sc_parser.set_defaults(func=handle_run_script)

    # --- Auth Parsers ---
    auth_help = {
        "api-key": "Firebase API Key (or use FIREBASE_API_KEY env var)",
        "email": "The user's email address",
        "password": "The user's password (if omitted, will be prompted for securely)"
    }
    
    signup_parser = subparsers.add_parser("signup", help="Sign up a new user with email/password")
    signup_parser.add_argument("--api-key", help=auth_help["api-key"])
    signup_parser.add_argument("email", help=auth_help["email"])
    signup_parser.add_argument("password", nargs="?", help=auth_help["password"])
    signup_parser.set_defaults(func=handle_auth)

    signin_parser = subparsers.add_parser("signin", help="Sign in a user with email/password")
    signin_parser.add_argument("--api-key", help=auth_help["api-key"])
    signin_parser.add_argument("email", help=auth_help["email"])
    signin_parser.add_argument("password", nargs="?", help=auth_help["password"])
    signin_parser.set_defaults(func=handle_auth)

    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

